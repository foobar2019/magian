#define _GNU_SOURCE

#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <paths.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <limits.h>
#include <grp.h>
#include <sys/statvfs.h>
#include <openssl/sha.h>

#define __ASHMEMIOC		0x77
#define ASHMEM_SET_NAME		_IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE		_IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE		_IO(__ASHMEMIOC, 4)
#define ASHMEM_NAME_LEN		256

#define ASHV_KEY_SYMLINK_PATH _PATH_TMP "ashv_key_%d"
#define ANDROID_SHMEM_SOCKNAME "/dev/shm/%08x"
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

#define SUIDCACHE "/var/suid/"
static gid_t blessed_groups[] = {
	3003,
	3004,
	3005
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	// The shmid (shared memory id) contains the socket address (16 bits)
	// and a local id (15 bits).
	int id;
	void *addr;
	int descriptor;
	size_t size;
	bool markedForDeletion;
	key_t key;
} shmem_t;

static shmem_t* shmem = NULL;
static size_t shmem_amount = 0;

// The lower 16 bits of (getpid() + i), where i is a sequence number.
// It is unique among processes as it's only set when bound.
static int ashv_local_socket_id = 0;
// To handle forks we store which pid the ashv_local_socket_id was
// created for.
static int ashv_pid_setup = 0;
static pthread_t ashv_listening_thread_id = 0;

static int ancil_send_fd(int sock, int fd)
{
	char nothing = '!';
	struct iovec nothing_ptr = { .iov_base = &nothing, .iov_len = 1 };

	struct {
		struct cmsghdr align;
		int fd[1];
	} ancillary_data_buffer;

	struct msghdr message_header = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &nothing_ptr,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_control = &ancillary_data_buffer,
		.msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
	};

	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
	cmsg->cmsg_len = message_header.msg_controllen; // sizeof(int);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	((int*) CMSG_DATA(cmsg))[0] = fd;

	return sendmsg(sock, &message_header, 0) >= 0 ? 0 : -1;
}

static int ancil_recv_fd(int sock)
{
	char nothing = '!';
	struct iovec nothing_ptr = { .iov_base = &nothing, .iov_len = 1 };

	struct {
		struct cmsghdr align;
		int fd[1];
	} ancillary_data_buffer;

	struct msghdr message_header = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &nothing_ptr,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_control = &ancillary_data_buffer,
		.msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
	};

	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
	cmsg->cmsg_len = message_header.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	((int*) CMSG_DATA(cmsg))[0] = -1;

	if (recvmsg(sock, &message_header, 0) < 0) return -1;

	return ((int*) CMSG_DATA(cmsg))[0];
}

static int ashmem_get_size_region(int fd)
{
	return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL));
}

/*
 * From https://android.googlesource.com/platform/system/core/+/master/libcutils/ashmem-dev.c
 *
 * ashmem_create_region - creates a new named ashmem region and returns the file
 * descriptor, or <0 on error.
 *
 * `name' is the label to give the region (visible in /proc/pid/maps)
 * `size' is the size of the region, in page-aligned bytes
 */
static int ashmem_create_region(char const* name, size_t size)
{
	int fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0) return fd;

	char name_buffer[ASHMEM_NAME_LEN] = {0};
	strncpy(name_buffer, name, sizeof(name_buffer));
	name_buffer[sizeof(name_buffer)-1] = 0;

	int ret = ioctl(fd, ASHMEM_SET_NAME, name_buffer);
	if (ret < 0) goto error;

	ret = ioctl(fd, ASHMEM_SET_SIZE, size);
	if (ret < 0) goto error;

	return fd;
error:
	close(fd);
	return ret;
}

static void ashv_check_pid()
{
	pid_t mypid = getpid();
	if (ashv_pid_setup == 0) {
		ashv_pid_setup = mypid;
	} else if (ashv_pid_setup != mypid) {
		// We inherited old state across a fork.
		ashv_pid_setup = mypid;
		ashv_local_socket_id = 0;
		ashv_listening_thread_id = 0;
		shmem_amount = 0;
		// Unlock if fork left us with held lock from parent thread.
		pthread_mutex_unlock(&mutex);
		if (shmem != NULL) free(shmem);
		shmem = NULL;
	}
}


// Store index in the lower 15 bits and the socket id in the
// higher 16 bits.
static int ashv_shmid_from_counter(unsigned int counter)
{
	return ashv_local_socket_id * 0x10000 + counter;
}

static int ashv_socket_id_from_shmid(int shmid)
{
	return shmid / 0x10000;
}

static int ashv_find_local_index(int shmid)
{
	for (size_t i = 0; i < shmem_amount; i++)
		if (shmem[i].id == shmid)
			return i;
	return -1;
}

static void* ashv_thread_function(void* arg)
{
	int sock = *(int*)arg;
	free(arg);
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int sendsock;
	while ((sendsock = accept(sock, (struct sockaddr *)&addr, &len)) != -1) {
		int shmid;
		if (recv(sendsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
			close(sendsock);
			continue;
		}
		pthread_mutex_lock(&mutex);
		int idx = ashv_find_local_index(shmid);
		if (idx != -1) {
			write(sendsock, &shmem[idx].key, sizeof(key_t));
			ancil_send_fd(sendsock, shmem[idx].descriptor);
		}
		pthread_mutex_unlock(&mutex);
		close(sendsock);
		len = sizeof(addr);
	}
	return NULL;
}

static void android_shmem_delete(int idx)
{
	if (shmem[idx].descriptor) close(shmem[idx].descriptor);
	shmem_amount--;
	memmove(&shmem[idx], &shmem[idx+1], (shmem_amount - idx) * sizeof(shmem_t));
}

static int ashv_read_remote_segment(int shmid)
{
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(&addr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_socket_id_from_shmid(shmid));
	int addrlen = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;

	int recvsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (recvsock == -1) {
		return -1;
	}
	if (connect(recvsock, (struct sockaddr*) &addr, addrlen) != 0) {
		close(recvsock);
		return -1;
	}

	if (send(recvsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
		close(recvsock);
		return -1;
	}

	key_t key;
	if (read(recvsock, &key, sizeof(key_t)) != sizeof(key_t)) {
		close(recvsock);
		return -1;
	}

	int descriptor = ancil_recv_fd(recvsock);
	if (descriptor < 0) {
		close(recvsock);
		return -1;
	}
	close(recvsock);

	int size = ashmem_get_size_region(descriptor);
	if (size == 0 || size == -1) {
		return -1;
	}

	int idx = shmem_amount;
	shmem_amount ++;
	shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
	shmem[idx].id = shmid;
	shmem[idx].descriptor = descriptor;
	shmem[idx].size = size;
	shmem[idx].addr = NULL;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;
	return idx;
}

/* Get shared memory area identifier. */
int shmget(key_t key, size_t size, int flags)
{
	(void) flags;

	ashv_check_pid();

	// Counter wrapping around at 15 bits.
	static size_t shmem_counter = 0;

	if (!ashv_listening_thread_id) {
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (!sock) {
			errno = EINVAL;
			return -1;
		}
		int i;
		for (i = 0; i < 4096; i++) {
			struct sockaddr_un addr;
			int len;
			memset (&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			ashv_local_socket_id = (getpid() + i) & 0xffff;
			sprintf(&addr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_local_socket_id);
			len = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;
			if (bind(sock, (struct sockaddr *)&addr, len) != 0) continue;
			break;
		}
		if (i == 4096) {
			ashv_local_socket_id = 0;
			errno = ENOMEM;
			return -1;
		}
		if (listen(sock, 4) != 0) {
			errno = ENOMEM;
			return -1;
		}
		int* socket_arg = malloc(sizeof(int));
		*socket_arg = sock;
		pthread_create(&ashv_listening_thread_id, NULL, &ashv_thread_function, socket_arg);
	}

	int shmid = -1;

	pthread_mutex_lock(&mutex);
	char symlink_path[256];
	if (key != IPC_PRIVATE) {
		// (1) Check if symlink exists telling us where to connect.
		// (2) If so, try to connect and open.
		// (3) If connected and opened, done. If connection refused
		//     take ownership of the key and create the symlink.
		// (4) If no symlink, create it.
		sprintf(symlink_path, ASHV_KEY_SYMLINK_PATH, key);
		char path_buffer[256];
		char num_buffer[64];
		while (true) {
			int path_length = readlink(symlink_path, path_buffer, sizeof(path_buffer) - 1);
			if (path_length != -1) {
				path_buffer[path_length] = '\0';
				int shmid = atoi(path_buffer);
				if (shmid != 0) {
					int idx = ashv_read_remote_segment(shmid);
					if (idx != -1) {
						pthread_mutex_unlock(&mutex);
						return shmem[idx].id;
					}
				}
				// TODO: Not sure we should try to remove previous owner if e.g.
				// there was a tempporary failture to get a soket. Need to
				// distinguish between why ashv_read_remote_segment failed.
				unlink(symlink_path);
			}
			// Take ownership.
			// TODO: HAndle error (out of resouces, no infinite loop)
			if (shmid == -1) {
				shmem_counter = (shmem_counter + 1) & 0x7fff;
				shmid = ashv_shmid_from_counter(shmem_counter);
				sprintf(num_buffer, "%d", shmid);
			}
			if (symlink(num_buffer, symlink_path) == 0) break;
		}
	}


	int idx = shmem_amount;
	char buf[256];
	sprintf(buf, ANDROID_SHMEM_SOCKNAME "-%d", ashv_local_socket_id, idx);

	shmem_amount++;
	if (shmid == -1) {
		shmem_counter = (shmem_counter + 1) & 0x7fff;
		shmid = ashv_shmid_from_counter(shmem_counter);
	}

	shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
	size = ROUND_UP(size, getpagesize());
	shmem[idx].size = size;
	shmem[idx].descriptor = ashmem_create_region(buf, size);
	shmem[idx].addr = NULL;
	shmem[idx].id = shmid;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;

	if (shmem[idx].descriptor < 0) {
		shmem_amount --;
		shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
		pthread_mutex_unlock (&mutex);
		return -1;
	}
	pthread_mutex_unlock(&mutex);

	return shmid;
}

/* Attach shared memory segment. */
void* shmat(int shmid, void const* shmaddr, int shmflg)
{
	ashv_check_pid();

	int socket_id = ashv_socket_id_from_shmid(shmid);
	void *addr;

	pthread_mutex_lock(&mutex);

	int idx = ashv_find_local_index(shmid);
	if (idx == -1 && socket_id != ashv_local_socket_id) {
		idx = ashv_read_remote_segment(shmid);
	}

	if (idx == -1) {
		pthread_mutex_unlock(&mutex);
		errno = EINVAL;
		return (void*) -1;
	}

	if (shmem[idx].addr == NULL) {
		shmem[idx].addr = mmap((void*) shmaddr, shmem[idx].size, PROT_READ | (shmflg == 0 ? PROT_WRITE : 0), MAP_SHARED, shmem[idx].descriptor, 0);
		if (shmem[idx].addr == MAP_FAILED) {
			shmem[idx].addr = NULL;
		}
	}
	addr = shmem[idx].addr;
	pthread_mutex_unlock (&mutex);

	return addr ? addr : (void *)-1;
}

/* Detach shared memory segment. */
int shmdt(void const* shmaddr)
{
	ashv_check_pid();

	pthread_mutex_lock(&mutex);
	for (size_t i = 0; i < shmem_amount; i++) {
		if (shmem[i].addr == shmaddr) {
			munmap(shmem[i].addr, shmem[i].size);
			shmem[i].addr = NULL;
			if (shmem[i].markedForDeletion || ashv_socket_id_from_shmid(shmem[i].id) != ashv_local_socket_id) {
				android_shmem_delete(i);
			}
			pthread_mutex_unlock(&mutex);
			return 0;
		}
	}
	pthread_mutex_unlock(&mutex);

	/* Could be a remove segment, do not report an error for that. */
	return 0;
}

/* Shared memory control operation. */
int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	ashv_check_pid();

	if (cmd == IPC_RMID) {
		pthread_mutex_lock(&mutex);
		int idx = ashv_find_local_index(shmid);
		if (idx == -1) {
			/* We do not rm non-local regions, but do not report an error for that. */
			pthread_mutex_unlock(&mutex);
			return 0;
		}

		if (shmem[idx].addr) {
			// shmctl(2): The segment will actually be destroyed only
			// after the last process detaches it (i.e., when the shm_nattch
			// member of the associated structure shmid_ds is zero.
			shmem[idx].markedForDeletion = true;
		} else {
			android_shmem_delete(idx);
		}
		pthread_mutex_unlock(&mutex);
		return 0;
	} else if (cmd == IPC_STAT) {
		if (!buf) {
			errno = EINVAL;
			return -1;
		}

		pthread_mutex_lock(&mutex);
		int idx = ashv_find_local_index(shmid);
		if (idx == -1) {
			pthread_mutex_unlock (&mutex);
			errno = EINVAL;
			return -1;
		}
		/* Report max permissive mode */
		memset(buf, 0, sizeof(struct shmid_ds));
		buf->shm_segsz = shmem[idx].size;
		buf->shm_nattch = 1;
		buf->shm_perm.__key = shmem[idx].key;
		buf->shm_perm.uid = geteuid();
		buf->shm_perm.gid = getegid();
		buf->shm_perm.cuid = geteuid();
		buf->shm_perm.cgid = getegid();
		buf->shm_perm.mode = 0666;
		buf->shm_perm.__seq = 1;

		pthread_mutex_unlock (&mutex);
		return 0;
	}

	errno = EINVAL;
	return -1;
}

int setgroups(size_t size, const gid_t *list) {
	const int nbless = sizeof(blessed_groups)/sizeof(gid_t);
	static int (*orig)(size_t, const gid_t *);
	if (orig == NULL)
		orig = dlsym(RTLD_NEXT, "setgroups");
	gid_t tmp[size + nbless];
	memcpy(tmp, list, size * sizeof(gid_t));
	memcpy(tmp + size, blessed_groups, sizeof(blessed_groups));
	return orig(size + nbless, tmp);
}

int initgroups(const char *user, gid_t group) {
	gid_t tab[NGROUPS_MAX];
	int n = NGROUPS_MAX;
	int got = getgrouplist(user, group, tab, &n);
	if (got < 0) return got;
	return setgroups(got, tab);
}


// 1 if exists and suid or sgid
int gethash(char *key, char *path, struct stat *st) {
	char tmp[4096], tmp2[4096];
	if (stat(path, st))
		return 0;
	if (readlink(path, tmp, 4096)<0)
		return 0;
	// the hashed file is already in cache
	if (!memcmp(tmp, SUIDCACHE, sizeof(SUIDCACHE)-1))
		return 0;
	if (!(st->st_mode & (S_ISGID|S_ISUID)))
		return 0;
	if (!S_ISREG(st->st_mode))
		return 0;

	sprintf(tmp2, "%lld-%lld-%d-%d-%d-%lld-%d-%d-%s",
		(long long)st->st_dev, (long long)st->st_ino, (int)st->st_mode, (int)st->st_uid, (int)st->st_gid, (long long)st->st_size, (int)st->st_mtime, (int)st->st_ctime, tmp);
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, tmp2, strlen(tmp2));
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_Final(hash, &sha256);
	for (int i = 0; i < 32; i++) {
		sprintf(key + i*2, "%02hhx", hash[i]);
	}
	key[64] = 0;

	return 1;
}

const char elf_interpreter[] __attribute__((section(".interp"))) = LINKER;
void run() {
	umask(0);
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SUIDCACHE ".pipe");
	if (bind(fd, (struct sockaddr*)&addr, SUN_LEN(&addr)))
		exit(0);
	if (listen(fd, 16))
		exit(0);
	int cli = - 1;
	int infd = -1;
	int outfd = -1;
	char *rdata = NULL;
	umask(022);
	while (1) {
		if (rdata != NULL)
			free(rdata);
		if (cli != -1)
			close(cli);
		if (infd != -1)
			close(infd);
		if (outfd != -1)
			close(outfd);
		outfd = infd = cli = -1;
		rdata = NULL;

		cli = accept(fd, NULL, NULL);
		struct ucred ucred;
		unsigned len = sizeof(ucred);
		if (getsockopt(cli, SOL_SOCKET, SO_PEERCRED, &ucred, &len))
			continue;
		char buf[4096], buf2[4096];
		sprintf(buf, "/proc/%d/exe", ucred.pid);

		struct stat st, st2;
		if (!gethash(buf2, buf, &st))
			continue;

		infd = open(buf, O_RDONLY);
		if (infd < 0)
			continue;

		sprintf(buf, SUIDCACHE "%s", buf2);
		if (!stat(buf, &st2)) // already exists
			continue;

		// actually, identical file
		if ((st.st_dev == st2.st_dev) && (st.st_ino == st2.st_ino))
			continue;

		// new copy
		int outfd = open(SUIDCACHE ".tmp", O_CREAT|O_WRONLY, st.st_mode & 07777);
		if (outfd < 0)
			continue;
		// TODO: this is bad idea for large binaries
		rdata = malloc(st.st_size);
		if (rdata == NULL)
			continue;
		if (read(infd, rdata, st.st_size) != st.st_size)
			continue;
		if (write(outfd, rdata, st.st_size) != st.st_size)
			continue;
		if (fchown(outfd, st.st_uid, st.st_gid))
			continue;
		if (fchmod(outfd, st.st_mode & 07777))
			continue;
		// other attributes are not cared for as they don't have any affect
		close(outfd);
		outfd = -1;
		// all seems good, rename the output
		rename(SUIDCACHE ".tmp", buf);
	}

	exit(0);
}

extern char **environ;
static __attribute__((constructor)) void init(int argc, char **argv)
{
	struct stat st;
	char key[4096], buf[4096];

	if (!gethash(key, "/proc/self/exe", &st))
		return;
	int getperm = 0;
	if ((st.st_mode & S_ISGID) && (getegid() != st.st_gid))
		getperm = 1;
	if ((st.st_mode & S_ISUID) && (geteuid() != st.st_uid))
		getperm = 1;
	//printf("%d\n", getperm);
	if (!getperm)
		return;
	struct statvfs vfs;
	if (statvfs("/proc/self/exe", &vfs))
		return;
	if (!(vfs.f_flag & ST_NOSUID))
		return;

	sprintf(buf, SUIDCACHE "%s", key);
	execve(buf, argv, environ);

	// ping the server to make a new one
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SUIDCACHE ".pipe");
	if (!connect(fd, (struct sockaddr*)&addr, SUN_LEN(&addr))) {
		char dummy;
		read(fd, &dummy, 1); // closed socket = server done
	}
	close(fd);
	execve(buf, argv, environ);
}


