# TODO rsyslog
# TODO union /etc AFTER debootstrap, not before

#!/system/bin/sh
cat <<_banner
                   _
   _ __  __ _ __ _(_)__ _ _ _
  | '  \/ _\` / _\` | / _\` | ' \\
  |_|_|_\__,_\__, |_\__,_|_||_|
             |___/ v1

_banner

export busybox=/data/adb/magisk/busybox
export instlog=install.log

export mirror=http://deb.debian.org/debian
export distro=stable
export addpkg=htop,powertop,iptables,iproute2,net-tools,mc,traceroute,inetutils-ping,procps,sysvinit-core,libc6-dev,libssl-dev,gcc,vim-tiny,nano


export cdbpath=/pool/main/c/cdebootstrap/
export cdb=cdebootstrap-static_0.6.4_
export dirlist="bin etc lib run sbin usr var"

export tmperr=.tmperr
export abilist=`getprop ro.product.cpu.abilist`
export cpu="unknown"

echo -n > $instlog
log() {
	echo "* $1"
	echo "* $1" >> $instlog
	echo "** Running: '$3'" >> $instlog
	sh -c "$3" 2> $tmperr
	cat $tmperr >> $instlog 2> /dev/null
	if [ "$?" != "0" ] && [ "$2" == "" ]; then
		echo "*** ERROR Command:"
		echo "   $3"
		echo "*** Failed with:"
		cat $tmperr
		echo "*** See $instlog for full log."
		exit 1
	fi
	if ! sh -c "$2"; then
		echo "*** ERROR Command:"
		echo "   $3"
		echo "*** Failed with:"
		cat $tmperr
		echo "*** Tripped by: $2" | tee >> $instlog
		echo "*** See $instlog for full log."
		exit 1
	fi
}


for abi in ${abilist//,/ }; do
	case $abi in
		arm64*)
			cpu=arm64
			break
			;;
		armeabi*)
			cpu=armhf
			break
			;;
		x86_64*)
			cpu=amd64
			break
			;;
		x86*)
			cpu=i386
			break
			;;
	esac
done

export PATH=./bin:$PATH
mkdir -p bin
# these are all for the sake of cdebootstrap
ln -s $busybox bin/wget 2> /dev/null
ln -s $busybox bin/tar 2> /dev/null
ln -s $busybox bin/ar 2> /dev/null
ln -s $busybox bin/sha256sum 2> /dev/null
deb=$cdb$cpu.deb
rm -rf usr
rm -f $deb debian-binary data.tar.*z control.tar.*z
log "Get $deb" "test -e ./usr/bin/cdebootstrap-static" \
"wget $mirror/$cdbpath$deb
ar x $deb
tar xf data.tar.*z
rm -f data.tar.*z control.tar.*z debian-binary"

cleantarget() {
	# Clean up left over target, if any
	#for i in 1 2 3 4 5 6 7 8; do
	for i in 1 2; do
		for n in $dirlist; do
			(umount target/$n || umount -l target/$n) 2> /dev/null
			rmdir target/$n 2> /dev/null
		done
		(umount target || umount -l target) 2> /dev/null
	done
}

if true; then

echo "* Clean previous target if present"
cleantarget
if test -d target/var; then
	echo "Target folder busy; you'll need to reboot to unhog the mount and try again"
	exit 1
fi

log "Provisional /bin/sh" "test -e /bin/sh" \
	"mount -o remount,rw / && mkdir -p /bin && ln -s /system/bin/sh /bin/sh"

# make a symlink-mirror of the fixed etc structure
log "Root directory" "test -d root/etc" \
	"mkdir -p root && cp -as /system/etc/ root/ && ln -s /vendor/etc/fstab.* root/etc/fstab"

rm -f root/etc/passwd root/etc/shadow root/etc/group root/etc/hosts

log "Root subdirs, and target links" "test -e target/var" \
'mkdir -p target
mount -t tmpfs none target
for dir in $dirlist; do
	(mkdir -p root/$dir target/$dir && mount -o bind root/$dir target/$dir) || exit 1
done'

export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin
count=0
rm -f target/var/run target/var/lock
total=1550
echo "* Installing Debian $distro/$cpu"
(./usr/bin/cdebootstrap-static --suite-config=sid -q -f minimal --include=$addpkg --allow-unauthenticated -c ./usr/share/cdebootstrap-static -H ./usr/share/cdebootstrap-static -v $distro ./target $mirror && touch target/.ok) 2>&1 | while read line; do
	echo $line >> $instlog
	if [ $count -lt $total ]; then
		echo -ne "\r$((count * 100 / total))%"
	fi
	count=$((count+1))
done
if ! [ -e target/.ok ]; then
	echo -e "\r*** FAILED."
	tail -20 $instlog
	echo "*** You can find full error log in $instlog"
	exit 1
fi
echo "\rDONE"


log "Setting up resolver" "test -e target/etc/resolv.conf" "if [ ! -e target/etc/resolv.conf ]; then echo nameserver 8.8.8.8 > target/etc/resolv.conf; fi"

cat << _EOF > target/tmp/compile
LINKER=\$(readelf -l /bin/ls | grep 'Requesting' | cut -d':' -f2 | tr -d ' ]')
gcc -Wall -lcrypt -ldl -shared -fPIC -Wl,-erun /sbin/magian.c -DLINKER=\"$LINKER\" -o /sbin/magian
_EOF

log "Compiling compat library" "test -f target/sbin/magian && test -f target/etc/ld.so.preload" \
"cp -f magian.c target/sbin/magian.c
chroot target sh /tmp/compile
rm -f target/etc/ld.so.preload
echo /sbin/magian > target/etc/ld.so.preload
"

fi
exit 0
cleantarget

log "Deleting temporary files" "! test -e target" "
rm -rf usr target bin
rm -f cdebootstrap*deb
rm -f $tmperr
"
chroot target /bin/su -c "apt-get update"

