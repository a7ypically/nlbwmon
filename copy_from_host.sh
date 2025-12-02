#!/bin/sh
SERVER=$1
DIR=$2

rsync -av --delete -e "ssh -i /etc/dropbear/dropbear_rsa_host_key" $SERVER:$DIR/staging_dir/target-x86_64_musl/usr/include/libubox/. libubox/.
rsync -av --delete -e "ssh -i /etc/dropbear/dropbear_rsa_host_key" $SERVER:$DIR/staging_dir/target-x86_64_musl/usr/include/libnl3/netlink/. netlink/.
rsync -av -e "ssh -i /etc/dropbear/dropbear_rsa_host_key" $SERVER:$DIR/staging_dir/target-x86_64_musl/usr/include/openssl/. /usr/include/openssl/.
for lib in "libnl-3.*" "libnl-genl-3.*" "libubox.*" "libz.*" "libubus.*" "libubox.*" "libustream-ssl.*" "libuci.*"; do
rm $lib
rsync -av -e "ssh -i /etc/dropbear/dropbear_rsa_host_key" $SERVER:$DIR/staging_dir/target-x86_64_musl/usr/lib/$lib .
done
scp -i /etc/dropbear/dropbear_rsa_host_key $SERVER:$DIR/staging_dir/target-x86_64_musl/usr/include/libubus.h .
scp -i /etc/dropbear/dropbear_rsa_host_key $SERVER:$DIR/staging_dir/target-x86_64_musl/usr/include/ubusmsg.h .

for lib in "libssl.*" "libcrypto.*"; do
rm /root/ssllib/$lib
rsync -av -e "ssh -i /etc/dropbear/dropbear_rsa_host_key" $SERVER:$DIR/staging_dir/target-x86_64_musl/usr/lib/$lib /root/ssllib/
done
