#!/bin/sh
#gcc -o nlbwmon_test -DDEBUG_LOG -Wall -Werror --std=gnu99 -gdwarf-2 -g3 -Wmissing-declarations -D_GNU_SOURCE   -I . *.c ./libnl-3.a ./libubox.so ./libz.a ./libnl-genl-3.a ./libubus.so ./libubox.a ./libustream-ssl.so ./libuci.so -L /root/ssllib -lcrypto -lssl
#./libblobmsg_json.a ./libjson-c.a

gcc -o nlbwmon_test -DDEBUG_LOG -Wall -Werror --std=gnu99 -gdwarf-2 -g3 -Wmissing-declarations -D_GNU_SOURCE   -I . *.c ./libnl-3.a ./libubox.so ./libz.a ./libnl-genl-3.a ./libubus.so ./libubox.a ustream-ssl/ustream-ssl.c ustream-ssl/ustream-openssl.c ustream-ssl/ustream-io-openssl.c ./libuci.so -L /root/ssllib -lcrypto -lssl
