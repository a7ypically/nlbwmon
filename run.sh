#!/bin/sh
./nlbwmon_test -o /root/nlbwmon -b 524288 -i 24h -r 30s -p /usr/share/nlbwmon/protocols -G 10 -I 1 -L 10000 -Z -s 192.168.0.0/16 -s 172.16.0.0/12 -w wan:eth5 -w wan_015:eth4 -w bint:l2tp-bint
