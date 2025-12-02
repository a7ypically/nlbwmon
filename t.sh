# Runtime configuration
. /lib/functions/network.sh
network_flush_cache
network_find_wan NET_IF
network_find_wan6 NET_IF6
#echo "${NET_IF}"
#echo "${NET_IF6}"
wan=bint
if network_get_device if_wan $wan; then
	echo ok
	echo "$wan:$if_wan"
fi
