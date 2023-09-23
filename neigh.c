/*
  ISC License

  Copyright (c) 2016-2017, Jo-Philipp Wich <jo@mein.io>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
  OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
  PERFORMANCE OF THIS SOFTWARE.
*/

#include <libubox/avl.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <endian.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "utils.h"
#include "hosts.h"
#include "notify.h"
#include "neigh.h"

static struct avl_tree neighbors;

static struct nl_sock *rt_sock = NULL;
static struct nl_cb *rt_cb = NULL;
static bool rt_done = false;

static int
cb_done(struct nl_msg *msg, void *arg)
{
	rt_done = true;
	return NL_STOP;
}

static int
cb_error(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	rt_done = true;
	return NL_STOP;
}

static int
rt_connect(void)
{
	int err = -ENOMEM;

	rt_sock = nl_socket_alloc();
	if (!rt_sock)
		goto out;

	rt_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!rt_cb)
		goto out;

	err = nl_connect(rt_sock, NETLINK_ROUTE);
	if (err < 0)
		goto out;

	nl_cb_set(rt_cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_done, NULL);
	nl_cb_err(rt_cb, NL_CB_CUSTOM, cb_error, NULL);

	return 0;

out:
	if (rt_cb)
		nl_cb_put(rt_cb);

	if (rt_sock)
		nl_socket_free(rt_sock);

	return err;
}


struct neigh_query {
	int family;
	const void *addr;
	struct ether_addr *mac;
};

static uint32_t neigh_parse_cnt;
static int
neigh_parse(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ndmsg *nd = NLMSG_DATA(hdr);
	struct nlattr *tb[NDA_MAX+1];

	struct neigh_query *query = arg;
	struct ether_addr empty = { };
	static struct ether_addr res;

	neigh_parse_cnt++;

	if (hdr->nlmsg_type != RTM_NEWNEIGH || nd->ndm_family != query->family)
		return NL_SKIP;

	if (nd->ndm_state & (NUD_NOARP | NUD_FAILED | NUD_INCOMPLETE))
		return NL_SKIP;

	if (nlmsg_parse(hdr, sizeof(*nd), tb, NDA_MAX, NULL))
		return NL_SKIP;

	if (!tb[NDA_LLADDR] || !tb[NDA_DST])
		return NL_SKIP;

	if (memcmp(nla_data(tb[NDA_DST]), query->addr, nla_len(tb[NDA_DST])))
		return NL_SKIP;

	if (nla_len(tb[NDA_LLADDR]) > sizeof(res))
		return NL_SKIP;

	if (!memcmp(nla_data(tb[NDA_LLADDR]), &empty, nla_len(tb[NDA_LLADDR])))
		return NL_SKIP;

	memset(&res, 0, sizeof(res));
	memcpy(&res, nla_data(tb[NDA_LLADDR]), nla_len(tb[NDA_LLADDR]));
	query->mac = &res;

	return NL_SKIP;
}

static struct ether_addr *
ipaddr_to_macaddr(int family, const void *addr)
{
	struct neigh_query query = { .family = family, .addr = addr };
	struct ndmsg ndm = { .ndm_family = family };
	struct nl_msg *msg = NULL;
	struct in_addr in;

	if (family == AF_INET) {
		in = *(struct in_addr *)addr;
		in.s_addr = htobe32(in.s_addr);
		query.addr = &in;
	}

	msg = nlmsg_alloc_simple(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);

	if (!msg)
		return NULL;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	rt_done = false;

	nl_cb_set(rt_cb, NL_CB_VALID, NL_CB_CUSTOM, neigh_parse, &query);
	nl_send_auto_complete(rt_sock, msg);
	nlmsg_free(msg);

	debug_printf("ipaddr_to_macaddr - dump %s\n", format_ipaddr(family, (void *)addr, 1));
	while (!rt_done)
		nl_recvmsgs(rt_sock, rt_cb);
	debug_printf("parsed - %d\n", neigh_parse_cnt);

	return query.mac;
}


struct ifindex_query {
	int family;
	const void *addr;
	int ifindex;
};

static uint32_t ipaddr_parse_cnt;
static int
ipaddr_parse(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifaddrmsg *ifa;
	struct nlattr *addr, *tb[__IFA_MAX+1];
	struct ifindex_query *query = arg;
	int len = hdr->nlmsg_len;

	for (; nlmsg_ok(hdr, len); hdr = nlmsg_next(hdr, &len)) {
		ipaddr_parse_cnt++;
		if (hdr->nlmsg_type != RTM_NEWADDR)
			continue;

		ifa = nlmsg_data(hdr);

		if (ifa->ifa_family != query->family)
			continue;

		if (nlmsg_parse(hdr, sizeof(*ifa), tb, __IFA_MAX, NULL))
			continue;

		addr = tb[IFA_LOCAL] ? tb[IFA_LOCAL] : tb[IFA_ADDRESS];

		if (!addr || memcmp(nla_data(addr), query->addr, nla_len(addr)))
			continue;

		query->ifindex = ifa->ifa_index;
	}

	return NL_SKIP;
}

static int
ipaddr_to_ifindex(int family, const void *addr)
{
	struct ifindex_query query = { .family = family, .addr = addr };
	struct ifaddrmsg ifa = { .ifa_family = family };
	struct nl_msg *msg = NULL;

	struct in_addr in;

	if (family == AF_INET) {
		in = *(struct in_addr *)addr;
		in.s_addr = htobe32(in.s_addr);
		query.addr = &in;
	}

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);

	if (!msg)
		return -1;

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	rt_done = false;

	nl_cb_set(rt_cb, NL_CB_VALID, NL_CB_CUSTOM, ipaddr_parse, &query);
	nl_send_auto_complete(rt_sock, msg);
	nlmsg_free(msg);

	debug_printf("ipaddr_to_ifindex - dump %s\n", format_ipaddr(family, (void *)addr, 1));

	while (!rt_done)
		nl_recvmsgs(rt_sock, rt_cb);

	debug_printf("parsed - %d\n", ipaddr_parse_cnt);

	return query.ifindex;
}


static struct ether_addr *
link_parse(void *msg, int len)
{
	static struct ether_addr mac;

	struct nlattr *tb[__IFLA_MAX+1];
	struct ifinfomsg *ifi;
	struct nlmsghdr *hdr;

	for (hdr = msg; nlmsg_ok(hdr, len); hdr = nlmsg_next(hdr, &len)) {
		if (hdr->nlmsg_type != RTM_NEWLINK)
			continue;

		ifi = nlmsg_data(hdr);

		if (nlmsg_parse(hdr, sizeof(*ifi), tb, __IFLA_MAX, NULL))
			continue;

		if (!tb[IFLA_ADDRESS])
			continue;

		if (nla_len(tb[IFLA_ADDRESS]) > sizeof(mac))
			continue;

		memset(&mac, 0, sizeof(mac));
		memcpy(&mac, RTA_DATA(tb[IFLA_ADDRESS]), nla_len(tb[IFLA_ADDRESS]));

		return &mac;
	}

	return NULL;
}

static struct ether_addr *
ifindex_to_macaddr(int ifindex)
{
	struct ifinfomsg ifi = { .ifi_index = ifindex };
	struct ether_addr *mac = NULL;
	struct nl_msg *msg = NULL;
	struct sockaddr_nl peer;
	unsigned char *reply;
	int len;

	msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST);

	if (!msg)
		return NULL;

	nlmsg_append(msg, &ifi, sizeof(ifi), 0);
	nl_send_auto_complete(rt_sock, msg);
	nlmsg_free(msg);

	len = nl_recv(rt_sock, &peer, &reply, NULL);

	if (len > 0) {
		mac = link_parse(reply, len);
		free(reply);
	}

	return mac;
}


int
update_macaddr(int family, const void *addr)
{
	struct neigh_entry *ptr, *tmp;
	union neigh_key key = { };
	struct ether_addr *res;
	int ifindex;

	debug_printf("update_macaddr - %s\n", format_ipaddr(family, (void *)addr, 1));

	if (family == AF_INET6) {
		key.data.family = AF_INET6;
		key.data.addr.in6 = *(struct in6_addr *)addr;
	}
	else {
		key.data.family = AF_INET;
		key.data.addr.in = *(struct in_addr *)addr;
		//key.data.addr.in.s_addr = htobe32(((struct in_addr *)addr)->s_addr);
	}

	res = ipaddr_to_macaddr(family, &key.data.addr);

	if (!res) {
		ifindex = ipaddr_to_ifindex(family, &key.data.addr);

		if (ifindex > 0)
			res = ifindex_to_macaddr(ifindex);

		if (!res)
			return -ENOENT;
	}

	ptr = avl_find_element(&neighbors, &key, tmp, node);

	if (!ptr) {
		ptr = calloc(1, sizeof(*ptr));

		if (!ptr)
			return -ENOMEM;

		ptr->key = key;
		ptr->node.key = &ptr->key;

		avl_insert(&neighbors, &ptr->node);
	}

	if (memcmp(&ptr->mac, res, sizeof(*res))) {
		ptr->mac = *res;
		if (hosts_is_new(res)) notify_new_client(res);
	}
	return 0;
}

int
lookup_macaddr(int family, const void *addr, struct ether_addr *mac)
{
	struct neigh_entry *ptr, *tmp;
	union neigh_key key = { };

	if (family == AF_INET6) {
		key.data.family = AF_INET6;
		key.data.addr.in6 = *(struct in6_addr *)addr;
	}
	else {
		key.data.family = AF_INET;
		key.data.addr.in = *(struct in_addr *)addr;
		//key.data.addr.in.s_addr = be32toh(((struct in_addr *)addr)->s_addr);
	}

	ptr = avl_find_element(&neighbors, &key, tmp, node);

	if (!ptr) {
		ptr = calloc(1, sizeof(*ptr));

		if (!ptr)
			return -ENOMEM;

		ptr->key = key;
		ptr->node.key = &ptr->key;

		avl_insert(&neighbors, &ptr->node);

		return -ENOENT;
	}

	*mac = ptr->mac;
	return 0;
}


void neigh_ubus_update(int ack, const char *ip, const char *mac)
{
	struct neigh_entry *ptr, *tmp;
	union neigh_key key = { };

	if (inet_pton(AF_INET6, ip, &key.data.addr.in6)) {
		key.data.family = AF_INET6;

	}
	else if (inet_pton(AF_INET, ip, &key.data.addr.in)) {
		key.data.family = AF_INET;
		key.data.addr.in.s_addr = be32toh(key.data.addr.in.s_addr);
	} else {
		error_printf("Error Wrong IP format: %s\n", ip);
		return;
	}

	struct ether_addr mac_addr;

	if (!ether_aton_r(mac, &mac_addr)) {
		error_printf("Error Wrong MAC addr format: %s\n", mac);
		return;
	}

	ptr = avl_find_element(&neighbors, &key, tmp, node);

	if (!ptr) {
		if (!ack) {
			error_printf("Error - Can not release dhcp (%s) - does not exist\n", ip);
			return;
		}

		//FIXME scan DB entries for this IP and update the mac addr. This can require merging.
		debug_printf("Creating new arp entry for %s\n", ip);

		ptr = calloc(1, sizeof(*ptr));

		ptr->key = key;
		ptr->node.key = &ptr->key;

		avl_insert(&neighbors, &ptr->node);
	}

	if (!ack) {
#if 0 // Some clients ignore DHCP renew time
		avl_delete(&neighbors, &ptr->node);
		debug_printf("Removing arp entry for %s\n", ip);
		free(ptr);
#endif
		return;
	}
	debug_printf("Updating arp entry for %s\n", ip);

	if (memcmp(&ptr->mac, &mac_addr, sizeof(mac_addr))) {
		ptr->mac = mac_addr;
		if (hosts_is_new(&mac_addr)) notify_new_client(&mac_addr);
	}
}


static int
avl_cmp_neigh(const void *k1, const void *k2, void *ptr)
{
	const union neigh_key *a = k1;
	const union neigh_key *b = k2;

	return memcmp(a->u32, b->u32, sizeof(a->u32));
}

__attribute__((constructor)) static void init_neighbors(void)
{
	rt_connect();
	avl_init(&neighbors, avl_cmp_neigh, false, NULL);
}
