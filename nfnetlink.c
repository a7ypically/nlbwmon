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


#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include <libubox/uloop.h>

#include "nfnetlink.h"
#include "database.h"
#include "protocol.h"
#include "subnets.h"
#include "wans.h"
#include "utils.h"
#include "neigh.h"
#include "geoip.h"
#include "asn.h"
#include "dns.h"
#include "hosts.h"
#include "notify.h"
#include "tg.h"


static uint32_t n_pending_inserts = 0;
static struct nl_sock *nl = NULL;
static struct uloop_fd ufd = { };
static int nfnetlink_dump_in_progress;

static struct nla_policy ct_tuple_policy[CTA_TUPLE_MAX+1] = {
	[CTA_TUPLE_IP]          = { .type = NLA_NESTED },
	[CTA_TUPLE_PROTO]       = { .type = NLA_NESTED },
};

static struct nla_policy ct_ip_policy[CTA_IP_MAX+1] = {
	[CTA_IP_V4_SRC]         = { .type = NLA_U32 },
	[CTA_IP_V4_DST]         = { .type = NLA_U32 },
	[CTA_IP_V6_SRC]         = { .minlen = 16 },
	[CTA_IP_V6_DST]         = { .minlen = 16 },
};

static struct nla_policy ct_proto_policy[CTA_PROTO_MAX+1] = {
	[CTA_PROTO_NUM]         = { .type = NLA_U8 },
	[CTA_PROTO_SRC_PORT]    = { .type = NLA_U16 },
	[CTA_PROTO_DST_PORT]    = { .type = NLA_U16 },
	[CTA_PROTO_ICMP_ID]     = { .type = NLA_U16 },
	[CTA_PROTO_ICMP_TYPE]   = { .type = NLA_U8 },
	[CTA_PROTO_ICMP_CODE]   = { .type = NLA_U8 },
	[CTA_PROTO_ICMPV6_ID]   = { .type = NLA_U16 },
	[CTA_PROTO_ICMPV6_TYPE] = { .type = NLA_U8 },
	[CTA_PROTO_ICMPV6_CODE] = { .type = NLA_U8 },
};

static struct nla_policy ct_counters_policy[CTA_COUNTERS_MAX+1] = {
	[CTA_COUNTERS_PACKETS]  = { .type = NLA_U64 },
	[CTA_COUNTERS_BYTES]    = { .type = NLA_U64 },
	[CTA_COUNTERS32_PACKETS]= { .type = NLA_U32 },
	[CTA_COUNTERS32_BYTES]  = { .type = NLA_U32 },
};


struct delayed_record {
	struct uloop_timeout timeout;
	struct record record;
	uint32_t delay_retry;
};

static void update_dns(struct record *db_r)
{
	uint32_t dns_host_id = dns_inc_count_for_addr(db_r->family, &db_r->last_ext_addr);
	if (!dns_host_id) return;
	//If all slots are full skip
	if (db_r->hosts[RECORD_NUM_HOSTS-1]) return;
	for (int i=0; i<RECORD_NUM_HOSTS; ++i) {
		if (!db_r->hosts[i]) {
			db_r->hosts[i] = dns_host_id;
			debug_printf("update_dns - added dns id:%d in slot:%d\n", dns_host_id, i);
			return;
		}
		if (db_r->hosts[i] == dns_host_id) return;
	}
}

static void
database_insert_immediately(struct record *r)
{
	int ret;
	struct record *db_r;
	if (r->count != 0) {
		debug_printf("Database insert new connection - %s:\n", format_ipaddr(r->family, &r->last_ext_addr, 1));
#ifdef DEBUG_LOG
		print_record(r);
#endif

		ret = database_insert(gdbh, r, &db_r);
		if (ret < 0) {
			tg_send_msg("Error in database_insert!");
		} else {
			update_dns(db_r);
			if (ret == 1) {
				notify_new(db_r);
			}
			notify_update(db_r);
		}
	} else {
		if (database_update(gdbh, r, &db_r) == 0) {
			notify_update(db_r);
		} else {
			//FIXME Why do we reach this case?
			// Dump dumping new records that have not yet been seen
			// Mac address updates creates a new record from an existing one
			// Other cases?
			if (!nfnetlink_dump_in_progress) {
				error_printf("Error in database_update - %s:\n", format_ipaddr(r->family, &r->last_ext_addr, 1));
#ifdef DEBUG_LOG
				print_record(r);
#endif
			}
			ret = database_insert(gdbh, r, &db_r);
			debug_printf("Adding to database: %d\n", ret);
			if (ret < 0) {
				tg_send_msg("Error in database_insert!");
			} else {
				assert(ret != 0);

				if (ret == 1) {
					update_dns(db_r);
					notify_new(db_r);
				}
			}
		}
	}
}

static void
database_insert_delayed_cb(struct uloop_timeout *t)
{
	int err = 0;
	struct delayed_record *dr;

	dr = container_of(t, struct delayed_record, timeout);
	if (!(dr->record.type & RECORD_TYPE_WAN) && !dr->record.src_mac.u64) {
		err = lookup_macaddr(dr->record.family, &dr->record.src_addr.in6,
				       &dr->record.src_mac.ea);
		if (err == -ENOENT)  {
			err = update_macaddr(dr->record.family, &dr->record.src_addr.in6);

			if (err == 0)
				lookup_macaddr(dr->record.family, &dr->record.src_addr.in6,
					       &dr->record.src_mac.ea);
		}
	}

	if (!(dr->record.type & RECORD_TYPE_WAN) && !dr->record.src_mac.u64) {
		debug_printf("database_insert_delayed_cb - no mac addr for %s\n", format_ipaddr(dr->record.family, &dr->record.src_addr, 1));
	}

	if (!dr->record.country[0]) {
		err = geoip_lookup(&dr->record);

		if (err == -EAGAIN) {
			dr->delay_retry++;
			debug_printf("database_insert_delayed_cb - geoip(%s) for ", (dr->record.type & RECORD_TYPE_WAN) ? "wan": format_ipaddr(dr->record.family, &dr->record.src_addr, 1));
			debug_printf("%s is -EAGAIN. Delaying again (%d).\n", format_ipaddr(dr->record.family, &dr->record.last_ext_addr, 1), dr->delay_retry);
			if (uloop_timeout_set(&dr->timeout, 500) == -EEXIST) {
				error_printf("Error can not reset delayed record timer.\n");
			}

			return;
		}

		if (err) {
			if (err == -EINVAL) {
				debug_printf("database_insert_delayed_cb - invalid (bogon) geoip(%s) for ", (dr->record.type & RECORD_TYPE_WAN) ? "wan": format_ipaddr(dr->record.family, &dr->record.src_addr, 1));
			} else {
				debug_printf("database_insert_delayed_cb - no geoip(%s) for ", (dr->record.type & RECORD_TYPE_WAN) ? "wan": format_ipaddr(dr->record.family, &dr->record.src_addr, 1));
			}
			debug_printf("%s\n", format_ipaddr(dr->record.family, &dr->record.last_ext_addr, 1));
		}
	}

	if (dr->delay_retry > 0) {
		debug_printf("database_insert_delayed_cb - success after %d retries -  geoip(%s) for ", dr->delay_retry, (dr->record.type & RECORD_TYPE_WAN) ? "wan": format_ipaddr(dr->record.family, &dr->record.src_addr, 1));
		debug_printf("%s\n", format_ipaddr(dr->record.family, &dr->record.last_ext_addr, 1));
	}

	if (err != -EINVAL) database_insert_immediately(&dr->record);
	free(dr);

	if (n_pending_inserts > 0)
		n_pending_inserts--;
}

static int
database_insert_delayed(struct record *r)
{
	struct delayed_record *dr;

	/* to avoid gobbling up too much memory, tie the maximum allowed number
	 * of pending insertions to the configured database limit */
	if (opt.db.limit > 0 && n_pending_inserts >= opt.db.limit) {
		error_printf("Error - Too many pending MAC address or geoip lookups\n");
		database_insert_immediately(r);
		return -ENOSPC;
	}

	dr = calloc(1, sizeof(*dr));

	if (!dr)
		return -ENOMEM;

	dr->record = *r;
	dr->timeout.cb = database_insert_delayed_cb;

	n_pending_inserts++;

	return uloop_timeout_set(&dr->timeout, 500) ? -EEXIST : 0;
}

static bool
parse_addrs(struct nlattr **tuple, uint8_t *family, void *saddr, void *daddr)
{
	struct nlattr *addrs[CTA_IP_MAX + 1];

	if (nla_parse_nested(addrs, CTA_IP_MAX, tuple[CTA_TUPLE_IP], ct_ip_policy))
		return false;

	if (addrs[CTA_IP_V4_SRC] && addrs[CTA_IP_V4_DST]) {
		*family = AF_INET;
		((struct in_addr *)saddr)->s_addr = htobe32(nla_get_u32(addrs[CTA_IP_V4_SRC]));
		((struct in_addr *)daddr)->s_addr = htobe32(nla_get_u32(addrs[CTA_IP_V4_DST]));
		return true;
	}
	else if (addrs[CTA_IP_V6_SRC] && addrs[CTA_IP_V6_DST]) {
		*family = AF_INET6;
		nla_memcpy(saddr, addrs[CTA_IP_V6_SRC], 16);
		nla_memcpy(daddr, addrs[CTA_IP_V6_DST], 16);
		return true;
	}

	return false;
}

static bool
parse_proto_port(struct nlattr **tuple, bool src, uint8_t *proto, uint16_t *port)
{
	struct nlattr *tb[CTA_PROTO_MAX + 1];

	*proto = 0;
	*port = 0;

	if (nla_parse_nested(tb, CTA_PROTO_MAX, tuple[CTA_TUPLE_PROTO], ct_proto_policy))
		return false;

	if (tb[CTA_PROTO_NUM]) {
		*proto = nla_get_u8(tb[CTA_PROTO_NUM]);

		if (tb[src ? CTA_PROTO_SRC_PORT : CTA_PROTO_DST_PORT])
			*port = nla_get_u16(tb[src ? CTA_PROTO_SRC_PORT : CTA_PROTO_DST_PORT]);

		return true;
	}

	return false;
}

static void
parse_event(void *reply, int len, bool allow_insert, bool update_mac)
{
	int err, geo_err;
	struct nlmsghdr *hdr;
	struct genlmsghdr *gnlh;
	static struct nlattr *attr[__CTA_MAX + 1];
	static struct nlattr *tuple[CTA_TUPLE_MAX + 1];
	static struct nlattr *counters[CTA_COUNTERS_MAX + 1];

	struct record r = { };
	struct in6_addr orig_saddr, orig_daddr, reply_saddr, reply_daddr;

	uint64_t orig_pkts, orig_bytes, reply_pkts, reply_bytes;
	uint16_t orig_port, reply_port;
	uint8_t orig_proto, reply_proto;

	int wan_idx;

	for (hdr = reply; nlmsg_ok(hdr, len); hdr = nlmsg_next(hdr, &len)) {
		gnlh = nlmsg_data(hdr);
		orig_pkts = 0;
		orig_bytes = 0;
		reply_pkts = 0;
		reply_bytes = 0;
		memset(&r, 0, sizeof(r));
		memset(&orig_saddr, 0, sizeof(orig_saddr));
		memset(&orig_daddr, 0, sizeof(orig_daddr));
		memset(&reply_saddr, 0, sizeof(reply_saddr));
		memset(&reply_daddr, 0, sizeof(reply_daddr));

		if (nla_parse(attr, __CTA_MAX, genlmsg_attrdata(nlmsg_data(hdr), 0),
				      genlmsg_attrlen(gnlh, 0), NULL))
			continue;

		if (!attr[CTA_TUPLE_ORIG] ||
		    nla_parse_nested(tuple, CTA_TUPLE_MAX, attr[CTA_TUPLE_ORIG], ct_tuple_policy))
			continue;

		if (!parse_addrs(tuple, &r.family, &orig_saddr, &orig_daddr) ||
		    !parse_proto_port(tuple, false, &orig_proto, &orig_port))
			continue;

		if (!attr[CTA_TUPLE_REPLY] ||
		    nla_parse_nested(tuple, CTA_TUPLE_MAX, attr[CTA_TUPLE_REPLY], ct_tuple_policy))
			continue;

		if (!parse_addrs(tuple, &r.family, &reply_saddr, &reply_daddr) ||
		    !parse_proto_port(tuple, true, &reply_proto, &reply_port))
			continue;

		if (attr[CTA_COUNTERS_ORIG] &&
		    !nla_parse_nested(counters, CTA_COUNTERS_MAX, attr[CTA_COUNTERS_ORIG], ct_counters_policy)) {
			orig_pkts = nla_get_u64(counters[CTA_COUNTERS_PACKETS]);
			orig_bytes = nla_get_u64(counters[CTA_COUNTERS_BYTES]);
		}

		if (attr[CTA_COUNTERS_REPLY] &&
		    !nla_parse_nested(counters, CTA_COUNTERS_MAX, attr[CTA_COUNTERS_REPLY], ct_counters_policy)) {
			reply_pkts = nla_get_u64(counters[CTA_COUNTERS_PACKETS]);
			reply_bytes = nla_get_u64(counters[CTA_COUNTERS_BYTES]);
		}

		/* local -> remote */
		if (!match_subnet(r.family, &orig_saddr) && match_subnet(r.family, &orig_daddr)) {
			r.proto = orig_proto;
			r.dst_port = orig_port;
			r.in_pkts = reply_pkts;
			r.in_bytes = reply_bytes;
			r.out_pkts = orig_pkts;
			r.out_bytes = orig_bytes;
			r.src_addr.in6 = orig_saddr;
			r.last_ext_addr = orig_daddr;
		}

		/* remote -> local */
		else if (!match_subnet(r.family, &reply_saddr) && match_subnet(r.family, &reply_daddr)) {
			r.proto = reply_proto;
			r.dst_port = reply_port;
			r.in_pkts = orig_pkts;
			r.in_bytes = orig_bytes;
			r.out_pkts = reply_pkts;
			r.out_bytes = reply_bytes;
			r.type = RECORD_TYPE_WAN_IN;
			r.src_addr.in6 = reply_saddr;
			r.last_ext_addr = reply_daddr;
		}

		/* WAN local -> remote */
		else if ((wan_idx = match_wan(r.family, &reply_daddr)) >= 0) {
			r.proto = orig_proto;
			r.dst_port = orig_port;
			r.in_pkts = reply_pkts;
			r.in_bytes = reply_bytes;
			r.out_pkts = orig_pkts;
			r.out_bytes = orig_bytes;
			r.src_addr.in6 = orig_saddr;
			r.type = RECORD_TYPE_WAN;
			r.src_addr.wan_idx = wan_idx;
			r.last_ext_addr = orig_daddr;
		}

		/* WAN remote -> local */
		else if ((wan_idx = match_wan(r.family, &orig_daddr)) >= 0) {
			r.proto = reply_proto;
			r.dst_port = reply_port;
			r.in_pkts = orig_pkts;
			r.in_bytes = orig_bytes;
			r.out_pkts = reply_pkts;
			r.out_bytes = reply_bytes;
			r.type = RECORD_TYPE_WAN|RECORD_TYPE_WAN_IN;
			r.src_addr.wan_idx = wan_idx;
			r.last_ext_addr = reply_daddr;
		}

		/* local -> local or remote -> remote */
		else {
			continue;
		}

		if (!protocol_include(r.proto, be16toh(r.dst_port))) {
			r.proto = 0;
			r.dst_port = 0;
		}

		r.count = htobe64(allow_insert);

		if (r.type & RECORD_TYPE_WAN) {
			err = 0;
		} else {
			//if (update_mac)
			//	update_macaddr(r.family, &r.src_addr.in6);

			err = lookup_macaddr(r.family, &r.src_addr.in6, &r.src_mac.ea);
			if (err == -ENOENT)
				update_macaddr(r.family, &r.src_addr.in6);
		}

		geo_err = geoip_lookup(&r);

		if (geo_err == -EINVAL) {
			debug_printf("parse_event - invalid (bogon) geoip(%s) for ", (r.type & RECORD_TYPE_WAN) ? "wan": format_ipaddr(r.family, &r.src_addr, 1));
			debug_printf("%s\n", format_ipaddr(r.family, &r.last_ext_addr, 1));
			continue;
		}

		if ((geo_err == -EAGAIN) || (update_mac && (err == -ENOENT)))
			database_insert_delayed(&r);
		else {
			if ((!r.type & RECORD_TYPE_WAN) && !r.src_mac.u64) {
				debug_printf("database_insert_immediately - no mac addr for %s\n", format_ipaddr(r.family, &r.src_addr, 1));
			}
			database_insert_immediately(&r);
		}
	}
}

static void
handle_event(struct uloop_fd *fd, unsigned int ev)
{
	struct sockaddr_nl peer;
	struct nlmsghdr *hdr;
	unsigned char *msg;
	bool is_new;
	int len;

	len = nl_recv(nl, &peer, &msg, NULL);

	if (len > 0) {
		database_archive(gdbh);

		hdr = (struct nlmsghdr *)msg;
		is_new = (NFNL_MSG_TYPE(hdr->nlmsg_type) == IPCTNL_MSG_CT_NEW);
		parse_event(msg, len, is_new, is_new);
		free(msg);
	}
}

static int
handle_dump(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	bool *allow_insert = arg;
	parse_event(hdr, hdr->nlmsg_len, *allow_insert, true);
	return NL_OK;
}

static int
handle_error(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int
handle_finish(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int
handle_ack(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int
handle_seq(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static void
check_rmem_max(int bufsize)
{
	char buf[16];
	int max = 0;
	FILE *f;

	f = fopen("/proc/sys/net/core/rmem_max", "r");

	if (f) {
		if (fgets(buf, sizeof(buf), f))
			max = atoi(buf);

		fclose(f);
	}

	if (bufsize > max)
		fprintf(stderr,
		        "The netlink receive buffer size of %d bytes will be capped to %d bytes\n"
		        "by the kernel. The net.core.rmem_max sysctl limit needs to be raised to\n"
		        "at least %d in order to sucessfully set the desired receive buffer size!\n",
		        bufsize, max, bufsize);
}


int
nfnetlink_connect(int bufsize)
{
	nl = nl_socket_alloc();

	if (!nl)
		return -ENOMEM;

	if (nl_connect(nl, NETLINK_NETFILTER))
		return -errno;

	if (nl_socket_add_memberships(nl, NFNLGRP_CONNTRACK_NEW,
					  //NFNLGRP_CONNTRACK_UPDATE,
	                                  NFNLGRP_CONNTRACK_DESTROY, 0))
		return -errno;

	check_rmem_max(bufsize);

	if (nl_socket_set_buffer_size(nl, bufsize, 0))
		return -errno;

	ufd.cb = handle_event;
	ufd.fd = nl_socket_get_fd(nl);

	if (uloop_fd_add(&ufd, ULOOP_READ))
		return -errno;

	return 0;
}

int
nfnetlink_dump(bool allow_insert)
{
	struct nl_msg *req = NULL;
	struct nl_cb *cb = NULL;
	struct nlattr *tuple, *ip, *proto;
	struct nfgenmsg hdr = {
		.nfgen_family = AF_UNSPEC,
		.version = NFNETLINK_V0,
		.res_id = 0, //htons(res_id),
	};

	int err, ret;

	errno = ENOMEM;

	req = nlmsg_alloc_simple(
		(NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET_CTRZERO,
		NLM_F_REQUEST | NLM_F_DUMP);

	if (!req)
		goto err;

	if (nlmsg_append(req, &hdr, sizeof(hdr), NLMSG_ALIGNTO) < 0)
		goto err;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto err;

	tuple = nla_nest_start(req, CTA_TUPLE_ORIG);
	if (!tuple)
		goto err;

	ip = nla_nest_start(req, CTA_TUPLE_IP);
	if (!ip)
		goto err;

	//addr = nfnl_ct_get_src(ct, repl);
	//if (addr)
	//	NLA_PUT_ADDR(req,
	//		     family == AF_INET ? CTA_IP_V4_SRC : CTA_IP_V6_SRC,
	//		     addr);
	//
	//addr = nfnl_ct_get_dst(ct, repl);
	//if (addr)
	//	NLA_PUT_ADDR(req,
	//		     family == AF_INET ? CTA_IP_V4_DST : CTA_IP_V6_DST,
	//		     addr);

	nla_nest_end(req, ip);

	proto = nla_nest_start(req, CTA_TUPLE_PROTO);
	if (!proto)
		goto err;

	//if (nfnl_ct_test_proto(ct))
	//	NLA_PUT_U8(req, CTA_PROTO_NUM, nfnl_ct_get_proto(ct));
	//
	//if (nfnl_ct_test_src_port(ct, repl))
	//	NLA_PUT_U16(req, CTA_PROTO_SRC_PORT,
	//		htons(nfnl_ct_get_src_port(ct, repl)));
	//
	//if (nfnl_ct_test_dst_port(ct, repl))
	//	NLA_PUT_U16(req, CTA_PROTO_DST_PORT,
	//		htons(nfnl_ct_get_dst_port(ct, repl)));
	//
	//if (nfnl_ct_test_icmp_id(ct, repl))
	//	NLA_PUT_U16(req, CTA_PROTO_ICMP_ID,
	//		htons(nfnl_ct_get_icmp_id(ct, repl)));
	//
	//if (nfnl_ct_test_icmp_type(ct, repl))
	//	NLA_PUT_U8(req, CTA_PROTO_ICMP_TYPE,
	//		    nfnl_ct_get_icmp_type(ct, repl));
	//
	//if (nfnl_ct_test_icmp_code(ct, repl))
	//	NLA_PUT_U8(req, CTA_PROTO_ICMP_CODE,
	//		    nfnl_ct_get_icmp_code(ct, repl));

	nla_nest_end(req, proto);

	nla_nest_end(req, tuple);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, handle_dump, &allow_insert);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, handle_finish, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, handle_ack, &err);
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, handle_seq, NULL);
	nl_cb_err(cb, NL_CB_CUSTOM, handle_error, &err);

	if (nl_send_auto_complete(nl, req) < 0)
		goto err;

	debug_printf("DUMP start\n");
	nfnetlink_dump_in_progress = 1;
	for (err = 1; err > 0; ) {
		ret = nl_recvmsgs(nl, cb);

		if (ret < 0) {
			error_printf("Error Netlink receive failure: %s\n", nl_geterror(ret));
			err = (-ret == NLE_NOMEM) ? -ENOBUFS : -EIO;
			break;
		}
	}

	errno = -err;

err:
	if (cb)
		nl_cb_put(cb);

	if (req)
		nlmsg_free(req);

	nfnetlink_dump_in_progress = 0;
	debug_printf("DUMP end\n");
	return -errno;
}
