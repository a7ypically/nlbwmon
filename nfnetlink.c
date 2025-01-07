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
#include "config.h"
#include "tg.h"


static uint32_t n_pending_inserts = 0;
static struct nl_sock *nl_event_sock = NULL, *nl_dump_sock = NULL;
static struct uloop_fd ufd = { };
static int nfnetlink_dump_in_progress;
static uint32_t DumpCounter, DumpInsertCounter;
static struct avl_tree active_table_avl;
static struct timespec last_oom_ts;

static uint32_t DnsNoWan;

#define EVENT_TYPE_NEW 0x1
#define EVENT_TYPE_DELETED 0x2

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

static struct nla_policy ct_protoinfo_policy[CTA_PROTOINFO_MAX+1] = {
	[CTA_PROTOINFO_TCP]	= { .type = NLA_NESTED },
};

static struct nla_policy ct_protoinfo_tcp_policy[CTA_PROTOINFO_TCP_MAX+1] = {
	[CTA_PROTOINFO_TCP_STATE]		= { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL]	= { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_WSCALE_REPLY]	= { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]	= { .minlen = 2 },
	[CTA_PROTOINFO_TCP_FLAGS_REPLY]		= { .minlen = 2 },
};

static int ct_parse_protoinfo_tcp(struct nlattr *attr)
{
	struct nlattr *tb[CTA_PROTOINFO_TCP_MAX+1];
	int err;
	err = nla_parse_nested(tb, CTA_PROTOINFO_TCP_MAX, attr,
			       ct_protoinfo_tcp_policy);
	if (err < 0)
		return err;
	if (tb[CTA_PROTOINFO_TCP_STATE])
		return nla_get_u8(tb[CTA_PROTOINFO_TCP_STATE]);
	return 0;
}

static int get_tcp_state(struct nlattr *attr)
{
	struct nlattr *tb[CTA_PROTOINFO_MAX+1];
	int err;
	if (!attr) return -1;
	err = nla_parse_nested(tb, CTA_PROTOINFO_MAX, attr,
			       ct_protoinfo_policy);
	if (err < 0)
		return err;

	if (tb[CTA_PROTOINFO_TCP]) {
		err = ct_parse_protoinfo_tcp(tb[CTA_PROTOINFO_TCP]);
		return err;
	}
	return 0;
}


static int
avl_cmp_active_id(const void *k1, const void *k2, void *ptr)
{
	uint32_t *a = (uint32_t *)k1;
	uint32_t *b = (uint32_t *)k2;

	return memcmp(a, b, sizeof(*a));
}

struct active_table;
struct delayed_record {
	struct uloop_timeout timeout;
	struct record record;
	struct active_table *active_entry;
	uint32_t delay_retry;
};

#define ACTIVE_TABLE_FLAG_DELAYED 0x1
#define ACTIVE_TABLE_FLAG_DELETED 0x2
#define ACTIVE_TABLE_FLAG_INVALID 0x4
#define ACTIVE_TABLE_FLAG_NOTIFIED_NEW 0x8
#define ACTIVE_TABLE_FLAG_INACTIVE 0x10 /*duration is calculated*/
#define ACTIVE_TABLE_FLAG_NEW_IN_DUMP 0x20
#define ACTIVE_TABLE_FLAG_OUT_OF_TREE 0x40
#define ACTIVE_TABLE_FLAG_DB_PTR_VALID 0x80

static uint32_t ActiveTableCount;

//FIXME update idx after archive
struct active_table {
	uint32_t id;
	uint32_t dump_counter;
	union {
		struct {
			uint32_t idx;
			uint32_t md5[4];
		}db;
		struct delayed_record *delayed;
	} ptr;
	int flags;
	union {
		struct timespec tp;
		time_t duration;
	} time;
	struct avl_node node;
};

static void active_entry_delete(struct active_table *entry)
{
	debug_printf("in active_entry_delete\n");
	if (!(entry->flags & ACTIVE_TABLE_FLAG_INVALID) && (entry->flags & ACTIVE_TABLE_FLAG_DB_PTR_VALID)) {
		struct record *db_r = database_get_by_idx(entry->ptr.db.idx, entry->ptr.db.md5);

		if (entry->flags & ACTIVE_TABLE_FLAG_INACTIVE) {
			db_r->duration += entry->time.duration;
		} else {
			struct timespec now;
			if (clock_gettime(CLOCK_MONOTONIC_COARSE, &now)) {
				error_printf("Error - Can't get time - %s\n", strerror(errno));
			}
			db_r->duration += tp_diff(&entry->time.tp, &now);
		}
	}

	if (!(entry->flags & ACTIVE_TABLE_FLAG_OUT_OF_TREE)) {
		avl_delete(&active_table_avl, &entry->node);
	}
	free(entry);
	ActiveTableCount--;
	debug_printf("active_entry_delete - %d\n", ActiveTableCount);
}

static void update_dns(struct record *db_r, struct record *r)
{
	uint32_t dns_host_id = r->hosts[0];
	if (!dns_host_id) {
		return;
	}
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
database_insert_immediately(struct record *r, struct active_table *active_entry)
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
			if (!(active_entry->flags & ACTIVE_TABLE_FLAG_NOTIFIED_NEW)) {
				notify_new(db_r, (active_entry->flags & ACTIVE_TABLE_FLAG_INACTIVE) ? active_entry->time.duration : -1, active_entry->id);
				if (ret != 1) {
					update_dns(db_r, r);
				}
				active_entry->flags |= ACTIVE_TABLE_FLAG_NOTIFIED_NEW;
			}

			notify_update(db_r);
		}
	} else {
		if (database_update(gdbh, r, &db_r) == 0) {
			if (!(active_entry->flags & ACTIVE_TABLE_FLAG_NOTIFIED_NEW)) {
				notify_new(db_r, (active_entry->flags & ACTIVE_TABLE_FLAG_INACTIVE) ? active_entry->time.duration : -1, active_entry->id);
				update_dns(db_r, r);
				active_entry->flags |= ACTIVE_TABLE_FLAG_NOTIFIED_NEW;
			}
			notify_update(db_r);
		} else {
			//FIXME Why do we reach this case?
			// Dump dumping new records that have not yet been seen
			// Mac address updates creates a new record from an existing one
			// Other cases?
			//if (!nfnetlink_dump_in_progress) {
				error_printf("Error in database_update - %s:\n", format_ipaddr(r->family, &r->last_ext_addr, 1));
#ifdef DEBUG_LOG
				print_record(r);
#endif
			//}
			ret = database_insert(gdbh, r, &db_r);
			debug_printf("Adding to database: %d\n", ret);
			if (ret < 0) {
				tg_send_msg("Error in database_insert!");
			} else {
				assert(ret != 0);

				if (!(active_entry->flags & ACTIVE_TABLE_FLAG_NOTIFIED_NEW)) {
					notify_new(db_r, (active_entry->flags & ACTIVE_TABLE_FLAG_INACTIVE) ? active_entry->time.duration : -1, active_entry->id);
					active_entry->flags |= ACTIVE_TABLE_FLAG_NOTIFIED_NEW;
				}
				notify_update(db_r);
			}
		}
	}

	active_entry->flags &= ~ACTIVE_TABLE_FLAG_DELAYED;
	//Changes in resolutions can create a new idx or move current to a new one
	active_entry->ptr.db.idx = database_get_idx(db_r, active_entry->ptr.db.md5);
	active_entry->flags |= ACTIVE_TABLE_FLAG_DB_PTR_VALID;
	debug_printf("database_insert_immediately idx:%u\n", active_entry->ptr.db.idx);
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
			if (dr->delay_retry < 10) {
				debug_printf("%s is -EAGAIN. Delaying again (%d).\n", format_ipaddr(dr->record.family, &dr->record.last_ext_addr, 1), dr->delay_retry);
				if (uloop_timeout_set(&dr->timeout, 500) == -EEXIST) {
					error_printf("Error can not reset delayed record timer.\n");
				}

				return;
			} else {
				debug_printf("Error - %s geoip is -EAGAIN. Giving up after %d retries.\n", format_ipaddr(dr->record.family, &dr->record.last_ext_addr, 1), dr->delay_retry);
			}
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

	assert(!dr->record.topl_domain);
	if (!(dr->record.type & RECORD_TYPE_WAN_IN)) {
		if (!(dr->record.type & RECORD_TYPE_WAN) || !DnsNoWan) {
			if ((dr->record.proto != 1) && ((dr->record.proto != 17) || (dr->record.dst_port != DNS_UDP_NET_PORT))) {
				dr->record.hosts[0] = dns_inc_count_for_addr(dr->record.family, &dr->record.last_ext_addr, &dr->record.src_addr, &dr->record.topl_domain);
			}
		}
	}

	if (dr->delay_retry > 0) {
		debug_printf("database_insert_delayed_cb - success after %d retries -  geoip(%s) for ", dr->delay_retry, (dr->record.type & RECORD_TYPE_WAN) ? "wan": format_ipaddr(dr->record.family, &dr->record.src_addr, 1));
		debug_printf("%s\n", format_ipaddr(dr->record.family, &dr->record.last_ext_addr, 1));
	}

	database_insert_immediately(&dr->record, dr->active_entry);

	if (dr->active_entry->flags & ACTIVE_TABLE_FLAG_DELETED) {
		debug_printf("active_entry removed in database_insert_delayed_cb\n");
		active_entry_delete(dr->active_entry);
	}
	free(dr);

	if (n_pending_inserts > 0)
		n_pending_inserts--;
}

static int
database_insert_delayed(struct record *r, struct active_table *active_entry)
{
	struct delayed_record *dr;

	/* to avoid gobbling up too much memory, tie the maximum allowed number
	 * of pending insertions to the configured database limit */
	if (opt.db.limit > 0 && n_pending_inserts >= opt.db.limit) {
		error_printf("Error - Too many pending MAC address or geoip lookups\n");
		database_insert_immediately(r, active_entry);
		return -ENOSPC;
	}

	dr = calloc(1, sizeof(*dr));

	if (!dr)
		return -ENOMEM;

	dr->record = *r;
	dr->timeout.cb = database_insert_delayed_cb;
	dr->active_entry = active_entry;
	active_entry->flags |= ACTIVE_TABLE_FLAG_DELAYED;
	active_entry->ptr.delayed = dr;

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

#define add64(x, y) x = htobe64(be64toh(x) + be64toh(y))

static void
parse_event(void *reply, int len, int type, bool update_mac)
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

		if (type == EVENT_TYPE_NEW) {
			r.count = htobe64(1);
		}
		uint32_t id = nla_get_u32(attr[CTA_ID]);
		struct active_table *active_entry, *tmp;
		active_entry = avl_find_element(&active_table_avl, &id, tmp, node);

	 	int tcp_state = get_tcp_state(attr[CTA_PROTOINFO]);

		int diff_time = 0;
		if (active_entry) {
			struct timespec now;

			if (clock_gettime(CLOCK_MONOTONIC_COARSE, &now)) {
				error_printf("Can't get time - %s\n", strerror(errno));
			}
			diff_time = tp_diff(&active_entry->time.tp, &now);
			if (tcp_state > 3) {
				if (!(active_entry->flags & ACTIVE_TABLE_FLAG_INACTIVE)) {
					active_entry->time.duration = diff_time;
					active_entry->flags |= ACTIVE_TABLE_FLAG_INACTIVE;
				}
			}
		}

		debug_printf("parse_event - (%u) active_entry:%d idx:%u ms:%d dump:%d type:%d tcp_state:%d flags:%d src:%s ext:", id, active_entry != NULL, active_entry != NULL ? active_entry->ptr.db.idx : 0, diff_time, nfnetlink_dump_in_progress, type, tcp_state, active_entry ? active_entry->flags : -1, (r.type & RECORD_TYPE_WAN) ? "wan": format_ipaddr(r.family, &r.src_addr, 1));
		debug_printf("%s\n", format_ipaddr(r.family, &r.last_ext_addr, 1));
		debug_printf("cntrs: %lu %lu %lu %lu\n", be64toh(r.in_pkts), be64toh(r.in_bytes), be64toh(r.out_pkts), be64toh(r.out_bytes));

		if (active_entry) {
			if ((type == EVENT_TYPE_NEW) && (active_entry->flags & ACTIVE_TABLE_FLAG_DELETED)) {

				assert(active_entry->flags & ACTIVE_TABLE_FLAG_DELAYED);
				debug_printf("Error - entry was deleted but is delayed. Removing from tree.\n");
				active_entry->flags |= ACTIVE_TABLE_FLAG_OUT_OF_TREE;
				avl_delete(&active_table_avl, &active_entry->node);
				active_entry = NULL;
			} else {

				if (nfnetlink_dump_in_progress) active_entry->dump_counter = DumpCounter;

				if (type == EVENT_TYPE_NEW) {

					if (!(active_entry->flags & ACTIVE_TABLE_FLAG_NEW_IN_DUMP)) {
						error_printf("Error parse_event - new event but already seen\n");
					}
					r.count = 0;
				}

				if (active_entry->flags & ACTIVE_TABLE_FLAG_DELAYED) {
					debug_printf("parse_event - in active_entry but still delayed!\n");
					struct record *dr = &active_entry->ptr.delayed->record;
					add64(dr->in_pkts, r.in_pkts);
					add64(dr->in_bytes, r.in_bytes);
					add64(dr->out_pkts, r.out_pkts);
					add64(dr->out_bytes, r.out_bytes);
					if (type == EVENT_TYPE_DELETED) {
						if (active_entry->flags & ACTIVE_TABLE_FLAG_DELETED) {
							error_printf("Error - entry was already mark as deleted. OOM event?");
						} else {
							active_entry->flags |= ACTIVE_TABLE_FLAG_DELETED;
							if (!(active_entry->flags & ACTIVE_TABLE_FLAG_INACTIVE)) {
								struct timespec now;
								if (clock_gettime(CLOCK_MONOTONIC_COARSE, &now)) {
									error_printf("Error - Can't get time - %s\n", strerror(errno));
								}
								active_entry->time.duration = tp_diff(&active_entry->time.tp, &now);
								active_entry->flags |= ACTIVE_TABLE_FLAG_INACTIVE;
							}
						}
					}
					continue;
				}

				// if valid and not doing dump after archive
				if (!(active_entry->flags & ACTIVE_TABLE_FLAG_INVALID) && (active_entry->flags & ACTIVE_TABLE_FLAG_DB_PTR_VALID)) {
					struct record *db_r = database_get_by_idx(active_entry->ptr.db.idx, active_entry->ptr.db.md5);

					int create_new = 0;
					if (!(db_r->type & RECORD_TYPE_WAN) && !db_r->src_mac.u64) {
						err = lookup_macaddr(r.family, &r.src_addr.in6, &r.src_mac.ea);
						if (!err) create_new = 1;
					}

					if (!db_r->country[0]) {
						geo_err = geoip_lookup(&r);
						if (!geo_err) create_new = 1;
					}

					if (!(db_r->type & RECORD_TYPE_WAN_IN) && !db_r->topl_domain) {
						if ((r.proto != 1) && ((r.proto != 17) || (r.dst_port != DNS_UDP_NET_PORT))) {
							if (!(r.type & RECORD_TYPE_WAN) || !DnsNoWan) {
								r.hosts[0] = dns_inc_count_for_addr(r.family, &r.last_ext_addr, &r.src_addr, &r.topl_domain);
								if (r.hosts[0]) create_new = 1;
							}
						}
					}

					if (create_new) {
						r.count = htobe64(1);
						if (!(r.type & RECORD_TYPE_WAN) && !r.src_mac.u64) {
							r.src_mac.ea = db_r->src_mac.ea;
						}

						if (!r.country[0]) {
							memcpy(r.country, db_r->country, sizeof(r.country));
							memcpy(r.lonlat, db_r->lonlat, sizeof(r.lonlat));
							r.asn = db_r->asn;
						}

						if (!(r.type & RECORD_TYPE_WAN_IN) && !r.topl_domain) {
							r.topl_domain = db_r->topl_domain;
							r.hosts[0] = db_r->hosts[0];
						}

						database_insert_immediately(&r, active_entry);
					} else {
						database_update_record(&r, db_r);
						notify_update(db_r);
					}
				}

				if (type == EVENT_TYPE_DELETED) active_entry_delete(active_entry);
				continue;
			}
		}

		if (!active_entry) {
			active_entry = (struct active_table *) calloc(1, sizeof(*active_entry));
			active_entry->id = id;
			if (nfnetlink_dump_in_progress) active_entry->dump_counter = DumpCounter;
			active_entry->node.key = &active_entry->id;
			if (clock_gettime(CLOCK_MONOTONIC_COARSE, &active_entry->time.tp)) {
				error_printf("Can't get time - %s\n", strerror(errno));
			}
			avl_insert(&active_table_avl, &active_entry->node);
			ActiveTableCount++;
			if (type == EVENT_TYPE_DELETED) {
				active_entry->flags |= ACTIVE_TABLE_FLAG_DELETED;
				active_entry->flags |= ACTIVE_TABLE_FLAG_INACTIVE;
				active_entry->time.duration = 0;
			}
			if (nfnetlink_dump_in_progress) {
				active_entry->flags |= ACTIVE_TABLE_FLAG_NEW_IN_DUMP;
			}
			if (type != EVENT_TYPE_NEW) {
				r.count = htobe64(1);
				if (!nfnetlink_dump_in_progress && ((DumpCounter > 1) || (type != EVENT_TYPE_DELETED))) {
					error_printf("Error parse_event - not found in active_table!\n");
				}
			}
		}

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
			active_entry->flags |= ACTIVE_TABLE_FLAG_INVALID;
			if (type == EVENT_TYPE_DELETED) active_entry_delete(active_entry);
			continue;
		}

		if ((geo_err == -EAGAIN) || (update_mac && (err == -ENOENT))) {
			database_insert_delayed(&r, active_entry);
			continue;
		} else {
			if (!(r.type & RECORD_TYPE_WAN_IN)) {
				if (!(r.type & RECORD_TYPE_WAN) || !DnsNoWan) {
					if ((r.proto != 1) && ((r.proto != 17) || (r.dst_port != DNS_UDP_NET_PORT))) {
						r.hosts[0] = dns_inc_count_for_addr(r.family, &r.last_ext_addr, &r.src_addr, &r.topl_domain);
						if (!r.hosts[0]) {
							debug_printf("parse_event - have mac and geoip but not DNS.\n");
							database_insert_delayed(&r, active_entry);
							continue;
						}
					}
				}
			}
			if ((!r.type & RECORD_TYPE_WAN) && !r.src_mac.u64) {
				debug_printf("database_insert_immediately - no mac addr for %s\n", format_ipaddr(r.family, &r.src_addr, 1));
			}
			database_insert_immediately(&r, active_entry);
			if (type == EVENT_TYPE_DELETED) active_entry_delete(active_entry);
		}
	}
}

static void
handle_nl_sock_event(struct uloop_fd *fd, unsigned int ev)
{
	struct timespec start, end;
	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &start)) {
		error_printf("Can't get time - %s\n", strerror(errno));
	}

	debug_printf("handle_event start - %ld.%ld\n", start.tv_sec, start.tv_nsec/1000000);
	database_archive(gdbh);
	int len = nl_recvmsgs_default(nl_event_sock);
	if (len < 0) {
		error_printf("Error Netlink receive failure: %s\n", nl_geterror(len));
		// Check for Out of Memory error
		if (len == -NLE_NOMEM) {
			last_oom_ts = start;
			// Run a full dump to re-sync
			debug_printf("Error - OOM detected, running full dump to resync...\n");
			nfnetlink_dump(true);
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end)) {
		error_printf("Can't get time - %s\n", strerror(errno));
	}
	debug_printf("handle event (%d) end - %d ms\n", len, tp_diff(&start, &end));
}

static int
handle_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	int type = 0;
	if (NFNL_MSG_TYPE(hdr->nlmsg_type) == IPCTNL_MSG_CT_NEW) type = EVENT_TYPE_NEW;
	else if (NFNL_MSG_TYPE(hdr->nlmsg_type) == IPCTNL_MSG_CT_DELETE) type = EVENT_TYPE_DELETED;

	parse_event(hdr, hdr->nlmsg_len, type, type == EVENT_TYPE_NEW);
	//nlmsg_free(msg);

	return 0;
}

static int
handle_dump(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	bool *allow_insert = arg;
	int type = 0;
	if (NFNL_MSG_TYPE(hdr->nlmsg_type) == IPCTNL_MSG_CT_DELETE) type = EVENT_TYPE_DELETED;
	if (!type && *allow_insert) type = EVENT_TYPE_NEW;
	parse_event(hdr, hdr->nlmsg_len, type, true);
	return NL_OK;
}

static int
handle_error(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	error_printf("Error - handle_error\n");
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

#if 0
static int
handle_ack(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_OK;
}

static int
handle_seq(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}
#endif

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
	check_rmem_max(bufsize*2);

	DnsNoWan = config_get_uint32("no_dns_for_wan", 1);

	avl_init(&active_table_avl, avl_cmp_active_id, false, NULL);

	nl_event_sock = nl_socket_alloc();

	if (!nl_event_sock)
		return -ENOMEM;

	nl_socket_disable_seq_check(nl_event_sock);

	if (nl_socket_modify_cb(nl_event_sock, NL_CB_VALID, NL_CB_CUSTOM, handle_event, NULL))
		return -errno;

	if (nl_connect(nl_event_sock, NETLINK_NETFILTER))
		return -errno;

	if (nl_socket_set_nonblocking(nl_event_sock))
		return -errno;

	if (nl_socket_set_buffer_size(nl_event_sock, bufsize*2, 32*1024))
		return -errno;

	if (nl_socket_add_memberships(nl_event_sock, NFNLGRP_CONNTRACK_NEW,
					  //NFNLGRP_CONNTRACK_UPDATE,
	                                  NFNLGRP_CONNTRACK_DESTROY, 0))
		return -errno;

	ufd.cb = handle_nl_sock_event;
	ufd.fd = nl_socket_get_fd(nl_event_sock);

	if (uloop_fd_add(&ufd, ULOOP_READ))
		return -errno;


	nl_dump_sock = nl_socket_alloc();


	if (!nl_dump_sock)
		return -ENOMEM;

	if (nl_connect(nl_dump_sock, NETLINK_NETFILTER))
		return -errno;

	if (nl_socket_set_nonblocking(nl_dump_sock))
		return -errno;

	if (nl_socket_set_buffer_size(nl_dump_sock, bufsize, 32*1024))
		return -errno;

	return 0;
}

static struct active_table *
active_table_next(struct avl_tree *index, struct active_table *cur)
{
	struct active_table *last = avl_last_element(index, last, node);
	struct active_table *next = cur ? avl_next_element(cur, node)
	                          : avl_first_element(index, cur, node);

	if (next->node.list.prev != &last->node.list)
		return next;

	return NULL;
}

int
nfnetlink_is_active(uint32_t active_entry_id)
{
	struct active_table *active_entry, *tmp;
	active_entry = avl_find_element(&active_table_avl, &active_entry_id, tmp, node);
	if (active_entry && (!(active_entry->flags & ACTIVE_TABLE_FLAG_INACTIVE))) return 1;
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

	struct timespec start, end;
	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &start)) {
		error_printf("Can't get time - %s\n", strerror(errno));
	}

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
	//nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, handle_ack, &err);
	//nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, handle_seq, NULL);
	nl_cb_err(cb, NL_CB_CUSTOM, handle_error, &err);

	if (nl_send_auto_complete(nl_dump_sock, req) < 0)
		goto err;

	nfnetlink_dump_in_progress = 1;
	++DumpCounter;
	if (!DumpCounter) ++DumpCounter;
	if (allow_insert) DumpInsertCounter = DumpCounter;
	debug_printf("DUMP start - %ld.%ld counter:%d\n", start.tv_sec, start.tv_nsec/1000000, DumpCounter);
	int loops = 0;
	for (err = 1; err > 0; ) {
		++loops;
		ret = nl_recvmsgs(nl_dump_sock, cb);

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
	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &end)) {
		error_printf("Can't get time - %s\n", strerror(errno));
	}
	debug_printf("DUMP end - %d ms loops:%d\n", tp_diff(&start, &end), loops);

	int recently_oom = (last_oom_ts.tv_sec || last_oom_ts.tv_nsec) &&
                    (tp_diff(&last_oom_ts, &end) < 45000);

	uint32_t delayed_cnt = 0;
	uint32_t invalid_cnt = 0;
	struct active_table *rec = active_table_next(&active_table_avl, NULL);
	while (rec) {
		struct active_table *next = active_table_next(&active_table_avl, rec);

		if (rec->dump_counter != DumpCounter) {
			if (recently_oom || (DumpInsertCounter && (rec->dump_counter == DumpInsertCounter))) {
				// Handle as DELETE event

				if (recently_oom) {
					debug_printf("Zombie connection found (%u) post-OOM.\n", rec->id);
				} else {
					debug_printf("Zombie connection found (%u) post Dump insert.\n", rec->id);
				}

				// Mark delayed entries as deleted so they can be removed once the delayed callback fires
				// For invalid entries or any others, if not delayed, remove immediately
				if (rec->flags & ACTIVE_TABLE_FLAG_DELAYED) {
					if (!(rec->flags & ACTIVE_TABLE_FLAG_DELETED)) {
						rec->flags |= ACTIVE_TABLE_FLAG_DELETED;
						if (!(rec->flags & ACTIVE_TABLE_FLAG_INACTIVE)) {
							rec->time.duration = tp_diff(&rec->time.tp, &end);
							rec->flags |= ACTIVE_TABLE_FLAG_INACTIVE;
						}
					}
				} else {
					// Remove directly
					active_entry_delete(rec);
				}
			} else {

				if (rec->flags & ACTIVE_TABLE_FLAG_DELAYED) {
					++delayed_cnt;
				} else if (rec->flags & ACTIVE_TABLE_FLAG_INVALID) {
					++invalid_cnt;
				} else {
					if (rec->dump_counter && (rec->dump_counter < (DumpCounter - 1))) {
						error_printf("Error - leftover entry in active table:\n");
					}
					debug_printf("Dump zombie (%u) - counter:%d\n", rec->id, rec->dump_counter);
					if (rec->flags & ACTIVE_TABLE_FLAG_DB_PTR_VALID) {
						struct record *db_r = database_get_by_idx(rec->ptr.db.idx, rec->ptr.db.md5);
						print_record(db_r);
					}
					if (!rec->dump_counter) ++rec->dump_counter;
					if (allow_insert) {
						debug_printf("Removing leftover due to dump insert\n");
						active_entry_delete(rec);
					}
				}
			}
		}
		rec = next;
	}

	if (delayed_cnt) debug_printf("Zombie - delayed:%d\n", delayed_cnt);
	if (invalid_cnt) debug_printf("Zombie - invalid:%d\n", invalid_cnt);

	return -errno;
}

extern struct dbhandle *gdbh; // Ensure we have access to the global DB handle

void nfnetlink_invalidate_active_entries(void)
{
	struct active_table *entry = NULL;
	avl_for_each_element(&active_table_avl, entry, node) {
		entry->flags &= ~ACTIVE_TABLE_FLAG_DB_PTR_VALID;
	}
}

