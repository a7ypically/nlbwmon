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
#include <stdlib.h>
#include <ctype.h>

#include "tg.h"
#include "config.h"

#include "mmap_cache.h"
#include "utils.h"
#include "wans.h"
#include "protocol.h"
#include "nfnetlink.h"
#include "geoip.h"
#include "notify.h"

static unsigned char NotifyCountry['Z'-'A' + 1]['Z'-'A' + 1];
static uint32_t NotifySigUploadKB;
static uint32_t NotifySigUploadRatio;
static uint32_t DnsNoWan;
static int NotifyNoDNS = 0;
static struct uloop_timeout notify_no_dns_tm = { };

struct notify_rule_entry {
	struct notify_params params;
	uint8_t action;
	struct avl_node node;
};

#define NOTIFY_MMAP_CACHE_SIZE 500
DEFINE_MMAP_CACHE(notify_rule);

struct notify_delayed_record {
	struct uloop_timeout timeout;
	uint32_t rec_idx;
	uint32_t rec_md5[4];
	uint32_t active_entry_id;
	struct active_table *active_entry;
};

static uint32_t n_notify_delayed;

static void
notify_delayed_cb(struct uloop_timeout *t)
{
	struct notify_delayed_record *dr;

	dr = container_of(t, struct notify_delayed_record, timeout);
	struct record *r = database_get_by_idx(dr->rec_idx, dr->rec_md5);

	if (r) {
		if (!(r->flags & RECORD_FLAG_NOTIF_INBOUND) && !notify_is_muted(r, RECORD_FLAG_NOTIF_INBOUND, NULL)) {
			//assert(be64toh(r->count) == 1);
			if (nfnetlink_is_active(dr->active_entry_id)) {
				tg_notify_incoming(r, RECORD_FLAG_NOTIF_INBOUND);
				r->flags |= RECORD_FLAG_NOTIF_INBOUND;
			}
		}
	}

	free(dr);

	if (n_notify_delayed > 0)
		n_notify_delayed--;
}

static int
notify_new_delay(struct record *r, uint32_t active_entry_id)
{
	struct notify_delayed_record *dr;

	/* to avoid gobbling up too much memory, tie the maximum allowed number
	 * of pending insertions to the configured database limit */
	if (n_notify_delayed >= 50) {
		error_printf("Error - Too many pending notify delay\n");
		return -ENOSPC;
	}

	dr = calloc(1, sizeof(*dr));

	if (!dr)
		return -ENOMEM;

	dr->rec_idx = database_get_idx(r, dr->rec_md5);
	dr->timeout.cb = notify_delayed_cb;
	dr->active_entry_id = active_entry_id;

	n_notify_delayed++;

	return uloop_timeout_set(&dr->timeout, 15000) ? -EEXIST : 0;
}

static void
notify_start_no_dns(struct uloop_timeout *tm)
{
	debug_printf("notify_start_no_dns - Timer expired. Starting no DNS notifications.\n");
	NotifyNoDNS = 1;
}

static int notify_mmap_persist(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(notify_rule, NOTIFY_MMAP_CACHE_SIZE, path, 0);
	return 0;
}

struct notify_params **notify_get_all(size_t *count) {
    *count = notify_rule_avl.count;
    struct notify_params **rules = calloc(*count, sizeof(struct notify_params *));
    
    if (!rules) {
        *count = 0;
        return NULL;
    }

    struct notify_rule_entry *ptr;
    size_t i = 0;

    avl_for_each_element(&notify_rule_avl, ptr, node) {
        rules[i++] = &ptr->params;
    }

    return rules;
}

static int
avl_cmp_notify_rules(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, offsetof(struct notify_rule_entry, node));
}

static char *format_notify_rule(const void *ptr)
{
	struct notify_rule_entry *rule = (struct notify_rule_entry *)ptr;
	struct notify_params *r = &rule->params;
	const char *src_name;
	char country[3];
	static char str[256];

	if (r->type & RECORD_TYPE_WAN) {
		src_name = get_wan_name(r->src.wan_idx);
	} else {
		src_name = format_macaddr(&r->src.ea);
	}

	if (!r->country[0]) {
		country[0] = '0';
		country[1] = '0' + country[1];
	} else {
		country[0] = r->country[0];
		country[1] = r->country[1];
	}
	country[2] = 0;

	snprintf(str, sizeof(str), "Notify rule - flag:%d src:%s proto:%d dst_port:%d country:%s asn:%d topl_domain:%d action:%d\n", r->notify_flag, src_name, r->proto, r->dst_port, country, r->asn, r->topl_domain, rule->action);

	return str;
}

int init_notify(const char *db_path) {
	nlbwmon_add_presistence_cb(notify_mmap_persist);
	MMAP_CACHE_INIT(notify_rule, NOTIFY_MMAP_CACHE_SIZE, avl_cmp_notify_rules, params, format_notify_rule);
	if (!notify_rule_db) return -errno;

	if (notify_rule_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(notify_rule, NOTIFY_MMAP_CACHE_SIZE, params, db_path, 0, format_notify_rule);
	}

	const char *list = config_get("notify_country_list");
	if (list) {
		while (*list) {
			while (*list && ((toupper(*list) < 'A') || (toupper(*list) > 'Z'))) ++list;
			if (!*list) break;
			if ((toupper(*(list+1)) < 'A') || (toupper(*(list+1)) > 'Z')) {
				error_printf("Error - unable to parse country list config:%s\n", config_get("notify_country_list"));
				break;
			}

			int idx1 = toupper(*list) - 'A';
			++list;
			int idx2 = toupper(*list) - 'A';
			++list;

			NotifyCountry[idx1][idx2] = 1;
		}
	}

	NotifySigUploadKB = config_get_uint32("notify_outbound_kb", 1024*10);
	NotifySigUploadRatio = config_get_uint32("notify_outbound_ratio", 50);
	DnsNoWan = config_get_uint32("no_dns_for_wan", 1);

	if (config_get_uint32("notify_no_dns", 0)) {
		notify_no_dns_tm.cb = notify_start_no_dns;
		uloop_timeout_set(&notify_no_dns_tm, 24 * 3600 * 1000);
	}
	return 0;
}

static inline int notify_is_match(struct record *r, uint8_t notif_record_flag, struct notify_params *params) {
	if (!(notif_record_flag & params->notify_flag)) return 0;
	if ((r->type & RECORD_TYPE_WAN_IN) !=
			(params->type & RECORD_TYPE_WAN_IN)) return 0;

	if (params->proto &&
			((params->proto != r->proto) ||
			 (params->dst_port && (params->dst_port != r->dst_port)))) return 0;

	if (params->type & RECORD_TYPE_WAN) {
		if (!(r->type & RECORD_TYPE_WAN) ||
			 (params->src.wan_idx != r->src_addr.wan_idx)) return 0;
	} else if (params->src.u64 && (params->src.u64 != r->src_mac.u64)) return 0;

	if (params->country[0] && memcmp(params->country, r->country, sizeof(r->country))) return 0;

	if (params->asn && (params->asn != r->asn)) return 0;

	if (params->topl_domain && (params->topl_domain != r->topl_domain)) return 0;

	return 1;
}


int notify_is_muted(struct record *r, uint8_t notif_record_flag, struct notify_params *params) {
	struct notify_rule_entry *rule;

	if (params) return notify_is_match(r, notif_record_flag, params);

	for (int i=0; i<notify_rule_mmap_db_len; ++i) {
		rule = notify_rule_db + i;
		if (!rule->node.key) continue;

		if (!notify_is_match(r, notif_record_flag, &rule->params)) continue;

		debug_printf("notify_is_muted - skipping notification:\n%s\n", format_notify_rule(rule));
#ifdef DEBUG_LOG
		print_record(r);
#endif

		// Mark as notify so we don't keep running is_muted on this record
		r->flags |= notif_record_flag;
		return 1;
	}

	return 0;
}

static inline int notify_is_country(char *country) {

	int idx1 = country[0] - 'A';
	int idx2 = country[1] - 'A';

	if (idx1 < 0) return 0;

	return NotifyCountry[idx1][idx2];
}

void notify_new(struct record *r, int duration, uint32_t active_entry_id) {
	if (r->type & RECORD_TYPE_WAN_IN) {
		if (r->proto == 1) return;
		if (r->flags & RECORD_FLAG_NOTIF_INBOUND) return;

		if (!notify_is_muted(r, RECORD_FLAG_NOTIF_INBOUND, NULL)) {
			if (be64toh(r->count) == 1) {
				if (duration == -1) {
					if (notify_new_delay(r, active_entry_id) == 0) return;
				} else if (duration < 15000) {
					return;
				}
			}
			tg_notify_incoming(r, RECORD_FLAG_NOTIF_INBOUND);
			r->flags |= RECORD_FLAG_NOTIF_INBOUND;
		}
	} else {
		if (!(r->flags & RECORD_FLAG_NOTIF_COUNTRY) && notify_is_country(r->country)) {
			if (!notify_is_muted(r, RECORD_FLAG_NOTIF_COUNTRY, NULL)) {
				tg_notify_outgoing(r, RECORD_FLAG_NOTIF_COUNTRY);
				r->flags |= RECORD_FLAG_NOTIF_COUNTRY;
			}
		}
		if (NotifyNoDNS && !r->topl_domain && !(r->flags & RECORD_FLAG_NOTIF_NO_DNS)) {
			if (!(r->type & RECORD_TYPE_WAN) || !DnsNoWan) {
				if ((r->proto != 1) && ((r->proto != 17) || (r->dst_port != DNS_UDP_NET_PORT)) && !geoip_is_bogon(r->country)) {
					if (!notify_is_muted(r, RECORD_FLAG_NOTIF_NO_DNS, NULL)) {
						tg_notify_no_dns(r, RECORD_FLAG_NOTIF_NO_DNS);
						r->flags |= RECORD_FLAG_NOTIF_NO_DNS;
					}
				}
			}
		}
	}
}

void notify_update(struct record *r) {
	if (!(r->flags & RECORD_FLAG_NOTIF_UPLOAD)) {
		uint64_t out = be64toh(r->out_bytes);
		if (out > NotifySigUploadKB*1024) {
			uint64_t in = be64toh(r->in_bytes);
			if (out * (100/NotifySigUploadRatio) > in) {
				if (!notify_is_muted(r, RECORD_FLAG_NOTIF_UPLOAD, NULL)) {
					tg_notify_upload(r, RECORD_FLAG_NOTIF_UPLOAD);
					r->flags |= RECORD_FLAG_NOTIF_UPLOAD;
				}
			}
		}
	}
}

void notify_new_client(struct ether_addr *mac) {
	tg_notify_new_client(mac);
}

int notify_mute_add(struct notify_params *params) {
	struct notify_rule_entry *ptr, key = {};
	key.params = *params;
	key.action = NOTIFY_ACTION_MUTE;

	ptr = avl_find_element(&notify_rule_avl, &key, ptr, node);

	if (ptr) return -EEXIST;

	MMAP_CACHE_GET_NEXT(ptr, notify_rule, NOTIFY_MMAP_CACHE_SIZE, NULL);
	ptr->params = key.params;
	ptr->action = key.action;
	ptr->node.key = &ptr->params;
	MMAP_CACHE_INSERT(ptr, notify_rule);
	MMAP_CACHE_SAVE(notify_rule, NOTIFY_MMAP_CACHE_SIZE, NULL, 0);

	return 0;
}
