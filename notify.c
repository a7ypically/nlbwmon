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
#include <ctype.h>

#include "tg.h"
#include "config.h"

#include "mmap_cache.h"
#include "utils.h"
#include "wans.h"
#include "notify.h"

static unsigned char NotifyCountry['Z'-'A' + 1]['Z'-'A' + 1];
static uint32_t NotifySigUploadKB;
static uint32_t NotifySigUploadRatio;

struct notify_rule_entry {
	struct notify_params params;
	uint8_t action;
	struct avl_node node;
};

#define NOTIFY_MMAP_CACHE_SIZE 500
DEFINE_MMAP_CACHE(notify_rule);

static int notify_mmap_persist(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(notify_rule, NOTIFY_MMAP_CACHE_SIZE, path, 0);
	return 0;
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

	snprintf(str, sizeof(str), "Notify rule - src:%s proto:%d dst_port:%d country:%s asn:%d action:%d\n", src_name, r->proto, r->dst_port, country, r->asn, rule->action);

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

	NotifySigUploadKB = config_get_uint32("notify_outbound_kb", 1024);
	NotifySigUploadRatio = config_get_uint32("notify_outbound_ratio", 10);

	return 0;
}

static inline int notify_is_match(struct record *r, struct notify_params *params) {
	if ((r->type & RECORD_TYPE_WAN_IN) !=
			(params->type & RECORD_TYPE_WAN_IN)) return 0;

	if (params->proto &&
			((params->proto != r->proto) ||
			 (params->dst_port != r->dst_port))) return 0;

	if ((params->type & RECORD_TYPE_WAN) &&
			(!(r->type & RECORD_TYPE_WAN) ||
			 (params->src.wan_idx != r->src_addr.wan_idx))) return 0;

	if (params->src.u64 && (params->src.u64 != r->src_mac.u64)) return 0;

	if (params->country[0] && memcmp(params->country, r->country, sizeof(r->country))) return 0;

	if (params->asn && (params->asn != r->asn)) return 0;

	return 1;
}


int notify_is_muted(struct record *r, struct notify_params *params) {
	struct notify_rule_entry *rule;

	if (params) return notify_is_match(r, params);

	for (int i=0; i<notify_rule_mmap_db_len; ++i) {
		rule = notify_rule_db + i;
		if (!rule->node.key) continue;

		if (!notify_is_match(r, &rule->params)) continue;

		debug_printf("notify_is_muted - skipping notification:\n%s\n", format_notify_rule(rule));
#ifdef DEBUG_LOG
		print_record(r);
#endif

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

void notify_new(struct record *r) {
	if (r->type & RECORD_TYPE_WAN_IN) {
		if (r->proto == 1) return;

		if (!notify_is_muted(r, NULL)) tg_notify_incoming(r);
	} else {
		if (!(r->flags & RECORD_FLAG_NOTIF_COUNTRY) && notify_is_country(r->country)) {
			if (!notify_is_muted(r, NULL)) tg_notify_outgoing(r);
			r->flags |= RECORD_FLAG_NOTIF_COUNTRY;
		}
	}
}

void notify_update(struct record *r) {
	if (!(r->flags & RECORD_FLAG_NOTIF_UPLOAD)) {
		uint64_t out = be64toh(r->out_bytes);
		if (out > NotifySigUploadKB*1024) {
			uint64_t in = be64toh(r->in_bytes);
			if (out * (100/NotifySigUploadRatio) > in) {
				if (!notify_is_muted(r, NULL)) tg_notify_upload(r);
				r->flags |= RECORD_FLAG_NOTIF_UPLOAD;
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
