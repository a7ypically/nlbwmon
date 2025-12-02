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
#include "dns.h"
#include "notify.h"

static unsigned char NotifyCountry['Z'-'A' + 1]['Z'-'A' + 1];
uint32_t NotifySigUploadKB;
uint32_t NotifySigUploadMB[4];           /* Index 0 unused, 1-3 for hard-coded MB thresholds */
uint32_t NotifySigIncomingCounts[4];     /* Index 0 unused, 1-3 for connection thresholds */
uint32_t NotifySigOutgoingCounts[4];     /* Index 0 unused, 1-3 for connection thresholds */
static uint64_t NotifySigUploadThreshold;
static uint64_t NotifySigUploadThresholds[4];  /* Index 0 unused, 1-3 for thresholds */
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
DEFINE_MMAP_CACHE(notify_rule, 0);

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
	/* Compare only up to topl_domain field, excluding hostname backup field */
	return memcmp(k1, k2, offsetof(struct notify_params, hostname));
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
		country[1] = '0' + r->country[1];
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

	/* Recovery: rebuild TLD indices from backup hostnames and ensure protection */
	for (int i = 0; i < notify_rule_mmap_db_len; ++i) {
		struct notify_rule_entry *rule = notify_rule_db + i;
		if (!rule->node.key) continue;
		
		if (rule->params.topl_domain) {
			uint16_t old_idx = rule->params.topl_domain;
			uint16_t new_idx = 0;
			
			if (rule->params.hostname[0]) {
				/* Verify the current index points to the correct hostname */
				const char *current_hostname = dns_get_topl(rule->params.topl_domain);
				if (!current_hostname || strcmp(current_hostname, rule->params.hostname) != 0) {
					/* Index is invalid or points to wrong hostname, rebuild from backup */
					debug_printf("Rebuilding TLD index for rule with hostname '%s'\n", rule->params.hostname);
					new_idx = dns_promote_topl_hostname(rule->params.hostname);
					if (new_idx) {
						rule->params.topl_domain = new_idx;
						debug_printf("Rebuilt TLD index: %d -> %d\n", old_idx, new_idx);
					} else {
						error_printf("Failed to rebuild TLD index for hostname '%s'\n", rule->params.hostname);
						rule->params.topl_domain = 0;
					}
				} else {
					/* Hostname matches, but ensure it's in protected zone */
					new_idx = dns_promote_topl_index(rule->params.topl_domain);
					if (new_idx != old_idx) {
						rule->params.topl_domain = new_idx;
						debug_printf("Promoted TLD index to protected zone: %d -> %d\n", old_idx, new_idx);
					}
				}
			} else {
				/* No backup hostname, but ensure current index is in protected zone */
				new_idx = dns_promote_topl_index(rule->params.topl_domain);
				if (new_idx != old_idx) {
					rule->params.topl_domain = new_idx;
					debug_printf("Promoted TLD index to protected zone: %d -> %d\n", old_idx, new_idx);
				}
			}
		}
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
	NotifySigUploadMB[1] = config_get_uint32("notify_outbound_mb1", 20);
	NotifySigUploadMB[2] = config_get_uint32("notify_outbound_mb2", 50);
	NotifySigUploadMB[3] = config_get_uint32("notify_outbound_mb3", 100);
	NotifySigIncomingCounts[1] = config_get_uint32("notify_incoming_count1", 10);
	NotifySigIncomingCounts[2] = config_get_uint32("notify_incoming_count2", 50);
	NotifySigIncomingCounts[3] = config_get_uint32("notify_incoming_count3", 100);
	NotifySigOutgoingCounts[1] = config_get_uint32("notify_outgoing_count1", 10);
	NotifySigOutgoingCounts[2] = config_get_uint32("notify_outgoing_count2", 50);
	NotifySigOutgoingCounts[3] = config_get_uint32("notify_outgoing_count3", 100);
	NotifySigUploadRatio = config_get_uint32("notify_outbound_ratio", 50);
	
	/* Pre-calculate thresholds to avoid repeated calculations */
	NotifySigUploadThreshold = (uint64_t)NotifySigUploadKB * 1024;
	NotifySigUploadThresholds[1] = (uint64_t)NotifySigUploadMB[1] * 1024 * 1024;
	NotifySigUploadThresholds[2] = (uint64_t)NotifySigUploadMB[2] * 1024 * 1024;
	NotifySigUploadThresholds[3] = (uint64_t)NotifySigUploadMB[3] * 1024 * 1024;
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

		if (rule->action == NOTIFY_ACTION_MUTE) {
			// Mark as permanently muted
			r->flags |= notif_record_flag;
			return rule->action;
		} else if (rule->action >= NOTIFY_ACTION_MUTE_THRESHOLD1 && rule->action <= NOTIFY_ACTION_MUTE_THRESHOLD3) {
			// Return action for conditional muting - caller will set mute_threshold
			return rule->action;
		}
	}

	return 0;
}

static inline int notify_is_country(char *country) {

	int idx1 = country[0] - 'A';
	int idx2 = country[1] - 'A';

	if (idx1 < 0) return 0;

	return NotifyCountry[idx1][idx2];
}

/* Utility function to get current threshold for a notification type */
static uint8_t notify_get_threshold(struct record *rec, uint8_t notif_flag)
{
	switch (notif_flag) {
		case RECORD_FLAG_NOTIF_UPLOAD:   return rec->mute_thresholds.upload;
		case RECORD_FLAG_NOTIF_INBOUND:  return rec->mute_thresholds.incoming;
		case RECORD_FLAG_NOTIF_COUNTRY:  return rec->mute_thresholds.outgoing;
		case RECORD_FLAG_NOTIF_NO_DNS:   return rec->mute_thresholds.no_dns;
		default: return 0;
	}
}

/* Utility function to set threshold for a notification type */
static void notify_set_threshold(struct record *rec, uint8_t notif_flag, uint8_t threshold)
{
	switch (notif_flag) {
		case RECORD_FLAG_NOTIF_UPLOAD:   rec->mute_thresholds.upload = threshold; break;
		case RECORD_FLAG_NOTIF_INBOUND:  rec->mute_thresholds.incoming = threshold; break;
		case RECORD_FLAG_NOTIF_COUNTRY:  rec->mute_thresholds.outgoing = threshold; break;
		case RECORD_FLAG_NOTIF_NO_DNS:   rec->mute_thresholds.no_dns = threshold; break;
	}
}

/* Utility function to check if record has passed upload byte threshold */
static bool notify_check_upload_threshold(struct record *rec, uint8_t threshold_level)
{
	uint64_t out = be64toh(rec->out_bytes);
	if (out > NotifySigUploadThresholds[threshold_level]) {
		uint64_t in = be64toh(rec->in_bytes);
		if (out * 100 > in * NotifySigUploadRatio) {
			return true;
		}
	}
	return false;
}

/* Utility function to check if record has passed connection count threshold */
static bool notify_check_connection_threshold(struct record *rec, uint8_t notif_flag, uint8_t threshold_level)
{
	uint64_t count = be64toh(rec->count);
	uint32_t *count_thresholds = (notif_flag == RECORD_FLAG_NOTIF_INBOUND) ? 
		NotifySigIncomingCounts : NotifySigOutgoingCounts;
	return (count >= count_thresholds[threshold_level]);
}

static void notify_apply_flags_to_records(struct notify_params *params, uint8_t action)
{
	/* Only apply flags for threshold actions - NOTIFY_ACTION_MUTE is handled in notify_update/notify_new */
	if (action < NOTIFY_ACTION_MUTE_THRESHOLD1 || action > NOTIFY_ACTION_MUTE_THRESHOLD3)
		return;

	uint8_t threshold_level = action - NOTIFY_ACTION_MUTE_THRESHOLD1 + 1;
	uint8_t notif_flag = params->notify_flag;

	/* Only check records that have the notification flag set */
	struct record *rec = NULL;
	while ((rec = database_next(gdbh, rec)) != NULL) {
		/* Skip records that don't have the notification flag set */
		if (!(rec->flags & notif_flag))
			continue;

		/* Skip records that already have a higher or equal threshold set */
		uint8_t current_threshold = notify_get_threshold(rec, notif_flag);
		if (current_threshold >= threshold_level)
			continue;

		/* Check if record has already passed the threshold */
		bool skip_modification = false;
		if (notif_flag == RECORD_FLAG_NOTIF_UPLOAD) {
			skip_modification = notify_check_upload_threshold(rec, threshold_level);
		} else if (notif_flag == RECORD_FLAG_NOTIF_INBOUND || notif_flag == RECORD_FLAG_NOTIF_COUNTRY) {
			skip_modification = notify_check_connection_threshold(rec, notif_flag, threshold_level);
		}
		
		if (skip_modification)
			continue;

		if (notify_is_match(rec, notif_flag, params)) {
			/* Convert permanent mute to conditional mute for specific threshold */
			notify_set_threshold(rec, notif_flag, threshold_level);
		}
	}
}

void notify_new(struct record *r, int duration, uint32_t active_entry_id) {
	if (r->type & RECORD_TYPE_WAN_IN) {
		/* Handle incoming notifications - first connection only */
		if (r->proto == 1) return;

		if (!(r->flags & RECORD_FLAG_NOTIF_INBOUND)) {
			int action = notify_is_muted(r, RECORD_FLAG_NOTIF_INBOUND, NULL);
			if (!action) {
				/* Check if we should notify on first connection */
				if (be64toh(r->count) == 1) {
					if (duration == -1) {
						if (notify_new_delay(r, active_entry_id) == 0) return;
					} else if (duration < 15000) {
						return;
					}
				}
				
				tg_notify_incoming(r, RECORD_FLAG_NOTIF_INBOUND);
				r->flags |= RECORD_FLAG_NOTIF_INBOUND;
			} else if (action >= NOTIFY_ACTION_MUTE_THRESHOLD1 && action <= NOTIFY_ACTION_MUTE_THRESHOLD3) {
				/* Set incoming threshold for conditional muting */
				notify_set_threshold(r, RECORD_FLAG_NOTIF_INBOUND, action - NOTIFY_ACTION_MUTE_THRESHOLD1 + 1);
				r->flags |= RECORD_FLAG_NOTIF_INBOUND;
			}
			/* For NOTIFY_ACTION_MUTE, flag was already set in notify_is_muted */
		}
		/* Note: Connection threshold checking moved to notify_update() */
	} else {
		/* Handle outgoing notifications - first connection only */
		
		if (!(r->flags & RECORD_FLAG_NOTIF_COUNTRY) && notify_is_country(r->country)) {
			if (!(r->flags & RECORD_FLAG_NOTIF_COUNTRY)) {
				int action = notify_is_muted(r, RECORD_FLAG_NOTIF_COUNTRY, NULL);
				if (!action) {
					tg_notify_outgoing(r, RECORD_FLAG_NOTIF_COUNTRY);
					r->flags |= RECORD_FLAG_NOTIF_COUNTRY;
				} else if (action >= NOTIFY_ACTION_MUTE_THRESHOLD1 && action <= NOTIFY_ACTION_MUTE_THRESHOLD3) {
					/* Set outgoing threshold for conditional muting */
					notify_set_threshold(r, RECORD_FLAG_NOTIF_COUNTRY, action - NOTIFY_ACTION_MUTE_THRESHOLD1 + 1);
					r->flags |= RECORD_FLAG_NOTIF_COUNTRY;
				}
			}
			/* Note: Connection threshold checking moved to notify_update() */
		}

		/* Handle no DNS notifications (no threshold support for now) */
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
	/* Handle upload notifications */
	uint8_t upload_threshold = notify_get_threshold(r, RECORD_FLAG_NOTIF_UPLOAD);
	
	/* Early exit for permanently muted upload records - most common case */
	if ((r->flags & RECORD_FLAG_NOTIF_UPLOAD) && (upload_threshold == 0)) {
		/* Still need to check connection thresholds below */
	} else if (!(r->flags & RECORD_FLAG_NOTIF_UPLOAD)) {
		/* Normal threshold check - most common case for new records */
		uint64_t out = be64toh(r->out_bytes);
		
		if (out > NotifySigUploadThreshold) {
			uint64_t in = be64toh(r->in_bytes);
			if (out * (100/NotifySigUploadRatio) > in) {
				int action = notify_is_muted(r, RECORD_FLAG_NOTIF_UPLOAD, NULL);
				if (!action) {
					tg_notify_upload(r, RECORD_FLAG_NOTIF_UPLOAD);
					r->flags |= RECORD_FLAG_NOTIF_UPLOAD;
				} else if (action >= NOTIFY_ACTION_MUTE_THRESHOLD1 && action <= NOTIFY_ACTION_MUTE_THRESHOLD3) {
					/* Set upload threshold for conditional muting */
					notify_set_threshold(r, RECORD_FLAG_NOTIF_UPLOAD, action - NOTIFY_ACTION_MUTE_THRESHOLD1 + 1);
					r->flags |= RECORD_FLAG_NOTIF_UPLOAD;
				}
				/* For NOTIFY_ACTION_MUTE, flag was already set in notify_is_muted */
			}
		}
	} else if (upload_threshold > 0) {
		/* Threshold check for records with conditional muting - least common case */
		if (notify_check_upload_threshold(r, upload_threshold)) {
			tg_notify_upload(r, RECORD_FLAG_NOTIF_UPLOAD);
			notify_set_threshold(r, RECORD_FLAG_NOTIF_UPLOAD, 0); /* Clear threshold after notification */
		}
	}

	/* Handle incoming connection thresholds */
	if (r->type & RECORD_TYPE_WAN_IN) {
		uint8_t incoming_threshold = notify_get_threshold(r, RECORD_FLAG_NOTIF_INBOUND);
		
		/* Early exit for permanently muted incoming records */
		if ((r->flags & RECORD_FLAG_NOTIF_INBOUND) && (incoming_threshold == 0)) {
			return;
		}

		if ((r->flags & RECORD_FLAG_NOTIF_INBOUND) && (incoming_threshold > 0)) {
			/* Threshold check for records with conditional muting */
			if (notify_check_connection_threshold(r, RECORD_FLAG_NOTIF_INBOUND, incoming_threshold)) {
				tg_notify_incoming(r, RECORD_FLAG_NOTIF_INBOUND);
				notify_set_threshold(r, RECORD_FLAG_NOTIF_INBOUND, 0); /* Clear threshold after notification */
			}
		}
	}

	/* Handle outgoing connection thresholds */
	if (!(r->type & RECORD_TYPE_WAN_IN)) {
		uint8_t outgoing_threshold = notify_get_threshold(r, RECORD_FLAG_NOTIF_COUNTRY);
		
		/* Early exit for permanently muted outgoing records */
		if ((r->flags & RECORD_FLAG_NOTIF_COUNTRY) && (outgoing_threshold == 0)) {
			return;
		}

		if ((r->flags & RECORD_FLAG_NOTIF_COUNTRY) && (outgoing_threshold > 0)) {
			/* Threshold check for records with conditional muting */
			if (notify_check_connection_threshold(r, RECORD_FLAG_NOTIF_COUNTRY, outgoing_threshold)) {
				tg_notify_outgoing(r, RECORD_FLAG_NOTIF_COUNTRY);
				notify_set_threshold(r, RECORD_FLAG_NOTIF_COUNTRY, 0); /* Clear threshold after notification */
			}
		}
	}
}

void notify_new_client(struct ether_addr *mac) {
	tg_notify_new_client(mac);
}

int notify_mute_add(struct notify_params *params, uint8_t action) {
	struct notify_rule_entry *ptr, key = {};
	key.params = *params;
	key.action = action;

	ptr = avl_find_element(&notify_rule_avl, &key, ptr, node);

	if (ptr) {
		if (ptr->action == action) {
			return -EEXIST;
		} else {
			ptr->action = action;
			/* Apply threshold flags to existing records that match this rule */
			notify_apply_flags_to_records(&key.params, key.action);
			return 0;
		}
	}

	/* Promote the TLD index into protected range if needed */
	if (key.params.topl_domain) {
		key.params.topl_domain = params->topl_domain = dns_promote_topl_index(key.params.topl_domain);
		
		/* Copy hostname for backup/recovery purposes */
		const char *hostname = dns_get_topl(key.params.topl_domain);
		if (hostname) {
			strncpy(key.params.hostname, hostname, MAX_TOPL_DNS_LEN);
			key.params.hostname[MAX_TOPL_DNS_LEN] = '\0';
		} else {
			key.params.hostname[0] = '\0';
		}
	} else {
		key.params.hostname[0] = '\0';
	}

	MMAP_CACHE_GET_NEXT(ptr, notify_rule, NOTIFY_MMAP_CACHE_SIZE, NULL);
	ptr->params = key.params;
	ptr->action = key.action;
	ptr->node.key = &ptr->params;
	MMAP_CACHE_INSERT(ptr, notify_rule);
	MMAP_CACHE_SAVE(notify_rule, NOTIFY_MMAP_CACHE_SIZE, NULL, 0);

	/* Apply threshold flags to existing records that match this rule */
	notify_apply_flags_to_records(&key.params, key.action);

	return 0;
}
