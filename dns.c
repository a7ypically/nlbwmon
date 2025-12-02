/*
  ISC License

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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <endian.h>
#include <sys/types.h>

#include "utils.h"
#include "database.h"
#include "mmap_cache.h"
#include "dns.h"
#include "database.h"
#include "notify.h"  /* for forward declaration only */
#include "tg.h"

/* ------------------------------------------------------------
 *  TLD management helpers (swap / promote / compact)
 * ------------------------------------------------------------*/

/* Forward declarations of static helpers */
static void dns_swap_topl_entries(uint16_t a, uint16_t b);
static void dns_swap_all_references(uint16_t a, uint16_t b);

// DNS resolve cache by IP and client IP
#define DNS_IP_CACHE_SIZE 10000
DEFINE_MMAP_CACHE(dns_ip_cache, 0);

#define DNS_RECORD_CACHE_SIZE 50000
DEFINE_MMAP_CACHE(dns_record, 0);

#define DNS_TOPL_RECORD_CACHE_SIZE 10000
DEFINE_MMAP_CACHE(dns_topl_record, 1);

static uint32_t DnsRecordNextID = 1;

static char *format_dns_ip_key(const void *ptr) {
	union dns_ip_cache_key *key = (union dns_ip_cache_key *)ptr;

	return format_ipaddr(key->data.family, &key->data.addr, 1);
}

static char *format_hostname_key(const void *ptr) {
	char *hostname = (char *)ptr;

	return hostname;
}

/* Global struct for purge candidates */
struct cand { uint16_t idx; double score; };

/* qsort comparator for candidate scores (ascending) */
static int cand_cmp(const void *a, const void *b) {
	const struct cand *ca = a;
	const struct cand *cb = b;
	return (ca->score > cb->score) - (ca->score < cb->score);
}

/*
 * Promote the TLD at index `idx` into the rule-protected area.
 * Returns idx on success, 0 on error
 */
uint16_t dns_promote_topl_index(uint16_t idx)
{
	if (idx == 0 || idx >= dns_topl_record_mmap_db_len)
		return 0;

	uint32_t last_idx = DNS_TOPL_LAST_RULES_IDX();
	if (idx <= last_idx)
		return idx; /* already protected */

	if (last_idx + 1 >= DNS_TOPL_RECORD_CACHE_SIZE)
		return 0;

	uint16_t target = last_idx + 1;

	dns_swap_topl_entries(idx, target);
	dns_swap_all_references(idx, target);

	DNS_TOPL_SET_LAST_RULES_IDX(target);
	return target;
}

/*
 * Promote a TLD by hostname into the rule-protected area.
 * Creates the entry if it doesn't exist.
 * Returns the promoted index on success, 0 on error.
 */
uint16_t dns_promote_topl_hostname(const char *hostname)
{
	if (!hostname || !hostname[0])
		return 0;

	struct dns_topl_record_entry *record_topl_entry, *tmp;
	record_topl_entry = avl_find_element(&dns_topl_record_avl, hostname, tmp, node);
	
	if (!record_topl_entry) {
		/* Create new TLD entry */
		if (dns_topl_record_mmap_db_len == DNS_TOPL_RECORD_CACHE_SIZE) {
			dns_compact_topl_db();
		}
		if (dns_topl_record_mmap_db_len == DNS_TOPL_RECORD_CACHE_SIZE) {
			error_printf("dns_promote_topl_hostname: topl cache full even after compaction\n");
			return 0;
		}

		MMAP_CACHE_GET_NEXT(record_topl_entry, dns_topl_record, DNS_TOPL_RECORD_CACHE_SIZE, NULL);
		strncpy(record_topl_entry->hostname, hostname, MAX_TOPL_DNS_LEN);
		record_topl_entry->hostname[MAX_TOPL_DNS_LEN] = '\0';
		record_topl_entry->node.key = &record_topl_entry->hostname;
		MMAP_CACHE_INSERT(record_topl_entry, dns_topl_record);
	}

	uint16_t idx = MMAP_GET_IDX(dns_topl_record, record_topl_entry);
	return dns_promote_topl_index(idx);
}

void dns_compact_topl_db(void)
{
	/* High-level O(N) compaction based on the USER-requested algorithm. */
	uint32_t total_slots = dns_topl_record_mmap_db_len;
	if (total_slots <= 1) return; /* nothing but meta slot */

	uint32_t protected_end = DNS_TOPL_LAST_RULES_IDX();
	uint32_t target_free = total_slots / 10; /* aim to free 10 % */
	bool topl_changed = false;
	if (target_free == 0) return;

	/* Allocate working buffers */
	uint8_t *used  = calloc(total_slots, 1);
	uint8_t *purge = calloc(total_slots, 1);
	uint32_t *hist_cnt   = calloc(total_slots, sizeof(uint32_t));
	uint64_t *hist_byt   = calloc(total_slots, sizeof(uint64_t));
	uint32_t *recent_cnt = calloc(total_slots, sizeof(uint32_t));
	if (!used || !purge || !hist_cnt || !hist_byt || !recent_cnt) {
		free(used);
		free(purge);
		free(hist_cnt);
		free(hist_byt);
		free(recent_cnt);
		return; /* allocation failure – skip compaction */
	}

	/* ---------------- Phase A – mark protected + live DNS cache ------------- */
	for (uint32_t i = 1; i <= protected_end && i < total_slots; ++i)
		used[i] = 1;

	struct timespec now; clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
	for (int i = 0; i < dns_ip_cache_mmap_db_len; ++i) {
		struct dns_ip_cache_entry *ip = dns_ip_cache_db + i;
		if (!ip->node.key) continue;
		if (ip->ttl_expiry < now.tv_sec) {
			/* TTL expired */
			continue;
		}
		if (ip->dns_rec_mmap_idx >= dns_record_mmap_db_len) continue;
		uint16_t idx = dns_record_db[ip->dns_rec_mmap_idx].dns_topl_mmap_idx;
		if (idx < total_slots) used[idx] = 1;
	}

	/* ---------------- Phase B – gather historical DB stats ------------------ */
	if (gdbh && gdbh->db) {
		struct record *rec = gdbh->db->records;
		uint32_t n = be32toh(gdbh->db->entries);
		for (uint32_t i = 0; i < n; ++i, ++rec) {
			uint16_t idx = rec->topl_domain;
			if (idx >= total_slots) continue;
			hist_cnt[idx] += (uint32_t)be64toh(rec->count);
			hist_byt[idx] += be64toh(rec->in_bytes) + be64toh(rec->out_bytes);
		}
	}

	/* ---------------- Phase C – gather recent in-memory stats --------------- */
	for (int i = 0; i < dns_record_mmap_db_len; ++i) {
		struct dns_record_entry *r = dns_record_db + i;
		if (!r->node.key || r->count == 0) continue;
		uint16_t idx = r->dns_topl_mmap_idx;
		if (idx < total_slots)
			recent_cnt[idx] += r->count;
	}

	/* ---------------- Phase D – build candidate list ----------------------- */
	struct cand *candidates = calloc(total_slots, sizeof(*candidates));
	uint32_t cand_to_score = 0;
	uint32_t quick_purged  = 0;

	for (uint16_t i = protected_end + 1; i < total_slots; ++i) {
		if (used[i])
			continue; /* cannot purge */

		if (hist_cnt[i] == 0 && recent_cnt[i] == 0) { /* quick win: totally unused */
			purge[i] = 1;
			++quick_purged;
		} else {
			candidates[cand_to_score].idx   = i;
			candidates[cand_to_score].score = (double)hist_cnt[i] + (double)recent_cnt[i] + (double)hist_byt[i] / 1024.0;
			++cand_to_score;
		}
	}

	/* Sort remaining candidates by score ascending and mark for purge */
	if (cand_to_score) {
		qsort(candidates, cand_to_score, sizeof(*candidates), cand_cmp);

		/* Adjust target_free by the number already freed via quick wins */
		if (target_free > quick_purged)
			target_free -= quick_purged;
		else
			target_free = 0;

		for (uint32_t k = 0; k < cand_to_score && target_free; ++k) {
			uint16_t idx = candidates[k].idx;
			if (!purge[idx]) {
				purge[idx] = 1;
				--target_free;
			}
		}
	}
	free(candidates);

	/* ---------------- Phase E – build remap table and pack ------------------ */
	uint16_t *remap = calloc(total_slots, sizeof(uint16_t));
	if (!remap) {
		free(used);
		free(purge);
		free(hist_cnt);
		free(hist_byt);
		free(recent_cnt);
		return;
	}

	/* Preserve meta (0) and the protected range [1..protected_end] */
	for (uint16_t i = 0; i <= protected_end && i < total_slots; ++i) {
	    remap[i] = i;
	}

	uint16_t write_pos = protected_end + 1;
	for (uint16_t i = protected_end + 1; i < total_slots; ++i) {
		if (purge[i]) {
			remap[i] = 0; /* cleared */
			continue;
		}
		remap[i] = write_pos;
		if (write_pos != i) {
			/* move entry into packed area via swap – AVL keys updated inside */
			dns_swap_topl_entries(i, write_pos);
		}
		++write_pos;
	}

	uint32_t new_len = write_pos;

	/* Tell other subsystems (Telegram cache, ...) about the new indices */
	tg_dns_topl_remap(remap, total_slots);

	/* ---------------- Phase F – update references with single scans -------- */
	for (int i = 0; i < dns_record_mmap_db_len; ++i) {
		struct dns_record_entry *r = dns_record_db + i;
		if (!r->node.key) continue;
		uint16_t old = r->dns_topl_mmap_idx;
		if (!old || (old >= total_slots)) continue;
		uint16_t newidx = remap[old];
		if (newidx != old)
			r->dns_topl_mmap_idx = newidx;
	}

	if (gdbh && gdbh->db) {
		struct record *rec = gdbh->db->records;
		uint32_t n = be32toh(gdbh->db->entries);
		for (uint32_t i = 0; i < n; ++i, ++rec) {
			uint16_t old = rec->topl_domain;
			if (old >= total_slots) continue;
			uint16_t newidx = remap[old];
			if (newidx != old) {
				rec->topl_domain = newidx;
				topl_changed = true;
			}
		}
	}

	if (topl_changed && gdbh && gdbh->db) {
		database_reindex(gdbh);
	}

	/* Remove purged tail slots */
	for (uint32_t idx = new_len; idx < total_slots; ++idx) {
		if (dns_topl_record_db[idx].node.key)
			avl_delete(&dns_topl_record_avl, &dns_topl_record_db[idx].node);
		memset(&dns_topl_record_db[idx], 0, sizeof(dns_topl_record_db[idx]));
	}

	/* Update lengths */
	dns_topl_record_mmap_db_len   = new_len;
	*dns_topl_record_mmap_next_entry = new_len;

	free(remap);

	free(used);
		free(purge);
		free(hist_cnt);
		free(hist_byt);
		free(recent_cnt);
}

/* ------------------------------------------------------------
 * Internal helper implementations
 * ------------------------------------------------------------*/

/*
 * Ensure that a dns_record_entry has a valid dns_topl_mmap_idx.
 * If it is zero and the hostname is not empty, the function will locate
 * (or create) the corresponding TLD entry and update dns_topl_mmap_idx.
 * Returns 0 on success, negative errno-style code on error.
 */
static int ensure_topl_index_for_record(struct dns_record_entry *record_entry)
{
	if (!record_entry) return -EINVAL;
	if (record_entry->dns_topl_mmap_idx) return 0; /* already set */
	if (!record_entry->hostname[0]) return -EINVAL;

	char *hostname = record_entry->hostname;
	int len = strlen(hostname);

	char *topl_domain = strrchr(hostname, '.');
	if (!topl_domain)
		return -EINVAL;

	/* Walk backwards to ensure we don't chop sub-second level like co.uk */
	while (topl_domain > hostname) {
		topl_domain--;
		if ((hostname + len - topl_domain > 7) && (*topl_domain == '.')) {
			topl_domain++;
			break;
		}
	}

	struct dns_topl_record_entry *record_topl_entry, *tmp;
	record_topl_entry = avl_find_element(&dns_topl_record_avl, topl_domain, tmp, node);
	if (!record_topl_entry) {
		/* Make room if full */
		if (dns_topl_record_mmap_db_len == DNS_TOPL_RECORD_CACHE_SIZE) {
			dns_compact_topl_db();
		}
		if (dns_topl_record_mmap_db_len == DNS_TOPL_RECORD_CACHE_SIZE) {
			error_printf("ensure_topl_index_for_record: topl cache full even after compaction\n");
			record_entry->dns_topl_mmap_idx = 0;
		} else {

			MMAP_CACHE_GET_NEXT(record_topl_entry, dns_topl_record, DNS_TOPL_RECORD_CACHE_SIZE, NULL);
			strcpy(record_topl_entry->hostname, topl_domain);
			record_topl_entry->node.key = &record_topl_entry->hostname;
			MMAP_CACHE_INSERT(record_topl_entry, dns_topl_record);
			record_entry->dns_topl_mmap_idx = MMAP_GET_IDX(dns_topl_record, record_topl_entry);
		}
	} else {
		record_entry->dns_topl_mmap_idx = MMAP_GET_IDX(dns_topl_record, record_topl_entry);
	}
	return 0;
}

static void dns_swap_topl_entries(uint16_t a, uint16_t b)
{
	if (a == b) return;

	struct dns_topl_record_entry tmp = dns_topl_record_db[a];
	/* Fix AVL keys: remove then insert */
	if (dns_topl_record_db[a].node.key) {
		avl_delete(&dns_topl_record_avl, &dns_topl_record_db[a].node);
	}
	if (dns_topl_record_db[b].node.key) {
		avl_delete(&dns_topl_record_avl, &dns_topl_record_db[b].node);
	}

	dns_topl_record_db[a] = dns_topl_record_db[b];
	dns_topl_record_db[b] = tmp;

	dns_topl_record_db[a].node.key = DNS_TOPL_HOSTNAME(&dns_topl_record_db[a]);
	if (avl_insert(&dns_topl_record_avl, &dns_topl_record_db[a].node)) {
		error_printf("dns_swap_topl_entries: key collision on a\n");
		assert(0);
	}
	dns_topl_record_db[b].node.key = DNS_TOPL_HOSTNAME(&dns_topl_record_db[b]);
	if (avl_insert(&dns_topl_record_avl, &dns_topl_record_db[b].node)) {
		error_printf("dns_swap_topl_entries: key collision on b\n");
		assert(0);
	}
}

static void dns_swap_all_references(uint16_t a, uint16_t b)
{
	/* Swap in dns_record_db */
	for (int i = 0; i < dns_record_mmap_db_len; ++i) {
		struct dns_record_entry *r = dns_record_db + i;
		if (!r->node.key) continue;
		if (r->dns_topl_mmap_idx == a)
			r->dns_topl_mmap_idx = b;
		else if (r->dns_topl_mmap_idx == b)
			r->dns_topl_mmap_idx = a;
	}

	/* Swap in persistent DB records */
	if (!gdbh || !gdbh->db) return;
	struct record *rec = gdbh->db->records;
	uint32_t n = be32toh(gdbh->db->entries);
	bool had_swap = false;

	/* First pass: update records and remove them from the index */
	for (uint32_t i = 0; i < n; ++i, ++rec) {
		if (rec->topl_domain == a) {
			database_index_remove(rec);
			rec->topl_domain = b;
			had_swap = true;
		} else if (rec->topl_domain == b) {
			database_index_remove(rec);
			rec->topl_domain = a;
			had_swap = true;
		}
	}

	if (!had_swap)
		return;

	/* Second pass: add back all records referencing either topl_domain */
	rec = gdbh->db->records;
	for (uint32_t i = 0; i < n; ++i, ++rec) {
		if (rec->topl_domain == a || rec->topl_domain == b) {
			database_index_add(rec);
		}
	}
}


int dns_update(const char *name, uint32_t ttl, const char *addr, const char *c_addr)
{
	struct dns_record_entry *record_entry, *tmp;
	struct timespec tp;
	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &tp)) {
		error_printf("Can't get time - %s\n", strerror(errno));
	}

	debug_printf("%ld.%ld dns_update - %s %s client:%s\n", tp.tv_sec, tp.tv_nsec, name, addr, c_addr);

	int len = strlen(name);
	char c_name[MAX_DNS_LEN+1];

	if (len > MAX_DNS_LEN) {
		c_name[0] = '.';
		c_name[1] = '.';
		strcpy(c_name+2, name + len - MAX_DNS_LEN + 2);
		len = MAX_DNS_LEN;
	} else {
		strcpy(c_name, name);
	}

	record_entry = avl_find_element(&dns_record_avl, c_name, tmp, node);

	if (record_entry) {
		debug_printf("host name found in dns record cache.\n");
	} else {
		MMAP_CACHE_GET_NEXT(record_entry, dns_record, DNS_RECORD_CACHE_SIZE, NULL);
		strcpy(record_entry->hostname, c_name);
		record_entry->id = DnsRecordNextID++;
		if (ensure_topl_index_for_record(record_entry) != 0) {
			error_printf("dns_update - failed to assign TLD index for %s\n", c_name);
			return -1;
		}

		record_entry->node.key = &record_entry->hostname;
		MMAP_CACHE_INSERT(record_entry, dns_record);
	}

	struct dns_ip_cache_entry *ip_entry, *tmp2;
	union dns_ip_cache_key key = { };

	//FIXME IPv4 client can get ipv6 resolution (and probably vice versa)
	if (inet_pton(AF_INET6, addr, &key.data.addr.in6)) {
		key.data.family = AF_INET6;
		if (!c_addr) {
			memset(&key.data.client_addr.in6, 0, sizeof(key.data.client_addr.in6));
		} else if (!inet_pton(AF_INET6, c_addr, &key.data.client_addr.in6)) {
			error_printf("Wrong IP format: %s\n", c_addr);
			return -1;
		}
	}
	else if (inet_pton(AF_INET, addr, &key.data.addr.in)) {
		key.data.family = AF_INET;
		key.data.addr.in.s_addr = be32toh(key.data.addr.in.s_addr);
		if (!c_addr) {
			memset(&key.data.client_addr.in, 0, sizeof(key.data.client_addr.in));
		} else if (!inet_pton(AF_INET, c_addr, &key.data.client_addr.in)) {
			error_printf("Wrong IP format: %s\n", c_addr);
			return -1;
		}
		key.data.client_addr.in.s_addr = be32toh(key.data.client_addr.in.s_addr);
	} else {
		error_printf("Wrong IP format: %s\n", addr);
		return -1;
	}

	ip_entry = avl_find_element(&dns_ip_cache_avl, &key, tmp2, node);

	if (ip_entry) {
		ip_entry->ttl_expiry = tp.tv_sec + ttl;
		if (ip_entry->dns_rec_id == record_entry->id) {
			debug_printf("DNS IP cache - exists.\n");
			return 0;
		}

		debug_printf("DNS IP cache - different name for this IP. Old:%d\n", ip_entry->dns_rec_id);
		ip_entry->dns_rec_id = record_entry->id;
		ip_entry->dns_rec_mmap_idx = MMAP_GET_IDX(dns_record, record_entry);
	} else {

#if 0
		if (dns_ip_cache_mmap_db_len == DNS_IP_CACHE_SIZE) {
			uint32_t prev;
			if (dns_ip_cache_mmap_next_entry == 0) prev = DNS_IP_CACHE_SIZE - 1;
			else prev = dns_ip_cache_mmap_next_entry - 1;

			struct dns_ip_cache_entry *prev_entry = dns_ip_cache_db + prev;

			debug_printf("dns cache - removing %s\n", format_ipaddr(prev_entry->key.data.family, &prev_entry->key.data.addr, 1));
		}
#endif
		if (dns_ip_cache_mmap_db_len == DNS_IP_CACHE_SIZE) {
			int i;
			for (i=0; i<dns_ip_cache_mmap_db_len; ++i) {
				ip_entry = dns_ip_cache_db + *dns_ip_cache_mmap_next_entry;
				if (ip_entry->ttl_expiry < tp.tv_sec) break;
				*dns_ip_cache_mmap_next_entry = (*dns_ip_cache_mmap_next_entry + 1) % DNS_IP_CACHE_SIZE;
			}

			if (i == dns_ip_cache_mmap_db_len) {
				error_printf("Error dns_update - dns ip cache not big enough. Removing entry with live ttl.\n");
			}
		}

		MMAP_CACHE_GET_NEXT(ip_entry, dns_ip_cache, DNS_IP_CACHE_SIZE, format_dns_ip_key);

		ip_entry->ttl_expiry = tp.tv_sec + ttl;
		ip_entry->dns_rec_id = record_entry->id;
		ip_entry->dns_rec_mmap_idx = MMAP_GET_IDX(dns_record, record_entry);
		ip_entry->key = key;
		ip_entry->node.key = &ip_entry->key;
		MMAP_CACHE_INSERT(ip_entry, dns_ip_cache);
	}

	return 0;
}

static struct dns_record_entry *get_dns_record_by_addr(uint8_t family, void *addr, void *c_addr)
{
	struct dns_ip_cache_entry *ptr, *tmp;
	union dns_ip_cache_key key = { };

	if (family == AF_INET6) {
		key.data.family = AF_INET6;
		key.data.addr.in6 = *(struct in6_addr *)addr;
		key.data.client_addr.in6 = *(struct in6_addr *)c_addr;
	} else {
		key.data.family = AF_INET;
		key.data.addr.in = *(struct in_addr *)addr;
		key.data.client_addr.in = *(struct in_addr *)c_addr;
	}

	ptr = avl_find_element(&dns_ip_cache_avl, &key, tmp, node);

	if (!ptr) {
		debug_printf("DNS record lookup for ip:%s\n", format_ipaddr(key.data.family, addr, 1));
		debug_printf("can not find with client:%s\n", format_ipaddr(key.data.family, c_addr, 1));
		memset(&key.data.client_addr, 0, sizeof(key.data.client_addr));
		ptr = avl_find_element(&dns_ip_cache_avl, &key, tmp, node);
		if (!ptr) {
			debug_printf("can not find with NULL client\n");
			return NULL;
		}
	}

	if (ptr->dns_rec_mmap_idx >= dns_record_mmap_db_len) {
		debug_printf("dns_get_host_for_addr - dns_rec_mmap_idx(%d) >= DB(%d)\n", ptr->dns_rec_mmap_idx, dns_record_mmap_db_len);
		return NULL;
	}

	struct dns_record_entry *rec = dns_record_db + ptr->dns_rec_mmap_idx;
	if (rec->id != ptr->dns_rec_id) {
		debug_printf("dns_get_host_for_addr - ID mismatch %d != %d\n", rec->id, ptr->dns_rec_id);
		return NULL;
	}

	return rec;
}

const char *dns_get_host_for_addr(uint8_t family, void *addr, void *c_addr)
{
	struct dns_record_entry *rec = get_dns_record_by_addr(family, addr, c_addr);

	if (!rec) return NULL;

	return rec->hostname;
}

const char *dns_get_topl(uint16_t topl_mmap_idx)
{
	assert(topl_mmap_idx);
	//assert(topl_mmap_idx < dns_topl_record_mmap_db_len);
	if (topl_mmap_idx >= dns_topl_record_mmap_db_len) {
		error_printf("dns_get_topl - bad topl_mmap_idx: %d\n", topl_mmap_idx);
		return NULL;
	}

	struct dns_topl_record_entry *rec = dns_topl_record_db + topl_mmap_idx;
	return rec->hostname;
}

uint16_t dns_inc_count_for_addr(uint8_t family, void *addr, void *c_addr, uint16_t *topl_domain)
{
	struct dns_record_entry *rec = get_dns_record_by_addr(family, addr, c_addr);

	if (!rec) return 0;

	/* Ensure TLD index is valid before counting */
	if (rec->dns_topl_mmap_idx == 0 && rec->hostname[0]) {
		int res = ensure_topl_index_for_record(rec);
		assert(res == 0);
		assert(rec->id != 0);
	}

	++rec->count;
	debug_printf("dns_inc_count_for_addr - %s (%d) id:%d\n", rec->hostname, rec->count, rec->id);

	*topl_domain = rec->dns_topl_mmap_idx;
	return rec->id;
}

const char *dns_get_by_id(uint32_t id) {
	for (int i=0; i<dns_record_mmap_db_len; ++i) {
		struct dns_record_entry *r = dns_record_db + i;
		if (!r->node.key) continue;
		if (r->id == id) {
			return r->hostname;
		}
	}

	return NULL;
}

static int
avl_cmp_dns_ip_cache(const void *k1, const void *k2, void *ptr)
{
	const union dns_ip_cache_key *a = k1;
	const union dns_ip_cache_key *b = k2;

	return memcmp(a->u32, b->u32, sizeof(a->u32));
#if 0
	for (int i = 0; i < sizeof(a->u32) / sizeof(a->u32[0]); i++)
		if (a->u32[i] != b->u32[i])
			return (a->u32[i] - b->u32[i]);

	return 0;
#endif
}

static int
avl_cmp_dns_record(const void *k1, const void *k2, void *ptr)
{
	return strcmp(k1, k2);
}

static int dns_mmap_persist(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(dns_record, DNS_RECORD_CACHE_SIZE, path, timestamp);
	//MMAP_CACHE_SAVE(dns_ip_cache, DNS_IP_CACHE_SIZE, path, timestamp);
	MMAP_CACHE_SAVE(dns_topl_record, DNS_TOPL_RECORD_CACHE_SIZE, path, timestamp);
	return 0;
}

/* Helper struct for the temporary old_id -> new_id map */
struct id_remap_node {
	uint32_t old_id;
	uint32_t new_id;
	struct avl_node node;
};

/* Helper struct for the temporary id -> index map */
struct id_map_node {
	uint32_t id;
	uint32_t idx;
	struct avl_node node;
};

/* Comparison function for AVL trees keyed by uint32_t IDs */
static int avl_cmp_u32_id(const void *k1, const void *k2, void *ptr)
{
	const uint32_t id1 = *(const uint32_t *)k1;
	const uint32_t id2 = *(const uint32_t *)k2;
	return (id1 > id2) - (id1 < id2);
}

static int dns_archive(const char *path, uint32_t timestamp)
{
	int ret = 0;
	bool topl_changed = false;
	/* Save current state before pruning and archiving */
	MMAP_CACHE_SAVE(dns_record, DNS_RECORD_CACHE_SIZE, path, timestamp);
	//MMAP_CACHE_SAVE(dns_ip_cache, DNS_IP_CACHE_SIZE, path, timestamp);
	MMAP_CACHE_SAVE(dns_topl_record, DNS_TOPL_RECORD_CACHE_SIZE, path, timestamp);

	/* --- Resource Allocation --- */
	uint8_t *ip_used = NULL;
	uint8_t *record_used = NULL;
	uint8_t *topl_used = NULL;
	uint16_t *record_remap = NULL;
	uint16_t *topl_remap = NULL;
	struct id_map_node **id_to_idx_nodes = NULL;
	uint32_t id_to_idx_node_count = 0;
	struct id_remap_node **id_remap_nodes = NULL;
	uint32_t id_remap_node_count = 0;

	/* Allocate all helper memory upfront to simplify cleanup on failure */
	if (dns_ip_cache_mmap_db_len > 0)
		ip_used = calloc(dns_ip_cache_mmap_db_len, 1);
	if (dns_record_mmap_db_len > 0) {
		record_used = calloc(dns_record_mmap_db_len, 1);
		record_remap = calloc(dns_record_mmap_db_len, sizeof(uint16_t));
		id_to_idx_nodes = calloc(dns_record_mmap_db_len, sizeof(struct id_map_node *));
	}
	if (dns_topl_record_mmap_db_len > 0) {
		topl_used = calloc(dns_topl_record_mmap_db_len, 1);
		topl_remap = calloc(dns_topl_record_mmap_db_len, sizeof(uint16_t));
	}
	/* Check for allocation failures */
	if ((dns_ip_cache_mmap_db_len > 0 && !ip_used) ||
	    (dns_record_mmap_db_len > 0 && (!record_used || !record_remap || !id_to_idx_nodes)) ||
	    (dns_topl_record_mmap_db_len > 0 && (!topl_used || !topl_remap))) {
		error_printf("dns_archive: failed to allocate memory for usage maps\n");
		ret = -ENOMEM;
		goto cleanup;
	}

	/* --- Phase 1: Mark all entries that must be kept --- */
	struct avl_tree id_to_idx_avl;
	avl_init(&id_to_idx_avl, avl_cmp_u32_id, false, NULL);

	if (id_to_idx_nodes) {
		for (uint32_t i = 0; i < dns_record_mmap_db_len; ++i) {
			if (dns_record_db[i].node.key) {
				struct id_map_node *node = malloc(sizeof(*node));
				if (!node) { ret = -ENOMEM; goto cleanup; }
				node->id = dns_record_db[i].id;
				node->idx = i;
				node->node.key = &node->id;
				if (avl_insert(&id_to_idx_avl, &node->node)) {
					error_printf("dns_archive: key collision on id_to_idx_avl\n");
					assert(0);
				}
				id_to_idx_nodes[id_to_idx_node_count++] = node;
			}
		}
	}

	if (topl_used) {
		topl_used[DNS_TOPL_META_SLOT] = 1;
		uint32_t protected_end = DNS_TOPL_LAST_RULES_IDX();
		for (uint32_t i = 1; i <= protected_end && i < dns_topl_record_mmap_db_len; ++i)
			topl_used[i] = 1;
	}

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
	for (uint32_t i = 0; i < dns_ip_cache_mmap_db_len; ++i) {
		struct dns_ip_cache_entry *ip = &dns_ip_cache_db[i];
		if (!ip->node.key || ip->ttl_expiry < now.tv_sec) continue;
		if (ip->dns_rec_mmap_idx >= dns_record_mmap_db_len) continue;
		struct dns_record_entry *rec = &dns_record_db[ip->dns_rec_mmap_idx];
		if (!rec->node.key || rec->id != ip->dns_rec_id) continue;

		ip_used[i] = 1;
		record_used[ip->dns_rec_mmap_idx] = 1;
		if (rec->dns_topl_mmap_idx < dns_topl_record_mmap_db_len)
			topl_used[rec->dns_topl_mmap_idx] = 1;
	}

	if (gdbh && gdbh->db) {
		struct record *db_rec = gdbh->db->records;
		for (uint32_t i = 0, n = be32toh(gdbh->db->entries); i < n; ++i, ++db_rec) {
			if (db_rec->topl_domain < dns_topl_record_mmap_db_len)
				topl_used[db_rec->topl_domain] = 1;

			for (int j = 0; j < RECORD_NUM_HOSTS; ++j) {
				if (!db_rec->hosts[j]) break;
				struct id_map_node *tmp_node;
				tmp_node = avl_find_element(&id_to_idx_avl, &db_rec->hosts[j], tmp_node, node);
				if (tmp_node) {
					record_used[tmp_node->idx] = 1;
					uint16_t topl_idx = dns_record_db[tmp_node->idx].dns_topl_mmap_idx;
					if (topl_idx < dns_topl_record_mmap_db_len)
						topl_used[topl_idx] = 1;
				}
			}
		}
	}
	/* Done with the id->idx map, free it now */
	if (id_to_idx_nodes) {
		for (uint32_t i = 0; i < id_to_idx_node_count; i++) free(id_to_idx_nodes[i]);
		free(id_to_idx_nodes);
		id_to_idx_nodes = NULL; id_to_idx_node_count = 0;
	}

	/* --- Phase 2: Compact databases and create index remap tables --- */
	uint32_t new_topl_len = 0;
	if (topl_used) {
		for (uint32_t i = 0; i < dns_topl_record_mmap_db_len; i++) {
			if (topl_used[i]) {
				topl_remap[i] = new_topl_len;
				if (new_topl_len != i) {
					dns_topl_record_db[new_topl_len] = dns_topl_record_db[i];
					dns_topl_record_db[new_topl_len].node.key = NULL;
				}
				new_topl_len++;
			}
		}
	}

	/* Let other modules fix their cached topl_domain indices (old index -> new index) */
	if (topl_remap) {
		/* Use the old length here – topl_remap[] has dns_topl_record_mmap_db_len entries */
		tg_dns_topl_remap(topl_remap, dns_topl_record_mmap_db_len);
	}

	uint32_t new_record_len = 0;
	if (record_used) {
		for (uint32_t i = 0; i < dns_record_mmap_db_len; i++) {
			if (record_used[i]) {
				record_remap[i] = new_record_len;
				if (new_record_len != i) {
					dns_record_db[new_record_len] = dns_record_db[i];
					dns_record_db[new_record_len].node.key = NULL;
				}
				new_record_len++;
			}
		}
	}

	/* --- Phase 3: Renumber DNS record IDs and create ID remap table --- */
	struct avl_tree id_remap_avl;
	avl_init(&id_remap_avl, avl_cmp_u32_id, false, NULL);

	if (new_record_len > 0) {
		id_remap_nodes = calloc(new_record_len, sizeof(struct id_remap_node *));
		if (!id_remap_nodes) { ret = -ENOMEM; goto cleanup; }

		DnsRecordNextID = 1;
		for (uint32_t i = 0; i < new_record_len; i++) {
			struct id_remap_node *node = malloc(sizeof(*node));
			if (!node) { ret = -ENOMEM; goto cleanup; }

			node->old_id = dns_record_db[i].id;
			node->new_id = DnsRecordNextID++;
			node->node.key = &node->old_id;
			if (avl_insert(&id_remap_avl, &node->node)) {
				error_printf("dns_archive: key collision on id_remap_avl\n");
				assert(0);
			}
			id_remap_nodes[id_remap_node_count++] = node;

			dns_record_db[i].id = node->new_id;
			dns_record_db[i].count = 0;
		}
	}

	/* --- Phase 4: Update all references with new indices and IDs --- */
	if (gdbh && gdbh->db) {
		struct record *db_rec = gdbh->db->records;
		for (uint32_t i = 0, n = be32toh(gdbh->db->entries); i < n; ++i, ++db_rec) {
			if (topl_remap && (db_rec->topl_domain != topl_remap[db_rec->topl_domain])) {
				db_rec->topl_domain = topl_remap[db_rec->topl_domain];
				topl_changed = true;
			}
		
			uint32_t new_hosts[RECORD_NUM_HOSTS] = {0};
			int new_host_idx = 0;
			for (int j = 0; j < RECORD_NUM_HOSTS; ++j) {
				if (!db_rec->hosts[j]) break;
				struct id_remap_node *tmp_node;
				tmp_node = avl_find_element(&id_remap_avl, &db_rec->hosts[j], tmp_node, node);
				if (tmp_node)
					new_hosts[new_host_idx++] = tmp_node->new_id;
			}
			memcpy(db_rec->hosts, new_hosts, sizeof(db_rec->hosts));
		}
	}

	if (topl_changed && gdbh && gdbh->db) {
		database_reindex(gdbh);
	}

	for (uint32_t i = 0; i < new_record_len; i++)
		if (topl_remap)
			dns_record_db[i].dns_topl_mmap_idx = topl_remap[dns_record_db[i].dns_topl_mmap_idx];

	uint32_t new_ip_len = 0;
	if (ip_used) {
		for (uint32_t i = 0; i < dns_ip_cache_mmap_db_len; i++) {
			if (!ip_used[i]) continue;

			struct dns_ip_cache_entry *ip_old = &dns_ip_cache_db[i];
			struct id_remap_node *tmp_node;
			tmp_node = avl_find_element(&id_remap_avl, &ip_old->dns_rec_id, tmp_node, node);

			if (!tmp_node) {
				error_printf("dns_archive: inconsistency, IP entry for %s references purged DNS record ID %u. Discarding.\n",
					format_dns_ip_key(&ip_old->key), ip_old->dns_rec_id);
				continue;
			}
			
			if (new_ip_len != i) {
				dns_ip_cache_db[new_ip_len] = *ip_old;
				dns_ip_cache_db[new_ip_len].node.key = NULL;
			}
			struct dns_ip_cache_entry *ip_new = &dns_ip_cache_db[new_ip_len];
			if (record_remap) ip_new->dns_rec_mmap_idx = record_remap[ip_new->dns_rec_mmap_idx];
			ip_new->dns_rec_id = tmp_node->new_id;
			new_ip_len++;
		}
	}

	/* --- Phase 5: Update lengths and rebuild AVL trees --- */
	MMAP_ZERO_DB_TAIL(dns_topl_record_db,
             new_topl_len,
             DNS_TOPL_RECORD_CACHE_SIZE);
	dns_topl_record_mmap_db_len = new_topl_len;
	*dns_topl_record_mmap_next_entry = new_topl_len;

	MMAP_ZERO_DB_TAIL(dns_record_db,
             new_record_len,
             DNS_RECORD_CACHE_SIZE);
	dns_record_mmap_db_len = new_record_len;
	*dns_record_mmap_next_entry = new_record_len;

	MMAP_ZERO_DB_TAIL(dns_ip_cache_db,
             new_ip_len,
             DNS_IP_CACHE_SIZE);
	dns_ip_cache_mmap_db_len = new_ip_len;
	*dns_ip_cache_mmap_next_entry = new_ip_len;

	avl_init(&dns_topl_record_avl, avl_cmp_dns_record, false, NULL);
	for (uint32_t i = 1; i < new_topl_len; i++) {
		struct dns_topl_record_entry *r = &dns_topl_record_db[i];
		r->node.key = &r->hostname;
		if (avl_insert(&dns_topl_record_avl, &r->node) != 0) {
			error_printf("dns_archive: key collision on TLD rebuild for '%s'\n", r->hostname);
			assert(0);
		}
	}
	avl_init(&dns_record_avl, avl_cmp_dns_record, false, NULL);
	for (uint32_t i = 0; i < new_record_len; i++) {
		struct dns_record_entry *r = &dns_record_db[i];
		r->node.key = &r->hostname;
		if (avl_insert(&dns_record_avl, &r->node) != 0) {
			error_printf("dns_archive: key collision on DNS record rebuild for '%s'\n", r->hostname);
			assert(0);
		}
	}
	avl_init(&dns_ip_cache_avl, avl_cmp_dns_ip_cache, false, NULL);
	for (uint32_t i = 0; i < new_ip_len; i++) {
		struct dns_ip_cache_entry *ip = &dns_ip_cache_db[i];
		ip->node.key = &ip->key;
		if (avl_insert(&dns_ip_cache_avl, &ip->node) != 0) {
			error_printf("dns_archive: key collision on IP cache rebuild for '%s'\n", format_dns_ip_key(&ip->key));
			assert(0);
		}
	}

cleanup:
	if (id_to_idx_nodes) {
		for (uint32_t i = 0; i < id_to_idx_node_count; i++) free(id_to_idx_nodes[i]);
		free(id_to_idx_nodes);
	}
	if (id_remap_nodes) {
		for (uint32_t i = 0; i < id_remap_node_count; i++) free(id_remap_nodes[i]);
		free(id_remap_nodes);
	}
	free(ip_used);
	free(record_used);
	free(topl_used);
	free(record_remap);
	free(topl_remap);
	return ret;
}

int init_dns(const char *db_path, uint32_t timestamp)
{
	nlbwmon_add_presistence_cb(dns_mmap_persist);
	database_add_archive_cb(dns_archive);
	MMAP_CACHE_INIT(dns_ip_cache, DNS_IP_CACHE_SIZE, avl_cmp_dns_ip_cache, key, format_dns_ip_key);
	if (!dns_ip_cache_db) return -errno;

	MMAP_CACHE_INIT(dns_record, DNS_RECORD_CACHE_SIZE, avl_cmp_dns_record, hostname, format_hostname_key);
	if (!dns_record_db) return -errno;

	if (dns_record_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(dns_record, DNS_RECORD_CACHE_SIZE, hostname, db_path, timestamp, format_hostname_key);
	}

	MMAP_CACHE_INIT(dns_topl_record, DNS_TOPL_RECORD_CACHE_SIZE, avl_cmp_dns_record, hostname, format_hostname_key);
	if (!dns_topl_record_db) return -errno;

	if (dns_topl_record_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(dns_topl_record, DNS_TOPL_RECORD_CACHE_SIZE, hostname, db_path, timestamp, format_hostname_key);
	}

	for (int i=0; i<dns_record_mmap_db_len; ++i) {
		struct dns_record_entry *r = dns_record_db + i;
		if (!r->node.key) continue;
		if (r->id >= DnsRecordNextID) DnsRecordNextID = r->id+1;
	}

	if (dns_topl_record_mmap_db_len == 0) {
		/*
		 * Create meta slot 0.  Do NOT insert into the AVL tree –
		 * it is accessed directly by index.
		 */
		struct dns_topl_record_entry *meta = dns_topl_record_db; /* first slot */
		meta->id = 0;
		meta->last_rules_index = 0; /* no protected TLDs yet */
		meta->node.key = NULL; /* never in AVL */
		/* Ensure mmap length counts the meta slot */
		dns_topl_record_mmap_db_len = 1;
		*dns_topl_record_mmap_next_entry = 1;
	} else {
		/* If db loaded from disk, ensure meta slot is not in AVL */
		if (dns_topl_record_db[DNS_TOPL_META_SLOT].node.key) {
			dns_topl_record_db[DNS_TOPL_META_SLOT].node.key = NULL;
		}
	}

	return 0;
}
