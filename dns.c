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
#include <sys/types.h>
#include <libubox/avl.h>

#include "utils.h"
#include "database.h"
#include "mmap_cache.h"
#include "dns.h"

#define DNS_IP_CACHE_SIZE 1000
DEFINE_MMAP_CACHE(dns_ip_cache);

#define DNS_RECORD_CACHE_SIZE 50000
DEFINE_MMAP_CACHE(dns_record);

static uint32_t DnsRecordNextID = 1;

static char *format_dns_ip_key(const void *ptr) {
	union dns_ip_cache_key *key = (union dns_ip_cache_key *)ptr;

	return format_ipaddr(key->data.family, &key->data.addr, 1);
}

int dns_update(const char *name, const char *addr)
{
	struct dns_record_entry *record_entry, *tmp;

	debug_printf("dns_update - %s %s\n", name, addr);

	int len = strlen(name);
	char c_name[MAX_DNS_LEN];

	if (len > MAX_DNS_LEN) {
		c_name[0] = '.';
		c_name[1] = '.';
		strcpy(c_name+2, name + len - MAX_DNS_LEN + 2);
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
		record_entry->node.key = &record_entry->hostname;
		MMAP_CACHE_INSERT(record_entry, dns_record);
	}

	struct dns_ip_cache_entry *ip_entry, *tmp2;
	union dns_ip_cache_key key = { };

	if (inet_pton(AF_INET6, addr, &key.data.addr.in6)) {
		key.data.family = AF_INET6;
	}
	else if (inet_pton(AF_INET, addr, &key.data.addr.in)) {
		key.data.family = AF_INET;
		key.data.addr.in.s_addr = be32toh(key.data.addr.in.s_addr);
	} else {
		error_printf("Wrong IP format: %s\n", addr);
		return -1;
	}

	ip_entry = avl_find_element(&dns_ip_cache_avl, &key, tmp2, node);

	if (ip_entry) {
		
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
		MMAP_CACHE_GET_NEXT(ip_entry, dns_ip_cache, DNS_IP_CACHE_SIZE, format_dns_ip_key);

		ip_entry->dns_rec_id = record_entry->id;
		ip_entry->dns_rec_mmap_idx = MMAP_GET_IDX(dns_record, record_entry);
		ip_entry->key = key;
		ip_entry->node.key = &ip_entry->key;
		MMAP_CACHE_INSERT(ip_entry, dns_ip_cache);
	}

	return 0;
}

static struct dns_record_entry *get_dns_record_by_addr(uint8_t family, void *addr)
{
	struct dns_ip_cache_entry *ptr, *tmp;
	union dns_ip_cache_key key = { };

	if (family == AF_INET6) {
		key.data.family = AF_INET6;
		key.data.addr.in6 = *(struct in6_addr *)addr;
	}
	else {
		key.data.family = AF_INET;
		key.data.addr.in = *(struct in_addr *)addr;
	}

	ptr = avl_find_element(&dns_ip_cache_avl, &key, tmp, node);

	if (!ptr)
		return NULL;

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

const char *dns_get_host_for_addr(uint8_t family, void *addr)
{
	struct dns_record_entry *rec = get_dns_record_by_addr(family, addr);

	if (!rec) return NULL;

	return rec->hostname;
}

uint32_t dns_inc_count_for_addr(uint8_t family, void *addr)
{
	struct dns_record_entry *rec = get_dns_record_by_addr(family, addr);

	if (!rec) return 0;

	++rec->count;
	debug_printf("dns_inc_count_for_addr - %s (%d)\n", rec->hostname, rec->count);

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
	return 0;
}

#if 0
static int
avl_cmp_dns_record_prune(const void *k1, const void *k2, void *ptr)
{
	uint32_t a = *(uint32_t *)k1;
	uint32_t b = *(uint32_t *)k2;
	return (a > b) - (a < b);
}
#endif

static int dns_archive(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(dns_record, DNS_RECORD_CACHE_SIZE, path, timestamp);

	//RESET dns_ip_cache_key
	MMAP_CACHE_RESET(dns_ip_cache, avl_cmp_dns_ip_cache);

	//RESET dns_record
	MMAP_CACHE_RESET(dns_record, avl_cmp_dns_record);
	DnsRecordNextID = 1;

	//RESET db dns counts
	struct record *rec = NULL;

	while ((rec = database_next(gdbh, rec)) != NULL) {

		for (int i=0; i<RECORD_NUM_HOSTS; ++i) {
			if (!rec->hosts[i]) break;
			rec->hosts[i] = 0;
		}
	}

#if 0
	//Only leave used entries
	
	//Reindex by id just for prune and reset counters
	avl_init(&dns_record_avl, avl_cmp_dns_record_prune, false, NULL);
	
	for (int i=0; i<dns_record_mmap_db_len; ++i) {
		struct dns_record_entry *r = dns_record_db + i;
		r->count = 0;
		if (!r->node.key) continue;

		r->node.key = &r->id;

		if (!avl_insert(&dns_record_avl, &r->node)) {
			debug_printf("Error in dns_archive, can not add entry for prune.\n");
		}
	}
	
	uint32_t cur_used_entries = 0;

	struct record *rec = NULL;

	while ((rec = database_next(gdbh, rec)) != NULL) {

		for (int i=0; i<RECORD_NUM_HOSTS; ++i) {
			if (!rec->hosts[i]) break;

			struct dns_record_entry *ptr, *tmp;

			ptr = avl_find_element(&dns_record_avl, &rec->hosts[i], tmp, node);

			if (!ptr) {
				debug_printf("Error - dns_archive can not find dns entry - %d\n", rec->hosts[i]);
				continue;
			}

			++ptr->count;

			uint32_t idx = MMAP_GET_IDX(dns_record, ptr);

			if (idx == cur_used_entries) {
				++cur_used_entries;
			} else if (idx < cur_used_entries) {
				continue;
			}

			struct dns_record_entry swap;

			tmp = dns_record_db + cur_used_entries;

			avl_delete(&dns_record_avl, &tmp->node);
			avl_delete(&dns_record_avl, &ptr->node);

			swap = *tmp;
			*tmp = *ptr;
			*ptr = swap;

			tmp->node.key = &tmp->id;
			ptr->node.key = &ptr->id;

			if (avl_insert(&dns_record_avl, &tmp->node) ||
					avl_insert(&dns_record_avl, &ptr->node)) {
				debug_printf("Error - dns_archive can not swap two entries\n");
			}
			++cur_used_entries;
		}
	}

	dns_record_mmap_db_len = cur_used_entries;
	dns_record_mmap_next_entry = cur_used_entries;

	debug_printf("Error - dns_archive, dns_record_mmap_db_len:%d\n", dns_record_mmap_db_len);

	avl_init(&dns_record_avl, avl_cmp_dns_record, false, NULL);

	for (int i=0; i<dns_record_mmap_db_len; ++i) {
		dns_record_db[i].node.key = &dns_record_db[i].hostname;
		if (avl_insert(&dns_record_avl, &dns_record_db[i].node)) {
			debug_printf("Error - dns_archive can not reindex entry:%d\n", i);
		}
	}
#endif

	return 0;
}

int init_dns(const char *db_path, uint32_t timestamp)
{
	nlbwmon_add_presistence_cb(dns_mmap_persist);
	database_add_archive_cb(dns_archive);
	MMAP_CACHE_INIT(dns_ip_cache, DNS_IP_CACHE_SIZE, avl_cmp_dns_ip_cache, key, format_dns_ip_key);
	if (!dns_ip_cache_db) return -errno;

	MMAP_CACHE_INIT(dns_record, DNS_RECORD_CACHE_SIZE, avl_cmp_dns_record, hostname, NULL);
	if (!dns_record_db) return -errno;

	if (dns_record_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(dns_record, DNS_RECORD_CACHE_SIZE, hostname, db_path, timestamp, NULL);
	}

	for (int i=0; i<dns_record_mmap_db_len; ++i) {
		struct dns_record_entry *r = dns_record_db + i;
		if (!r->node.key) continue;
		if (r->id >= DnsRecordNextID) DnsRecordNextID = r->id+1;
	}

	return 0;
}

