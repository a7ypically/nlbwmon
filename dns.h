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
#ifndef __DNS_H__
#define __DNS_H__

#include <netinet/in.h>

#define MAX_DNS_LEN 31

struct dns_record_entry {
	uint32_t id;
	uint32_t count;
	char hostname[MAX_DNS_LEN+1];
	struct avl_node node;
};

union dns_ip_cache_key {
	uint32_t u32[5];
	struct {
		uint8_t family;
		union {
			struct in_addr in;
			struct in6_addr in6;
		} addr;
	} data;
};

struct dns_ip_cache_entry {
	union dns_ip_cache_key key;
	uint32_t dns_rec_id;
	uint32_t dns_rec_mmap_idx;
	struct avl_node node;
};

int dns_update(const char *name, const char *addr);
const char *dns_get_host_for_addr(uint8_t family, void *addr);
uint32_t dns_inc_count_for_addr(uint8_t family, void *addr);
const char *dns_get_by_id(uint32_t id);
int init_dns(const char *db_path, uint32_t timestamp);

#endif
