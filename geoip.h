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

#ifndef __GEOIP_H__
#define __GEOIP_H__

#include <netinet/in.h>

union geoip_key {
	uint32_t u32[5];
	struct {
		uint8_t family;
		union {
			struct in_addr in;
			struct in6_addr in6;
		} addr;
	} data;
};

struct geoip_entry {
	union geoip_key key;
	char country[2];
	int32_t lonlat[2];
	uint16_t asn;
	struct avl_node node;
};

int geoip_lookup(struct record *rec);
int init_geoip_mmap(const char *db_path);
int geoip_is_bogon(const char *country);

#endif
