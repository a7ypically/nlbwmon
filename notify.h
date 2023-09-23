
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

#ifndef __NOTIFY_H__
#define __NOTIFY_H__

#include <netinet/in.h>
#include <netinet/ether.h>
#include "database.h"

#define NOTIFY_ACTION_MUTE 1

struct notify_params {
	uint8_t proto;
	uint16_t dst_port;
	uint8_t type;
	union {
		struct ether_addr ea;
		uint64_t u64;
		uint8_t wan_idx;
	} src;
	char country[2];
	uint16_t asn;
};

int init_notify(const char *db_path);
void notify_new(struct record *r);
void notify_update(struct record *r);
void notify_new_client(struct ether_addr *mac);
int notify_mute_add(struct notify_params *params);
int notify_is_muted(struct record *r, struct notify_params *params);

#endif
