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
#include <errno.h>
#include <string.h>

#include <libubox/utils.h>

#include "protocol.h"
#include "config.h"
#include "nlbwmon.h"

static int ProtocolAll = 0;
uint16_t DNS_UDP_NET_PORT;

static int
avl_cmp_proto(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, offsetof(struct protocol, idx));
}

static AVL_TREE(protocols, avl_cmp_proto, false, NULL);

int
init_protocols(const char *database)
{
	char *p = NULL, buf[PR_NAMELEN];
	struct protocol *pr;
	uint16_t idx = 0;
	uint16_t port;
	uint8_t proto;
	FILE *in;

	DNS_UDP_NET_PORT = htons(53);
	ProtocolAll = config_get_uint32("all_protocols", 1) != 0;

	in = fopen(opt.protocol_db, "r");

	if (!in)
		return -errno;

	while (fscanf(in, PR_SCANFMT, &proto, &port, buf) == 3)
	{
		if (!buf[0])
			continue;

		if (!p || strcmp(p, buf))
			idx++;

		pr = calloc_a(sizeof(*pr), &p, strlen(buf) + 1);

		if (!pr) {
			fclose(in);
			return -ENOMEM;
		}

		pr->proto = proto;
		pr->port = port;
		pr->idx = idx;
		pr->name = strcpy(p, buf);
		pr->node.key = pr;

		avl_insert(&protocols, &pr->node);
	}

	fclose(in);
	return 0;
}

static struct protocol *
lookup_protocol(uint8_t proto, uint16_t port)
{
	static 
	struct protocol *pr, key = { };

	key.proto = proto;
	key.port = port;

	return avl_find_element(&protocols, &key, pr, node);
}

int protocol_include(uint8_t proto, uint16_t port)
{
	if (ProtocolAll) return 1;

	return lookup_protocol(proto, port) != NULL;
}

char *get_protocol_name(uint8_t proto, uint16_t port)
{
	static char str[64];
	struct protocol *p = lookup_protocol(proto, port);

	if (p) return p->name;

	if (!ProtocolAll) return "other";

	if (port) {
		p = lookup_protocol(proto, 0);
		if (p) {
			snprintf(str, sizeof(str), "%s port:%d", p->name, port);
			return str;
		}
	}

	snprintf(str, sizeof(str), "proto:%d port:%d", proto, port);
	return str;
}


