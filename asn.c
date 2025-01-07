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

#include <libubox/avl.h>

#include <assert.h>
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

#include "nlbwmon.h"
#include "mmap_cache.h"
#include "utils.h"
#include "database.h"
#include "asn.h"

#define ASNS_MMAP_CACHE_SIZE 10000
DEFINE_MMAP_CACHE(asn);

int asn_add(uint32_t asn, const char *org)
{
	struct asn_entry *ptr, *tmp;

	ptr = avl_find_element(&asn_avl, &asn, tmp, node);

	if (ptr) return 0;

	if (!ptr) {
		MMAP_CACHE_GET_NEXT(ptr, asn, ASNS_MMAP_CACHE_SIZE, NULL);

		int len = strlen(org);
		if (len > MAX_ORG_LEN) {
			strncpy(ptr->org, org, MAX_ORG_LEN - 2);
			ptr->org[MAX_ORG_LEN - 2] = '.';
			ptr->org[MAX_ORG_LEN-1] = '.';
			ptr->org[MAX_ORG_LEN] = 0;
		} else {
			strcpy(ptr->org, org);
		}

		ptr->asn = asn;
		ptr->node.key = &ptr->asn;
		MMAP_CACHE_INSERT(ptr, asn);
	}

	return 0;
}

const char *lookup_asn(uint32_t asn)
{
	struct asn_entry *ptr, *tmp;

	ptr = avl_find_element(&asn_avl, &asn, tmp, node);

	if (!ptr)
		return NULL;

	if (ptr->org[strlen(ptr->org)-1] == '\\') {
		ptr->org[strlen(ptr->org)-1] = 0;
	}
	return ptr->org;
}


static int
avl_cmp_asn(const void *k1, const void *k2, void *ptr)
{
	uint32_t a = *(uint32_t *)k1;
	uint32_t b = *(uint32_t *)k2;
	return (a > b) - (a < b);
}

static int asn_mmap_persist(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(asn, ASNS_MMAP_CACHE_SIZE, path, timestamp);
	return 0;
}

static int asn_archive(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(asn, ASNS_MMAP_CACHE_SIZE, path, timestamp);

	//Only keep used entries
	
	uint32_t cur_used_entries = 0;

	struct record *rec = NULL;

	while ((rec = database_next(gdbh, rec)) != NULL) {

		if (!rec->asn) continue;

		struct asn_entry *ptr, *tmp;

		ptr = avl_find_element(&asn_avl, &rec->asn, tmp, node);

		if (!ptr) {
			error_printf("Error - asn_archive can not find asn - %d\n", rec->asn);
			continue;
		}

		uint32_t idx = MMAP_GET_IDX(asn, ptr);

		if (idx == cur_used_entries) {
			++cur_used_entries;
		} else if (idx < cur_used_entries) {
			continue;
		}

		struct asn_entry swap;

		tmp = asn_db + cur_used_entries;

		avl_delete(&asn_avl, &tmp->node);
		avl_delete(&asn_avl, &ptr->node);

		swap = *tmp;
		*tmp = *ptr;
		*ptr = swap;

		tmp->node.key = &tmp->asn;
		ptr->node.key = &ptr->asn;

		if (avl_insert(&asn_avl, &tmp->node) ||
				avl_insert(&asn_avl, &ptr->node)) {
			error_printf("Error - asn_archive can not swap two entries\n");
		}
		++cur_used_entries;
	}

	assert(cur_used_entries <= asn_mmap_db_len);

	memset(asn_db+cur_used_entries, 0, sizeof(struct asn_entry) * (asn_mmap_db_len - cur_used_entries));
	asn_mmap_db_len = cur_used_entries;
	*asn_mmap_next_entry = cur_used_entries;

	debug_printf("asn_archive, asn_mmap_db_len:%d\n", asn_mmap_db_len);

	avl_init(&asn_avl, avl_cmp_asn, false, NULL);

	for (int i=0; i<asn_mmap_db_len; ++i) {
		if (avl_insert(&asn_avl, &asn_db[i].node)) {
			error_printf("Error - asn_archive can not reindex entry:%d\n", i);
		}
	}


	return 0;
}

static char *format_asn_record_key(const void *ptr) {
	uint32_t *asn = (uint32_t *)ptr;
	static char str[16];
	snprintf(str, sizeof(str), "%d", *asn);

	return str;
}

int init_asn_mmap(const char *db_path, uint32_t timestamp)
{
	nlbwmon_add_presistence_cb(asn_mmap_persist);
	database_add_archive_cb(asn_archive);

	MMAP_CACHE_INIT(asn, ASNS_MMAP_CACHE_SIZE, avl_cmp_asn, asn, format_asn_record_key);
	if (!asn_db) return -errno;

	if (asn_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(asn, ASNS_MMAP_CACHE_SIZE, asn, db_path, timestamp, format_asn_record_key);
	}

	return 0;
}

