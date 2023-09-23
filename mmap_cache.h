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

#ifndef __MMAP_CACHE_H__
#define __MMAP_CACHE_H__

#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <zlib.h>
#include "utils.h"
#include "nlbwmon.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define CONCAT_(a, b) a##b
#define CONCAT(a, b) CONCAT_(a, b)

#define DEFINE_MMAP_CACHE(TYPE) \
	static uint32_t CONCAT(TYPE, _mmap_db_len); \
	static uint32_t *CONCAT(TYPE, _mmap_next_entry); \
	static struct CONCAT(TYPE, _entry) *CONCAT(TYPE, _db); \
	static struct avl_tree CONCAT(TYPE, _avl);

#define MMAP_CACHE_INIT(TYPE, SIZE, CMP_FN, KEY, FORMAT_KEY_FN) \
{ \
	avl_init(&CONCAT(TYPE, _avl), CMP_FN, false, NULL); \
	uint32_t len = sizeof(uint32_t) + SIZE * sizeof(struct CONCAT(TYPE, _entry)); \
	char file[256]; \
	snprintf(file, sizeof(file), "%s/"TOSTRING(TYPE)".mmap", opt.tempdir); \
	int fd = open(file, O_CREAT|O_RDWR, 0640); \
	if (fd < 0) \
		goto CONCAT(TYPE, _init_out); \
	if (ftruncate(fd, len)) \
		goto CONCAT(TYPE, _init_out); \
	CONCAT(TYPE, _mmap_next_entry) = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0); \
	CONCAT(TYPE, _db) = (struct CONCAT(TYPE, _entry) *)(CONCAT(TYPE, _mmap_next_entry) + 1); \
	debug_printf(TOSTRING(TYPE)" DEBUG next_entry:0x%ld db:0x%ld\n", (uint64_t)CONCAT(TYPE, _mmap_next_entry), (uint64_t)CONCAT(TYPE, _db)); \
	if (CONCAT(TYPE, _db) == NULL) \
		goto CONCAT(TYPE, _init_out); \
	for (int i=0; i<SIZE; ++i) { \
		struct CONCAT(TYPE, _entry) *entry = CONCAT(TYPE, _db)+i; \
		if (!entry->node.key) { \
			char *buff = (char *)entry; \
			if (!*buff && !memcmp(buff, buff+1, sizeof(*entry)-1)) \
				break; \
		} \
		if (entry->node.key) { \
			memset(&entry->node, 0, sizeof(entry->node)); \
			entry->node.key = &entry->KEY; \
			if (FORMAT_KEY_FN != NULL) debug_printf(TOSTRING(TYPE)"_cache Loading %s from mmap cache\n", ((char * (*)(const void *))FORMAT_KEY_FN)(entry->node.key)); \
			if (avl_insert(&CONCAT(TYPE, _avl), &entry->node)) { \
				error_printf("Error inserting "TOSTRING(TYPE)" entry from mmap cache\n"); \
				entry->node.key = NULL; \
			} \
		} else { \
			debug_printf(TOSTRING(TYPE)"_cache entry %d not used\n", i); \
		} \
		CONCAT(TYPE, _mmap_db_len)++; \
	} \
	assert((CONCAT(TYPE, _mmap_db_len) == SIZE) || (CONCAT(TYPE, _mmap_db_len) == *CONCAT(TYPE, _mmap_next_entry))); \
	debug_printf(TOSTRING(TYPE)"_cache loaded %d entries.\n", CONCAT(TYPE, _mmap_db_len)); \
CONCAT(TYPE, _init_out): \
}

#define MMAP_CACHE_GET_NEXT(PTR, TYPE, SIZE, FORMAT_KEY_FN) \
	debug_printf(TOSTRING(TYPE) " - using record %d.\n", *CONCAT(TYPE, _mmap_next_entry)); \
	PTR = CONCAT(TYPE, _db) + *CONCAT(TYPE, _mmap_next_entry); \
	if (CONCAT(TYPE, _mmap_db_len) < SIZE) { \
		CONCAT(TYPE, _mmap_db_len) += 1; \
	} else { \
		if (PTR->node.key) { \
			if (FORMAT_KEY_FN != NULL) debug_printf(TOSTRING(TYPE)"_cache delete %s from mmap cache\n", ((char * (*)(const void *))FORMAT_KEY_FN)(PTR->node.key)); \
			avl_delete(&CONCAT(TYPE, _avl), &PTR->node); \
		} \
		memset(PTR, 0, sizeof(*PTR)); \
	} \
	*CONCAT(TYPE, _mmap_next_entry) = (*(CONCAT(TYPE, _mmap_next_entry)) + 1) % SIZE; 

#define MMAP_CACHE_INSERT(PTR, TYPE) \
	if (avl_insert(&CONCAT(TYPE, _avl), &PTR->node)) { \
		error_printf("Error adding entry to " TOSTRING(TYPE) ".\n"); \
		PTR->node.key = NULL; \
	}

#define MMAP_GET_IDX(TYPE, PTR) (PTR - CONCAT(TYPE, _db))

#define MMAP_CACHE_SAVE(TYPE, SIZE, path, timestamp) \
{ \
	char file[256]; \
	int err; \
	snprintf(file, sizeof(file), "%s/"TOSTRING(TYPE)"_%u_v2.db.gz", path ? path : opt.db.directory, timestamp); \
	debug_printf("file: '%s'\n", file); \
	gzFile gz = NULL; \
	int fd; \
	fd = open(file, O_WRONLY|O_CREAT|O_TRUNC, 0640); \
	if (fd < 0) { \
		error_printf("Error %s creating save file for " TOSTRING(TYPE) ".\n", strerror(errno)); \
		goto CONCAT(TYPE, _save_error); \
	} \
	gz = gzdopen(fd, "wb9"); \
	if (!gz) { \
		error_printf("Error in gzopen '%s' for " TOSTRING(TYPE) ".\n", gzerror(gz, &err)); \
		close(fd); \
		goto CONCAT(TYPE, _save_error); \
	} \
	if (gzwrite(gz, CONCAT(TYPE, _mmap_next_entry), sizeof(*CONCAT(TYPE, _mmap_next_entry))) != sizeof(*CONCAT(TYPE, _mmap_next_entry))) { \
		error_printf("Error in gzwrite for " TOSTRING(TYPE) ".\n"); \
		goto CONCAT(TYPE, _save_error); \
	} \
	for (int i=0; i<SIZE; ++i) { \
		struct CONCAT(TYPE, _entry) *entry = CONCAT(TYPE, _db)+i; \
		if (!entry->node.key) { \
			char *buff = (char *)entry; \
			if (!*buff && !memcmp(buff, buff+1, sizeof(*entry)-1)) \
				break; \
		} \
		if (entry->node.key) { \
			if (gzwrite(gz, entry, offsetof(struct CONCAT(TYPE, _entry), node)) != offsetof(struct CONCAT(TYPE, _entry), node)) { \
				error_printf("Error in gzwrite for " TOSTRING(TYPE) ".\n"); \
				goto CONCAT(TYPE, _save_error); \
			} \
		} \
	} \
CONCAT(TYPE, _save_error): \
	if (gz) \
		err = gzclose(gz); \
	if (err != Z_OK) { \
		error_printf("Error in gzclose (%d) for " TOSTRING(TYPE) ".\n", err); \
		unlink(file); \
	} \
}

#define MMAP_CACHE_LOAD(TYPE, SIZE, KEY, path, timestamp, FORMAT_KEY_FN) \
{ \
	char file[256]; \
	int err; \
	uint32_t gz_mmap_next_entry; \
	snprintf(file, sizeof(file), "%s/"TOSTRING(TYPE)"_%u_v2.db.gz", path, timestamp); \
	gzFile gz = NULL; \
	gz = gzopen(file, "rb"); \
	if (!gz) { \
		error_printf("No DB file for " TOSTRING(TYPE) ".\n"); \
		goto CONCAT(TYPE, _load_error); \
	} \
	if (gzread(gz, &gz_mmap_next_entry, sizeof(gz_mmap_next_entry)) != sizeof(gz_mmap_next_entry)) { \
		error_printf("Error in gzread for " TOSTRING(TYPE) ".\n"); \
	} else { \
		for (int i=0; i<SIZE; ++i) { \
			struct CONCAT(TYPE, _entry) entry = {}; \
			int res = gzread(gz, &entry, offsetof(struct CONCAT(TYPE, _entry), node)); \
			if (res == 0) { \
				gzerror(gz, &err); \
				if (!err || (err == Z_STREAM_END)) break; \
				else error_printf("Error in gzread. Read 0 bytes. err:%d\n", err); \
			} \
			if (res != offsetof(struct CONCAT(TYPE, _entry), node)) { \
				error_printf("Error in gzread for " TOSTRING(TYPE) ".\n"); \
				break; \
			} \
			struct CONCAT(TYPE, _entry) *ptr; \
			MMAP_CACHE_GET_NEXT(ptr, TYPE, SIZE, FORMAT_KEY_FN); \
			memcpy(ptr, &entry, offsetof(struct CONCAT(TYPE, _entry), node)); \
			ptr->node.key = &ptr->KEY; \
			if (FORMAT_KEY_FN != NULL) debug_printf(TOSTRING(TYPE)"_cache Loading %s from gz file\n", ((char * (*)(const void *))FORMAT_KEY_FN)(ptr->node.key)); \
			MMAP_CACHE_INSERT(ptr, TYPE); \
		} \
	} \
	debug_printf(TOSTRING(TYPE)"_cache loaded %d entries.\n", CONCAT(TYPE, _mmap_db_len)); \
	if (*CONCAT(TYPE, _mmap_next_entry) == 0) *CONCAT(TYPE, _mmap_next_entry) = gz_mmap_next_entry; \
	if (*CONCAT(TYPE, _mmap_next_entry) != gz_mmap_next_entry) error_printf("Warning - "TOSTRING(TYPE)"_cache using a different next_entry pointer from the one in backup - %d:%d\n", *CONCAT(TYPE, _mmap_next_entry),  gz_mmap_next_entry); \
	err = gzclose(gz); \
	if (err != Z_OK) { \
		error_printf("Error in gzclose (%d) for " TOSTRING(TYPE) ".\n", err); \
	} \
CONCAT(TYPE, _load_error): \
}

#define MMAP_CACHE_RESET(TYPE, CMP_FN) \
{ \
	avl_init(&CONCAT(TYPE, _avl), CMP_FN, false, NULL); \
	memset(CONCAT(TYPE, _db), 0, sizeof(struct CONCAT(TYPE, _entry)) * CONCAT(TYPE, _mmap_db_len)); \
	*CONCAT(TYPE, _mmap_next_entry) = 0; \
	CONCAT(TYPE, _mmap_db_len) = 0 ; \
}

#endif
