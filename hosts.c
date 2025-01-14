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

#include "nlbwmon.h"
#include "utils.h"
#include "mmap_cache.h"
#include "database.h"
#include "hosts.h"

#define HOSTS_RECORD_CACHE_SIZE 1000
DEFINE_MMAP_CACHE(hosts_record);

static struct uloop_timeout HostsNewGraceTimer;
static int HostsNewGracePeriod = 0;

int hosts_update_by_addr(const char *name, struct ether_addr *addr, uint8_t type)
{
	struct hosts_record_entry *record_entry, *tmp;

	debug_printf("hosts_update - %s %s\n", name, format_macaddr(addr));

	char *buf = (char *)addr;
	if (buf[0] == 0 && !memcmp(buf, buf + 1, sizeof(*addr) - 1)) {
		error_printf("Error ethernet addr is not set\n");
		return -1;
	}

	char c_name[MAX_HOST_NAME+1];
	if (strlen(name) > MAX_HOST_NAME) {
		strncpy(c_name, name, MAX_HOST_NAME);
		c_name[MAX_HOST_NAME] = 0;
		name = c_name;
	}

	record_entry = avl_find_element(&hosts_record_avl, addr, tmp, node);

	if (record_entry) {
		if (record_entry->type > type) {
			debug_printf("Ignore update - already set with higher prio.\n");
			return 0;
		}

		if (strcmp(record_entry->hostname, name)) {
			debug_printf("Updating hostname. Old:%s\n", record_entry->hostname);
			strcpy(record_entry->hostname, name);
		} else {
			debug_printf("hostname already updated.\n");
		}
		record_entry->type = type;

	} else {
		MMAP_CACHE_GET_NEXT(record_entry, hosts_record, HOSTS_RECORD_CACHE_SIZE, NULL);
		strcpy(record_entry->hostname, name);
		record_entry->type = type;
		record_entry->mac_addr = *addr;
		record_entry->node.key = &record_entry->mac_addr;
		MMAP_CACHE_INSERT(record_entry, hosts_record);
	}

	if (type == TYPE_USER_PROVIDED) {
		MMAP_CACHE_SAVE(hosts_record, HOSTS_RECORD_CACHE_SIZE, NULL, 0);
	}

	return 0;
}

int hosts_update(const char *name, const char *macaddr, uint8_t type)
{
	debug_printf("hosts_update - %s %s\n", name, macaddr);

	struct ether_addr addr;

	if (!ether_aton_r(macaddr, &addr)) {
		error_printf("Error Wrong MAC addr format: %s\n", macaddr);
		return -1;
	}

	return hosts_update_by_addr(name, &addr, type);
}

const char *lookup_hostname(struct ether_addr *macaddr)
{
	struct hosts_record_entry *ptr, *tmp;

	ptr = avl_find_element(&hosts_record_avl, macaddr, tmp, node);

	if (!ptr)
		return NULL;

	if (!ptr->hostname[0]) return NULL;

	return ptr->hostname;;
}

int hosts_is_new(struct ether_addr *macaddr)
{
	struct hosts_record_entry *ptr, *tmp;

	ptr = avl_find_element(&hosts_record_avl, macaddr, tmp, node);

	if (!ptr) {
		hosts_update_by_addr("", macaddr, TYPE_NO_NAME);

		if (!HostsNewGracePeriod) return 1;
		return 0;
	}

	return 0;
}

static int
avl_cmp_hosts_record(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, sizeof(struct ether_addr));
}

static char *format_hosts_record_key(const void *ptr) {
	struct ether_addr *addr = (struct ether_addr *)ptr;

	return format_macaddr(addr);
}

static int hosts_mmap_persist(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(hosts_record, HOSTS_RECORD_CACHE_SIZE, path, 0);
	return 0;
}

static void hosts_grace_timeout_cb(struct uloop_timeout *tm)
{
	HostsNewGracePeriod = 0;
}

struct hosts_stat *hosts_get_all(size_t *count) {
    size_t num_hosts = hosts_record_avl.count;
    struct hosts_stat *stats = NULL;

    if (num_hosts == 0) {
        *count = 0;
        return NULL;
    }

    stats = calloc(num_hosts, sizeof(struct hosts_stat));
    if (!stats) {
        *count = 0;
        return NULL;
    }

    struct hosts_record_entry *ptr;
    size_t i = 0;

    // Initialize stats array with hosts records
    avl_for_each_element(&hosts_record_avl, ptr, node) {
        stats[i].record = ptr;
        i++;
    }

    // Collect IPs and connection counts from database records
    struct record *rec = NULL;
    while ((rec = database_next(gdbh, rec)) != NULL) {
        for (i = 0; i < num_hosts; i++) {
            if (memcmp(&stats[i].record->mac_addr, &rec->src_mac.ea, sizeof(struct ether_addr)) == 0) {
                stats[i].conn_count += be64toh(rec->count);

                // Check if IP already exists and find empty slot
                bool ip_exists = false;
                size_t j;
                for (j = 0; j < NEIGH_MAX_STAT_IPS; j++) {
                    if (stats[i].ip[j].family == 0) {
                        break;
                    }
                    if (stats[i].ip[j].family == rec->family &&
                        memcmp(&stats[i].ip[j].addr, &rec->src_addr, sizeof(rec->src_addr)) == 0) {
                        ip_exists = true;
                        break;
                    }
                }

                // Add IP if not exists and there's space
                if (!ip_exists && j < NEIGH_MAX_STAT_IPS) {
                    stats[i].ip[j].family = rec->family;
                    memcpy(&stats[i].ip[j].addr, &rec->src_addr, sizeof(rec->src_addr));
                }
                break;
            }
        }
    }

    *count = num_hosts;
    return stats;
}

int hosts_clean() {
    size_t num_removed = 0;
    
    // Iterate backwards through the mmap cache
    for (int i = hosts_record_mmap_db_len - 1; i >= 0; i--) {
        struct hosts_record_entry *entry = hosts_record_db + i;
        
        // Skip unused entries
        if (!entry->node.key)
            continue;

        // Check if entry has no name
        if (entry->hostname[0] == '\0') {
            // Count connections for this MAC
            uint64_t conn_count = 0;
            struct record *rec = NULL;
            while ((rec = database_next(gdbh, rec)) != NULL) {
                if (memcmp(&entry->mac_addr, &rec->src_mac.ea, sizeof(struct ether_addr)) == 0) {
                    conn_count += be64toh(rec->count);
                    if (conn_count > 0) break; // Early exit if we find any connections
                }
            }

            // If no connections, remove the entry
            if (conn_count == 0) {
                num_removed++;
                
                // Compact the cache by moving remaining entries
                if (i < hosts_record_mmap_db_len - 1) {
                    memmove(entry, entry + 1, 
                        (hosts_record_mmap_db_len - i - 1) * sizeof(*entry));
                }
                
                // Clear last entry and update counters
                memset(&hosts_record_db[hosts_record_mmap_db_len - 1], 0, sizeof(*entry));
                hosts_record_mmap_db_len--;
                if (*hosts_record_mmap_next_entry > 0) {
                    (*hosts_record_mmap_next_entry)--;
                }
            }
        }
    }
    
    if (num_removed > 0) {
        // Rebuild AVL tree
        avl_init(&hosts_record_avl, avl_cmp_hosts_record, false, NULL);
        for (int i = 0; i < hosts_record_mmap_db_len; i++) {
            struct hosts_record_entry *entry = hosts_record_db + i;
            if (!entry->node.key)
                continue;
            entry->node.key = &entry->mac_addr;
            if (avl_insert(&hosts_record_avl, &entry->node)) {
                error_printf("Error adding entry to AVL tree\n");
                entry->node.key = NULL;
            }
        }

        // Save changes to mmap cache
        MMAP_CACHE_SAVE(hosts_record, HOSTS_RECORD_CACHE_SIZE, NULL, 0);
    }
    
    return num_removed;
}

int init_hosts(const char *db_path, uint32_t timestamp)
{
	nlbwmon_add_presistence_cb(hosts_mmap_persist);
	MMAP_CACHE_INIT(hosts_record, HOSTS_RECORD_CACHE_SIZE, avl_cmp_hosts_record, mac_addr, format_hosts_record_key);
	if (!hosts_record_db) return -errno;

	if (hosts_record_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(hosts_record, HOSTS_RECORD_CACHE_SIZE, mac_addr, db_path, 0, format_hosts_record_key);
	}

	// One minute grace of avoiding new client notifications on first run
	if (hosts_record_mmap_db_len == 0) {
		HostsNewGracePeriod = 1;
		HostsNewGraceTimer.cb = hosts_grace_timeout_cb;
		uloop_timeout_set(&HostsNewGraceTimer, 60 * 1000);
	}

	return 0;
}

