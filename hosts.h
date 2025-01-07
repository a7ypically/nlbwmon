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
#ifndef __HOSTS_H__
#define __HOSTS_H__

#include <netinet/in.h>
#include <net/ethernet.h>

#define MAX_HOST_NAME 31
#define NEIGH_MAX_STAT_IPS 4

#define TYPE_NO_NAME	   0
#define TYPE_DHCP_PROVIDED 1
#define TYPE_USER_PROVIDED 2

struct hosts_record_entry {
	uint8_t type;
	struct ether_addr mac_addr;
	char hostname[MAX_HOST_NAME];
	struct avl_node node;
};

struct hosts_stat {
  struct hosts_record_entry *record;
  struct {
    uint8_t family;
    union {
      struct in_addr in;
      struct in6_addr in6;
    } addr;
  } ip[NEIGH_MAX_STAT_IPS];
  uint64_t conn_count;
};

int hosts_update(const char *name, const char *macaddr, uint8_t type);
int hosts_update_by_addr(const char *name, struct ether_addr *addr, uint8_t type);
const char *lookup_hostname(struct ether_addr *macaddr);
int hosts_is_known(struct ether_addr *macaddr);
struct hosts_stat *hosts_get_all(size_t *count);
int init_hosts(const char *db_path, uint32_t timestamp);
int hosts_is_new(struct ether_addr *macaddr);
int hosts_clean();

#endif
