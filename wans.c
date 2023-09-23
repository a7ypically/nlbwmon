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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <libubox/list.h>

#include "utils.h"
#include "uci.h"
#include "wans.h"

#define MAX_WANS 4

static LIST_HEAD(wans);
static const char *wan_indx_arr[MAX_WANS];
static int num_wans;

int
add_wan(const char *name, const char *iface)
{
	struct ifaddrs *ifaddr;
	int family;
	int wan_idx = num_wans;

	if (num_wans == MAX_WANS)
		return -ENOMEM;

	wan_indx_arr[num_wans++] = name;

	if (getifaddrs(&ifaddr) == -1) {
		error_printf("Error - getifaddrs:%s\n", strerror(errno));
		return -ENOENT;
	}

	for (struct ifaddrs *ifa = ifaddr; ifa != NULL;
			ifa = ifa->ifa_next) {

		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, iface))
			continue;

		family = ifa->ifa_addr->sa_family;

		if ((family != AF_INET) && (family != AF_INET6))
			continue;

		struct wan *w = calloc(1, sizeof(*w));

		if (!w) {
			freeifaddrs(ifaddr);
			return -ENOMEM;
		}

		w->wan_idx = wan_idx;
		w->family = family;

		if (family == AF_INET) {
			w->addr.in.s_addr = be32toh(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr);
		} else {
			w->addr.in6 = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
		}

		debug_printf("Adding wan %s iface:%s %s (%d) %s\n",
				name,
				ifa->ifa_name,
				(family == AF_INET) ? "AF_INET" :
				(family == AF_INET6) ? "AF_INET6" : "???",
				family,
				(family == AF_INET) ? format_ipaddr(family, &w->addr.in, 1) : format_ipaddr(family, &w->addr.in6, 1));

		list_add_tail(&w->list, &wans);
	}

	freeifaddrs(ifaddr);
	return 0;
}

int
match_wan(int family, struct in6_addr *addr)
{
	struct wan *w;
	uint32_t *a, *b;

	if (list_empty(&wans))
		return -ENOENT;

	list_for_each_entry(w, &wans, list) {
		if (w->family != family)
			continue;

		a = addr->s6_addr32;
		b = w->addr.in6.s6_addr32;

		if (memcmp(a, b, sizeof(*a)))
			continue;

		return w->wan_idx;
	}

	return -ENOENT;
}

const char *get_wan_name(int index)
{
	if (index >= num_wans) {
		error_printf("Error - Bad wan index - %d\n", index);
		assert(0);
		return "Error getting wan!";
	}

	return wan_indx_arr[index];
}

int wan_read_config(void)
{
	char path[50]="nlbwmon.@nlbwmon[0].wan_interface";
	struct uci_ptr ptr;
	struct uci_context *c = uci_alloc_context();

	if (!c) return -1;

	if (uci_lookup_ptr(c, &ptr, path, true) != UCI_OK) {
		uci_free_context(c);
		return -1;
	}

	if (ptr.o->type != UCI_TYPE_LIST) {
		uci_free_context(c);
		return -1;
	}

	struct uci_element *l;
	const char *p;

	uci_foreach_element(&ptr.o->v.list, l) {
		p = l->name;
		if (!p) continue;

		if (num_wans == MAX_WANS) {
			uci_free_context(c);
			return -1;
		}

		wan_indx_arr[num_wans++] = p;
	}

	uci_free_context(c);
	
	return num_wans;
}

