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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <net/if.h>      // For if_indextoname
#include <unistd.h>      // For close()
#include <sys/socket.h>  // For struct msghdr

#include "utils.h"
#include "uci.h"
#include "wans.h"

#define MAX_WANS 5

static LIST_HEAD(wans);
static const char *wan_indx_arr[MAX_WANS];
static int num_wans;

struct wan_monitor {
    struct uloop_fd ufd;
    int nl_sock;
};

static struct wan_monitor wan_mon;

static void wan_handle_interface_event(struct uloop_fd *u, unsigned int events)
{
    char buf[4096];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct sockaddr_nl snl;
    struct msghdr msg = {
        .msg_name = &snl,
        .msg_namelen = sizeof(snl),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };
    struct nlmsghdr *h;
    int len;

    while ((len = recvmsg(u->fd, &msg, MSG_DONTWAIT)) > 0) {
        for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_type == NLMSG_DONE)
                return;

            if (h->nlmsg_type == NLMSG_ERROR)
                return;

            if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
                continue;

            struct ifaddrmsg *ifa = NLMSG_DATA(h);
            struct rtattr *rta = IFA_RTA(ifa);
            int rtl = IFA_PAYLOAD(h);
            char ifname[IFNAMSIZ] = {0};

            if (!if_indextoname(ifa->ifa_index, ifname))
                continue;

            struct wan *w = NULL;
            list_for_each_entry(w, &wans, list) {
                if (strcmp(w->ifname, ifname) == 0)
                    break;
            }
            if (!w)
                continue;

            while (rtl && RTA_OK(rta, rtl)) {
                if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
                    if (h->nlmsg_type == RTM_DELADDR) {
                        if (ifa->ifa_family == AF_INET) {
                            memset(&w->ipv4_addr, 0, sizeof(w->ipv4_addr));
                        } else if (ifa->ifa_family == AF_INET6) {
                            memset(&w->ipv6_addr, 0, sizeof(w->ipv6_addr));
                        }
                        debug_printf("Removed %s address from WAN %s\n",
                                     ifa->ifa_family == AF_INET ? "IPv4" : "IPv6", w->ifname);
                    } else if (h->nlmsg_type == RTM_NEWADDR) {
                        if (ifa->ifa_family == AF_INET && w->ipv4_addr.s_addr == 0) {
                            w->ipv4_addr.s_addr = be32toh(((struct in_addr *)RTA_DATA(rta))->s_addr);
                            debug_printf("Assigned IPv4 address %s to WAN %s\n",
                                         format_ipaddr(AF_INET, &w->ipv4_addr, 1), w->ifname);
                        } else if (ifa->ifa_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&w->ipv6_addr)) {
                            w->ipv6_addr = *((struct in6_addr *)RTA_DATA(rta));
                            debug_printf("Assigned IPv6 address %s to WAN %s\n",
                                         format_ipaddr(AF_INET6, &w->ipv6_addr, 1), w->ifname);
                        }
                    }
                }
                rta = RTA_NEXT(rta, rtl);
            }

            w->is_up = (w->ipv4_addr.s_addr != 0) || !IN6_IS_ADDR_UNSPECIFIED(&w->ipv6_addr);
            debug_printf("WAN interface %s %s (idx: %d)\n",
                         ifname, w->is_up ? "up" : "down", w->wan_idx);
        }
    }
}

static int wan_monitor_init(void)
{
    struct sockaddr_nl addr;
    int sock;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        error_printf("Failed to create netlink socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        error_printf("Failed to bind netlink socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    wan_mon.nl_sock = sock;
    wan_mon.ufd.fd = sock;
    wan_mon.ufd.cb = wan_handle_interface_event;

    uloop_fd_add(&wan_mon.ufd, ULOOP_READ);
    return 0;
}

int
add_wan(const char *name, const char *iface)
{
    struct ifaddrs *ifaddr;
    struct wan *w;
    int wan_idx = num_wans;

    if (num_wans == MAX_WANS)
        return -ENOMEM;

    wan_indx_arr[num_wans++] = name;

    w = calloc(1, sizeof(*w));
    if (!w)
        return -ENOMEM;

    w->wan_idx = wan_idx;
    w->is_up = 0; // Assume down until we find it's up
    strncpy(w->ifname, iface, IFNAMSIZ - 1);
    w->ifname[IFNAMSIZ - 1] = '\0';

    if (getifaddrs(&ifaddr) == -1) {
        error_printf("Error - getifaddrs:%s\n", strerror(errno));
        free(w);
        return -ENOENT;
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (strcmp(ifa->ifa_name, iface))
            continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET && w->ipv4_addr.s_addr == 0) {
            w->ipv4_addr.s_addr = be32toh(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr);
            w->is_up = 1; // Mark as up if we have at least one address
            debug_printf("Assigned IPv4 address %s to WAN %s\n",
                         format_ipaddr(AF_INET, &w->ipv4_addr, 1), w->ifname);
        } else if (family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&w->ipv6_addr)) {
            w->ipv6_addr = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            w->is_up = 1; // Mark as up if we have at least one address
            debug_printf("Assigned IPv6 address %s to WAN %s\n",
                         format_ipaddr(AF_INET6, &w->ipv6_addr, 1), w->ifname);
        }
    }

    freeifaddrs(ifaddr);

    debug_printf("Adding WAN %s iface:%s %s\n",
                 name,
                 w->ifname,
                 w->is_up ? "up" : "down");

    list_add_tail(&w->list, &wans);
    return 0;
}

int
match_wan(int family, struct in6_addr *addr)
{
    struct wan *w;

    list_for_each_entry(w, &wans, list) {
        // Skip interfaces that are down
        if (!w->is_up)
            continue;

        if (family == AF_INET) {
            struct in_addr *in_addr = (struct in_addr *)addr;
            if (w->ipv4_addr.s_addr == in_addr->s_addr)
                return w->wan_idx;
        } else if (family == AF_INET6) {
            if (!memcmp(&w->ipv6_addr, addr, sizeof(struct in6_addr)))
                return w->wan_idx;
        }
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
    
    if (wan_monitor_init() < 0) {
        error_printf("Failed to initialize WAN monitor\n");
        return -1;
    }
    
    return num_wans;
}
