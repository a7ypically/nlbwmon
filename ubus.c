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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <libubus.h>
#include <netinet/ether.h>

#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/list.h>

#include "utils.h"
#include "database.h"
#include "ubus.h"
#include "neigh.h"
#include "dns.h"
#include "hosts.h"

static struct ubus_context *ubus = NULL;

static int receive_request(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
  const char *name;
  struct blob_attr *pos;

  if (!strcmp(method, "dns_result")) {
    char *r_name = NULL;
    char *r_addr = NULL;
    char *c_addr = NULL;
    uint32_t ttl = -1;

    int rem = blobmsg_data_len(msg);
    struct blob_attr *msg_data = blobmsg_data(msg);
    __blob_for_each_attr(pos, msg_data, rem) {
      if (!blobmsg_check_attr(pos, false))
        continue;

      //if (blob_id(pos) != BLOBMSG_TYPE_STRING) continue;

      name = blobmsg_name(pos);

      if (!strcmp(name, "name")) {
        r_name = (char *)blobmsg_data(pos);
        continue;
      }

      if (!strcmp(name, "ttl")) {
        ttl = blobmsg_get_u32(pos);
        continue;
      }

      if (!strcmp(name, "address")) {
        r_addr = (char *)blobmsg_data(pos);
        continue;
      }

      if (!strcmp(name, "client_addr")) {
        c_addr = (char *)blobmsg_data(pos);
        continue;
      }
    }

    if (!r_name || !r_addr) {
      error_printf("Error - Missing data in ubus msg\n");
      return 0;
    }

    dns_update(r_name, ttl, r_addr, c_addr);

  } else if (!strcmp(method, "dhcp.ack") || !strcmp(method, "dhcp.release")) {

    char *r_ip = NULL;
    char *r_mac = NULL;
    char *r_name = NULL;
    int rem = blobmsg_data_len(msg);

    struct blob_attr *msg_data = blobmsg_data(msg);
    __blob_for_each_attr(pos, msg_data, rem) {
      if (!blobmsg_check_attr(pos, false))
        continue;

      if (blob_id(pos) != BLOBMSG_TYPE_STRING) continue;

      name = blobmsg_name(pos);

      if (!strcmp(name, "ip")) {
        r_ip = (char *)blobmsg_data(pos);
        continue;
      }

      if (!strcmp(name, "mac")) {
        r_mac = (char *)blobmsg_data(pos);
        continue;
      }

      if (!strcmp(name, "name")) {
        r_name = (char *)blobmsg_data(pos);
        continue;
      }
    }

    if (!r_ip || !r_mac) {
      error_printf("Error - Missing data in ubus msg dhcp.ack\n");
      return 0;
    }

    neigh_ubus_update(strcmp(method, "dhcp.release"), r_ip, r_mac);

    if (r_name) {
      hosts_update(r_name, r_mac, TYPE_DHCP_PROVIDED);
    }

  } else {
    error_printf("Error - { \"%s\" } - wrong method\n", method);
    return 0;
  }

  return 0;
}

static void getHostsCallback (struct ubus_request *req, int type, struct blob_attr *msg) {
  struct blob_attr *cur, *cur2, *cur3, *cur_c, *cur2_c;
  int rem, rem2, rem3;

  rem = blobmsg_len(msg);
  msg = blobmsg_data(msg);

  __blob_for_each_attr(cur, msg, rem) {
    if (!blobmsg_check_attr(cur, false))
      continue;

    if (blob_id(cur) != BLOBMSG_TYPE_TABLE) continue;

    const char *macaddr = blobmsg_name(cur);

    rem2 = blobmsg_len(cur);
    cur_c = blobmsg_data(cur);
    __blob_for_each_attr(cur2, cur_c, rem2) {

      const char *name = blobmsg_name(cur2);

      if (!strcmp(name, "name") && (blob_id(cur2) == BLOBMSG_TYPE_STRING)) {
        const char *hostname = (char *)blobmsg_data(cur2);
        debug_printf("%s - %s\n", macaddr, hostname);
        hosts_update(hostname, macaddr, TYPE_DHCP_PROVIDED);
      } else {

        if (blob_id(cur2) != BLOBMSG_TYPE_ARRAY) continue;

        rem3 = blobmsg_len(cur2);
        cur2_c = blobmsg_data(cur2);
        __blob_for_each_attr(cur3, cur2_c, rem3) {
          const char *ipaddr = (char *)blobmsg_data(cur3);
          debug_printf("Adding to neigh table %s - %s\n", macaddr, ipaddr);
          neigh_ubus_update(1, ipaddr, macaddr);
        }
      }

    }
  }

  /* do something */
  return;
}

struct ubus_subscriber sub = {
  .cb = receive_request,
};

void init_ubus(void)
{
  if (!(ubus = ubus_connect(NULL))) {
    error_printf("Can not init ubus!\n");
    exit(-1);
  }

  ubus_add_uloop(ubus);

  //avl_init(&geoip_db, avl_cmp_geoip, false, NULL);
  uint32_t id;

  int ret = ubus_register_subscriber(ubus, &sub);
  if (ret) {
    error_printf("Error while registering for event: %s\n", ubus_strerror(ret));
    exit(1);
  }
  ret = ubus_lookup_id(ubus, "dnsmasq.dns", &id);
  if (ret) {
    error_printf("Error while registering for event: %s\n", ubus_strerror(ret));
    exit(1);
  }
  ret = ubus_subscribe(ubus, &sub, id);
  if (ret) {
    error_printf("Error while registering for event: %s\n", ubus_strerror(ret));
    exit(1);
  }

  ret = ubus_lookup_id(ubus, "dnsmasq", &id);
  if (ret) {
    error_printf("Error while registering for event: %s\n", ubus_strerror(ret));
    exit(1);
  }
  ret = ubus_subscribe(ubus, &sub, id);
  if (ret) {
    error_printf("Error while registering for event: %s\n", ubus_strerror(ret));
    exit(1);
  }

  ret = ubus_lookup_id(ubus, "luci-rpc", &id);
  if (ret) {
    error_printf("Error calling luci-rpc.getHostHints: %s\n", ubus_strerror(ret));
  } else {
    ubus_invoke(ubus, id, "getHostHints", NULL, getHostsCallback, 0, 3000);
  }
}

