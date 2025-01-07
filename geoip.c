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
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>

#include <libubox/avl.h>
#include <libubox/ustream.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/list.h>

#include "utils.h"
#include "database.h"
#include "asn.h"
#include "https.h"
#include "tg.h"
#include "config.h"
#include "mmap_cache.h"
#include "geoip.h"

#define GEOIP_STATE_IDLE 0
#define GEOIP_STATE_IN_PROG 1
#define GEOIP_STATE_READ_ERROR 2

static char *IpInfoToken;

#define GEOIP_MMAP_CACHE_SIZE 10000
DEFINE_MMAP_CACHE(geoip);

static struct geoip_entry *ipinfo_cur_entry;

#define MAX_ADDRS_IN_TRANS 20

static int geoip_state;
static int ipinfo_content_len = -1;
static int ipinfo_data_ctr = 0;
static struct https_ctx *geoip_https_ctx;

struct geoip_req {
	struct list_head list;
	char addrs[MAX_ADDRS_IN_TRANS][INET6_ADDRSTRLEN];
	int cnt;
};

static LIST_HEAD(requests_queue);

static char *format_geoip_ip_key(const void *ptr) {
	union geoip_key *key = (union geoip_key *)ptr;

	return format_ipaddr(key->data.family, &key->data.addr, 1);
}

static struct geoip_entry *
_db_lookup_geoip(uint8_t family, void *addr)
{
	struct geoip_entry *ptr, *tmp;
	union geoip_key key = { };

	if (family == AF_INET6) {
		key.data.family = AF_INET6;
		key.data.addr.in6 = *(struct in6_addr *)addr;
	}
	else {
		key.data.family = AF_INET;
		key.data.addr.in = *(struct in_addr *)addr;
	}

	ptr = avl_find_element(&geoip_avl, &key, tmp, node);

	if (!ptr) {
		MMAP_CACHE_GET_NEXT(ptr, geoip, GEOIP_MMAP_CACHE_SIZE, format_geoip_ip_key);
		ptr->key = key;
		ptr->node.key = &ptr->key;
		MMAP_CACHE_INSERT(ptr, geoip);
	}

	return ptr;
}

static void geoip_send_next_data()
{
	assert(geoip_state == GEOIP_STATE_IDLE);
	assert(IpInfoToken);

	if (list_empty(&requests_queue)) return;

	char url[128];
	char data[(INET6_ADDRSTRLEN+3)*MAX_ADDRS_IN_TRANS] = "[";

	struct geoip_req *req;
	
	req = list_first_entry(&requests_queue, struct geoip_req, list);
	list_del(&req->list);

	int itr = 1;
	for (int i=0; i<req->cnt; ++i) {
		if ((i+1) < req->cnt) itr += sprintf(data+itr, "\"%s\",", req->addrs[i]);
		else itr += sprintf(data+itr, "\"%s\"]", req->addrs[i]);
	}

	free(req);
	snprintf(url, sizeof(url), "/batch?token=%s", IpInfoToken);
	https_send_msg(geoip_https_ctx, url, data, "application/x-www-form-urlencoded");

	geoip_state = GEOIP_STATE_IN_PROG;
	ipinfo_content_len = -1;
	ipinfo_data_ctr = 0;
}

static int geoip_on_data_cb(struct ustream *s, int eof)
{
	char *newline, *str;
	int len;

	do {
		str = ustream_get_read_buf(s, &len);
		if (!str) {
			if (eof && (geoip_state != GEOIP_STATE_READ_ERROR)) {
				geoip_state = GEOIP_STATE_IDLE;
				debug_printf("End of data\n");
			}
			break;
		}

		if (geoip_state == GEOIP_STATE_READ_ERROR) {
			char *str_itr, *end;
			newline = memchr(str, '\n', len);
			if (!newline) break;

			debug_printf("%s\n", str);
			ustream_consume(s, newline + 1 - str);
			if ((str_itr = strstr(str, "\"title\":"))) {
				str_itr += 8;
				str = strchr(str_itr, '"') + 1;
				end = strchr(str, '"');
				*end = 0;

				char msg[255];
				snprintf(msg, sizeof(msg), "Error in ipinfo.io API: %s\nAPI will not be used until service restart.\n", str);
				tg_send_msg(msg);
			}

		} else {
			newline = memchr(str, '\n', len);
			if (!newline) {
				if (eof) {
					geoip_state = GEOIP_STATE_IDLE;
					debug_printf("End of data\n");
					ustream_consume(s, len);
				}
				break;
			}

			*newline = 0;
			debug_printf("%s\n", str);
			ustream_consume(s, newline + 1 - str);
			ipinfo_data_ctr += newline + 1 - str;

			if ((strstr(str, "\"error\":"))) {
				geoip_state = GEOIP_STATE_READ_ERROR;

			} else if (strstr(str, ": {")) {
				char *end;
				union geoip_key key = { };

				str = strchr(str, '"') + 1;
				end = strchr(str, '"');
				*end = 0;
				ipinfo_cur_entry = NULL;

				if (strchr(str, ':')) {
					if (inet_pton(AF_INET6, str, &key.data.addr.in6)) {
						key.data.family = AF_INET6;
					} else {
						debug_printf("Can't parse IP addr: %s\n", str);
					}
				} else {
					if (inet_pton(AF_INET, str, &key.data.addr.in.s_addr)) {
						key.data.family = AF_INET;
						key.data.addr.in.s_addr = be32toh(key.data.addr.in.s_addr);
					} else {
						debug_printf("Can't parse IP addr: %s\n", str);
					}
				}

				if (key.data.family) {
					struct geoip_entry *tmp;

					ipinfo_cur_entry = avl_find_element(&geoip_avl, &key, tmp, node);

					if (!ipinfo_cur_entry) {
						error_printf("Error - Can't find a req IP in internal DB - %s\n", str);
						tg_send_msg("Can't find a req IP in internal DB");
					} else {
						//FIXME this marks the entry as resolved. Should detect end of parsing and then
						//mark as done if country is not set.
						assert(ipinfo_cur_entry->country[0] == 0);
						assert(ipinfo_cur_entry->country[1] == 1);
						ipinfo_cur_entry->country[1] = 2;
					}
				}

			} else if (ipinfo_cur_entry) {
				char *str_itr, *end;
				if (strstr(str, "\"bogon\":") && strcasestr(str, "true")) {
					ipinfo_cur_entry->country[0] = 0;
					ipinfo_cur_entry->country[1] = 9;
				} else if ((str_itr = strstr(str, "\"country\":"))) {
					str_itr += 10;
					str = strchr(str_itr, '"') + 1;
					end = strchr(str, '"');
					*end = 0;
					assert(strlen(str) == 2);
					memcpy(ipinfo_cur_entry->country, str, 2);
				} else if ((str_itr = strstr(str, "\"loc\":"))) {
					char *lon, *lat;

					str_itr += 5;
					lon = strchr(str_itr, '"') + 1;
					lat = strchr(lon, ',');
					*lat = 0;
					lat++;
					end = strchr(lat, '\"');
					*end = 0;
					ipinfo_cur_entry->lonlat[0] = (int)(atof(lon)*1000000);
					ipinfo_cur_entry->lonlat[1] = (int)(atof(lat)*1000000);
				} else if ((str_itr = strstr(str, "\"org\":"))) {
					str_itr += 5;
					str = strchr(str_itr, '"') + 1;
					end = strchr(str, '"');
					while (*(end-1) == '\\') end = strchr(end+1, '"');
					*end = 0;
					if ((str[0] != 'A') || (str[1] != 'S')) {
						debug_printf("Can't parse ASN number: %s\n", str);
					} else {
						ipinfo_cur_entry->asn = atoi(str + 2);
						asn_add(ipinfo_cur_entry->asn, str);
					}
				}
			}

		}

	} while(1);
	
	if ((geoip_state == GEOIP_STATE_IDLE) && !list_empty(&requests_queue)) geoip_send_next_data();

	return 0;
}

/* addr is in host order */
int geoip_lookup(struct record *rec)
{
	struct geoip_req *req = NULL;

	if (!IpInfoToken) return -ENOENT;

	struct geoip_entry *entry = _db_lookup_geoip(rec->family, &rec->last_ext_addr);

	if (entry) {
		if (!entry->country[0]) {
			if (entry->country[1] == 1) {
				// In queue for resolve.
				return -EAGAIN;
			} else if (entry->country[1] == 9) {
				// Bogon IP
				return -EINVAL;
			} else if (entry->country[1] == 2) {
				// No data for this IP
				return -ENOENT;
			}
		} else {
			memcpy(rec->country, entry->country, sizeof(rec->country));
			memcpy(rec->lonlat, entry->lonlat, sizeof(rec->lonlat));
			rec->asn = entry->asn;
			return 0;
		}
	}

	debug_printf("geoip_lookup - API request for address %s\n", format_ipaddr(rec->family, &rec->last_ext_addr, 1));
	entry->country[1] = 1;
	if (!list_empty(&requests_queue)) req = list_last_entry(&requests_queue, struct geoip_req, list);

	if (!req || (req->cnt == MAX_ADDRS_IN_TRANS)) {
		req = calloc(1, sizeof(*req));
		list_add_tail(&req->list, &requests_queue);
	}

	strcpy(req->addrs[req->cnt], format_ipaddr(rec->family, &rec->last_ext_addr, 1));
	req->cnt++;

	if (geoip_state == GEOIP_STATE_IDLE) {
		geoip_send_next_data();
	}

	return -EAGAIN;
}

static int
avl_cmp_geoip(const void *k1, const void *k2, void *ptr)
{
	union geoip_key *a = (union geoip_key *)k1;
	union geoip_key *b = (union geoip_key *)k2;

	return  memcmp(a->u32, b->u32, sizeof(a->u32));
}

static int geoip_mmap_persist(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(geoip, GEOIP_MMAP_CACHE_SIZE, path, 0);
	return 0;
}

static int geoip_archive(const char *path, uint32_t timestamp)
{
	int new_idx = 0;
	for (int i = 0; i < geoip_mmap_db_len; i++) {
		if (geoip_db[i].node.key && geoip_db[i].country[1] == 1) {
			if (i != new_idx) {
				struct geoip_entry swap = geoip_db[new_idx];
				geoip_db[new_idx] = geoip_db[i];
				geoip_db[i] = swap;
			}
			new_idx++;
		}
	}

	if (new_idx == 0) {
		MMAP_CACHE_RESET(geoip, avl_cmp_geoip);
	} else {
		memset(geoip_db + new_idx, 0,
		       sizeof(struct geoip_entry) * (geoip_mmap_db_len - new_idx));
		*geoip_mmap_next_entry = new_idx;
		geoip_mmap_db_len = new_idx;
		avl_init(&geoip_avl, avl_cmp_geoip, false, NULL);
		for (int i = 0; i < geoip_mmap_db_len; i++) {
			geoip_db[i].node.key = &geoip_db[i].key;
			avl_insert(&geoip_avl, &geoip_db[i].node);
		}
	}

	MMAP_CACHE_SAVE(geoip, GEOIP_MMAP_CACHE_SIZE, path, 0);
	return 0;
}

int geoip_is_bogon(const char *country)
{
	return (country[0] == 0) && (country[1] == 9);
}

int init_geoip_mmap(const char *db_path)
{
	nlbwmon_add_presistence_cb(geoip_mmap_persist);
	database_add_archive_cb(geoip_archive);

	MMAP_CACHE_INIT(geoip, GEOIP_MMAP_CACHE_SIZE, avl_cmp_geoip, key, format_geoip_ip_key);
	if (!geoip_db) return -errno;

	if (geoip_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(geoip, GEOIP_MMAP_CACHE_SIZE, key, db_path, 0, format_geoip_ip_key);
	}

	//Retry failed geoip entries
	for (int i=0; i<geoip_mmap_db_len; ++i) {
		if (geoip_db[i].node.key && !geoip_db[i].country[0] && (geoip_db[i].country[1] != 9)) {
			geoip_db[i].country[1] = 0;
		}
	}

	const char *token = config_get("ipinfo_api_token");
	if (token) {
		IpInfoToken = strdup(token);
	} else {
		debug_printf("Missing ipinfo_api_token in config file. geo ip resolve is disabled.\n");
	}

	return 0;
}

static void geoip_on_https_error(void)
{
	error_printf("Error in ipinfo.io API: Unknown\nAPI will not be used until service restart.\n");
	tg_send_msg("Error in ipinfo.io API: Unknown\nAPI will not be used until service restart.\n");
	geoip_state = GEOIP_STATE_READ_ERROR;
}

static struct https_cbs geoip_https_cbs = {
	.data = geoip_on_data_cb,
	.error = geoip_on_https_error,
};
	
__attribute__((constructor)) static void init_geoip(void)
{
        geoip_https_ctx = https_init(&geoip_https_cbs, "ipinfo.io", 443, 10);
}

