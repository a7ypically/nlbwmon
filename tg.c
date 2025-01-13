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
#include <arpa/inet.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>

#include "nlbwmon.h"
#include "https.h"
#include "wans.h"
#include "protocol.h"
#include "asn.h"
#include "utils.h"
#include "hosts.h"
#include "dns.h"
#include "config.h"
#include "mmap_cache.h"
#include "notify.h"
#include "abuseipdb.h"
#include "tg.h"

#define TG_SEND_STATE_IDLE 0
#define TG_SEND_STATE_IN_PROG 1

#define TG_MSG_TYPE_TEXT 0
#define TG_MSG_TYPE_INPUT_NAME 1

#define TG_MSG_ID_TYPE_OUTGOING 1
#define TG_MSG_ID_TYPE_INCOMING 2
#define TG_MSG_ID_TYPE_UPLOAD   3
#define TG_MSG_ID_TYPE_CLIENT_INFO   4

#define TG_MSG_ID_FLAG_OUTGOING_NO_DNS 0x1

#define TG_MSG_ID_FLAG_CLIENT_INFO_SET_NAME 0x1
#define TG_MSG_ID_FLAG_CLIENT_INFO_NEW      0x2
#define TG_MSG_ID_FLAG_PINNED 		    0x80

static int ChatID;
static char *TGBotToken;
static int tg_send_msg_state;
static int tg_send_errors;
static struct https_ctx *tg_send_https_ctx;
static int RefreshNum;

static struct uloop_timeout wait_input_tm = { };
static int tg_send_msg_wait_input;
static int TGNameReqMsgID;
static struct ether_addr TGNameReqAddr;

static char TGInlineKeys[20][50];
static int TGCallbackStateMsgID = -1;
static uint8_t TGCallbackState[10];

struct tg_send_req {
	struct list_head list;
	uint8_t type;
	char *msg;
	int message_id;
};

static LIST_HEAD(requests_queue);

struct record_key {
	uint8_t family;
	uint8_t proto;
	uint16_t dst_port;
	union {
		struct ether_addr ea;
		uint64_t u64;
	} src_mac;
	union {
		struct in6_addr in6;
		struct in_addr in;
		uint8_t wan_idx;
	} src_addr;
	uint8_t type;
	char country[2];
	int32_t lonlat[2];
	uint16_t asn;
	uint16_t topl_domain;
};

struct tg_msg_entry {
	int message_id;
	uint8_t type;
	uint8_t flags;
	uint8_t notify_flag;
	struct record_key rec_key;
	struct in6_addr ext_addr;
	struct avl_node node;
};

static struct tg_msg_entry *TGCurrentMsg;
static int TGNextMsgIDToSend = -1;

#define TG_MMAP_CACHE_SIZE 500
DEFINE_MMAP_CACHE(tg_msg);

static int RefreshMsgQueue[TG_MMAP_CACHE_SIZE];
static int RefreshMsgQueueHead = 0;
static int RefreshMsgQueueTail = 0;

static const char *CallbackMsgReply;
static char *CallbackQueryID;

static void tg_msg_wait_input_timer_cb(struct uloop_timeout *tm);

static char *get_flag_emoji(const char *code) {
	static char unicode[9];
	if (!code[0]) return "";
	unicode[0] = unicode[4] = 0xf0;
	unicode[1] = unicode[5] = 0x9f;
	unicode[2] = unicode[6] = 0x87;
	unicode[3] = code[0] - 'A' + 0xa6;
	unicode[7] = code[1] - 'A' + 0xa6;

	return unicode;
}

static void tg_add_inline_key(int *itr, const char *name, const char *param)
{
	if (!strcmp(name, "Refresh")) {
		strcpy(TGInlineKeys[(*itr)++], "Refresh");
		snprintf(TGInlineKeys[(*itr)++], sizeof(TGInlineKeys[0]), "Refresh%d", RefreshNum++ % 1000);
		return;
	}

	if (!strcmp(name, "Name")) {
		if (param) {
			strcpy(TGInlineKeys[(*itr)++], "Rename");
		} else {
			strcpy(TGInlineKeys[(*itr)++], "Set name");
		}
		strcpy(TGInlineKeys[(*itr)++], "name");
		return;
	}

	strncpy(TGInlineKeys[*itr], name, sizeof(TGInlineKeys[0])-1);
	TGInlineKeys[*itr][sizeof(TGInlineKeys[0])-1] = 0;
	++(*itr);
	strncpy(TGInlineKeys[*itr], param, sizeof(TGInlineKeys[0])-1);
	TGInlineKeys[*itr][sizeof(TGInlineKeys[0])-1] = 0;
	++(*itr);
}


static void tg_api_reply_callback(void)
{
	char url[128];
	char data[768];

	assert(tg_send_msg_state == TG_SEND_STATE_IDLE);
	assert(ChatID && TGBotToken);
	assert(CallbackQueryID);

	int data_len;

	if (CallbackMsgReply) {
		data_len = snprintf(data, sizeof(data), "callback_query_id=%s&text=%s", CallbackQueryID, urlencode(CallbackMsgReply));
		assert(data_len < sizeof(data));
	} else {
		data_len = snprintf(data, sizeof(data), "callback_query_id=%s", CallbackQueryID);
		assert(data_len < sizeof(data));
	}
	_unused(data_len);

	free(CallbackQueryID);
	CallbackQueryID = NULL;
	CallbackMsgReply = NULL;

	int url_len = snprintf(url, sizeof(url), "/bot%s/answerCallbackQuery", TGBotToken);
	assert(url_len < sizeof(url));
	_unused(url_len);

	tg_send_msg_state = TG_SEND_STATE_IN_PROG;

	debug_printf("tg_api_reply_callback:\n%s\n%s\n", url, data);
	https_send_msg(tg_send_https_ctx, url, data, "application/x-www-form-urlencoded");
}

static void tg_api_send_msg(char *msg)
{
	char url[128];
	char data[4096];

	assert(tg_send_msg_state == TG_SEND_STATE_IDLE);
	assert(ChatID && TGBotToken);

	int data_len = snprintf(data, sizeof(data), "parse_mode=HTML&chat_id=%d&text=%s", ChatID, urlencode(msg));
	assert(data_len < sizeof(data));
	int url_len;

	if (TGCurrentMsg && (TGCurrentMsg->message_id != -1)) {
		data_len += snprintf(data + data_len, sizeof(data) - data_len, "&message_id=%d", TGCurrentMsg->message_id);
		assert(data_len < sizeof(data));
		if (TGCurrentMsg->message_id == TGCallbackStateMsgID) {
			data_len += snprintf(data + data_len, sizeof(data) - data_len, "&disable_web_page_preview=true");
			assert(data_len < sizeof(data));
		}
		url_len = snprintf(url, sizeof(url), "/bot%s/editMessageText", TGBotToken);
		assert(url_len < sizeof(url));
	} else {
		url_len = snprintf(url, sizeof(url), "/bot%s/sendMessage", TGBotToken);
		assert(url_len < sizeof(url));
	}
	_unused(url_len);

	if (TGInlineKeys[0][0]) {
		char inline_keyboard[512];

		int inline_len = snprintf(inline_keyboard, sizeof(inline_keyboard), "{\"inline_keyboard\": [[");
		assert(inline_len < sizeof(inline_keyboard));

		int is_first_in_line = 1;
		for (int i=0; i<sizeof(TGInlineKeys) / sizeof(TGInlineKeys[0]) / 2; ++i) {
			if (!TGInlineKeys[i*2][0]) break;
			if (TGInlineKeys[i*2][0] == '\n') {
				inline_len += snprintf(inline_keyboard + inline_len, sizeof(inline_keyboard) - inline_len, "], [");
				assert(inline_len < sizeof(inline_keyboard));
				is_first_in_line = 1;
			} else {
				inline_len += snprintf(inline_keyboard + inline_len, sizeof(inline_keyboard) - inline_len, "%s{\"text\": \"%s\", \"callback_data\": \"%s\"}", !is_first_in_line ? ", " : "", TGInlineKeys[i*2], TGInlineKeys[i*2+1]);
				assert(inline_len < sizeof(inline_keyboard));
				is_first_in_line = 0;
			}
		}

		inline_len += snprintf(inline_keyboard + inline_len, sizeof(inline_keyboard) - inline_len, "]]}");
		assert(inline_len < sizeof(inline_keyboard));

		data_len += snprintf(data + data_len, sizeof(data) - data_len, "&reply_markup=%s", urlencode(inline_keyboard));
		assert(data_len < sizeof(data));
		memset(TGInlineKeys, 0, sizeof(TGInlineKeys));
	}

	tg_send_msg_state = TG_SEND_STATE_IN_PROG;

	debug_printf("tg_api_send_msg:\n%s\n%s\n", url, data);
	https_send_msg(tg_send_https_ctx, url, data, "application/x-www-form-urlencoded");
}

static void tg_format_inline_keys(struct tg_msg_entry *msg, char *msg_str, int msg_size)
{
	int keys = 0;
	int len;
	char str[100];

	if (TGCallbackState[0] == 1) {
		if (TGCallbackState[1] == 0) {
			if (msg->rec_key.topl_domain) {
				snprintf(str, sizeof(str), "%s", dns_get_topl(msg->rec_key.topl_domain));
				tg_add_inline_key(&keys, str, "2");
				tg_add_inline_key(&keys, "\n", "");
			}
			snprintf(str, sizeof(str), "%s", lookup_asn(msg->rec_key.asn));
			tg_add_inline_key(&keys, str, "1");
			tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, "any org or host", "9");
			tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, "Cancel", "cancel");
			snprintf(msg_str, msg_size, "\n\n%c%c%c%c <b>Mute notifications for %s org or domain...</b>", 0Xf0, 0X9f, 0X91, 0X89, msg->rec_key.type & RECORD_TYPE_WAN_IN ? "inbound connections from": "outbound connections to");
			return;
		}

		const char *host_or_org = "any host or org";
		if (TGCallbackState[1] == 1) host_or_org = lookup_asn(msg->rec_key.asn);
		else if (TGCallbackState[1] == 2) host_or_org = dns_get_topl(msg->rec_key.topl_domain);

		len = snprintf(msg_str, msg_size, "\n\n%c%c%c%c <b>Mute notifications for %s %s ", 0Xf0, 0X9f, 0X91, 0X89,
				msg->rec_key.type & RECORD_TYPE_WAN_IN ? "inbound connections from": "outbound connections to",
				host_or_org);
		msg_size -= len;
		msg_str += len;
		assert(msg_size > 0);
		
		if (TGCallbackState[2] == 0) {
			if (msg->rec_key.country[0]) {
				snprintf(str, sizeof(str), "%c%c %s", msg->rec_key.country[0], msg->rec_key.country[1], get_flag_emoji(msg->rec_key.country));
				tg_add_inline_key(&keys, str, "1");
				tg_add_inline_key(&keys, "\n", "");
			}
			tg_add_inline_key(&keys, "any country", "9");
			tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, "Cancel", "cancel");
			snprintf(msg_str, msg_size, "in the country...</b>");
			return;
		}

		char country_str[16];
		if (TGCallbackState[2] == 1) snprintf(country_str, sizeof(country_str), "%c%c %s ", msg->rec_key.country[0], msg->rec_key.country[1], get_flag_emoji(msg->rec_key.country));
		else strcpy(country_str, "any country ");
		len = snprintf(msg_str, msg_size, "in %s", country_str);
				
		msg_size -= len;
		msg_str += len;
		assert(msg_size > 0);

		if (TGCallbackState[3] == 0) {
			snprintf(str, sizeof(str), "%s", get_protocol_name(msg->rec_key.proto, ntohs(msg->rec_key.dst_port)));
			tg_add_inline_key(&keys, str, "1");
			tg_add_inline_key(&keys, "\n", "");
			if (msg->rec_key.proto == 17) {
				snprintf(str, sizeof(str), "%s any port", get_protocol_name(msg->rec_key.proto, 0));
				tg_add_inline_key(&keys, str, "2");
			}
			tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, "any protocol", "9");
			tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, "Cancel", "cancel");

			snprintf(msg_str, msg_size, "using protocol...</b>");
			return;
		}

		if (TGCallbackState[3] == 1) {
			snprintf(str, sizeof(str), "%s", get_protocol_name(msg->rec_key.proto, ntohs(msg->rec_key.dst_port)));
		} else {
			snprintf(str, sizeof(str), "%s any port", get_protocol_name(msg->rec_key.proto, 0));
		}

		len = snprintf(msg_str, msg_size, "using %s ",
				TGCallbackState[3] != 9 ? str: "any protocol");
				
		msg_size -= len;
		msg_str += len;
		assert(msg_size > 0);

		char client_name_str[MAX_HOST_NAME + INET6_ADDRSTRLEN + 10];
		if (msg->rec_key.type & RECORD_TYPE_WAN) {
			snprintf(client_name_str, sizeof(client_name_str), "WAN %s", get_wan_name(msg->rec_key.src_addr.wan_idx));
		} else {
			const char *client_name = lookup_hostname(&msg->rec_key.src_mac.ea);
			if (client_name) {
				strcpy(client_name_str, client_name);
			} else {
				strcpy(client_name_str, format_macaddr(&msg->rec_key.src_mac.ea));
			}
		}

		if (TGCallbackState[4] == 0) {
			snprintf(str, sizeof(str), "%s", client_name_str);
			tg_add_inline_key(&keys, str, "1");
			tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, "any client", "9");
			tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, "Cancel", "cancel");

			snprintf(msg_str, msg_size, "%s client...</b>", msg->rec_key.type & RECORD_TYPE_WAN_IN ? "to" : "from");
			return;
		}

		len += snprintf(msg_str, msg_size, "%s %s.</b>",
				msg->rec_key.type & RECORD_TYPE_WAN_IN ? "to" : "from",
				TGCallbackState[4] == 1 ? client_name_str: "any client");
				
		msg_size -= len;
		msg_str += len;
		assert(msg_size > 0);

		if (TGCallbackState[5] == 0) {
			tg_add_inline_key(&keys, "Confirm", "1");
			tg_add_inline_key(&keys, "Cancel", "cancel");
			return;
		}

		assert(0);
	} else if (TGCallbackState[0] == 2) {
		const char *categories[] = {"Port Scan", "14", "Brute-Force", "18", "SSH", "22", "IoT Targeted", "23"};

		for (int i=0; i<sizeof(categories)/sizeof(categories[0])/2; ++i) {
			int cat_id = atoi(categories[i*2+1]);
			int exist = 0;
			for (int j=1; j<sizeof(TGCallbackState); ++j) {
				if (TGCallbackState[j] == cat_id) {
					exist = 1;
					break;
				}
			}
			if (exist) continue;

			if (!(keys % 6)) tg_add_inline_key(&keys, "\n", "");
			tg_add_inline_key(&keys, categories[i*2], categories[i*2+1]);
		}

		if (keys) tg_add_inline_key(&keys, "\n", "");
		if (TGCallbackState[1] != 0) {
			tg_add_inline_key(&keys, "Confirm", "99");
		}
		tg_add_inline_key(&keys, "Cancel", "cancel");
	}
}

static int tg_check_muted(struct record *r, uint8_t notify_flag, char *msg, int *len, int size)
{
	if (notify_is_muted(r, notify_flag, NULL)) {
		*len += snprintf(msg, size, "%c%c%c%c <b>MUTED</b>\n",0xf0, 0X9f, 0x94, 0x95);
		return 1;
	}

	return 0;
}

static const char *tg_get_country_str(const char *country)
{
	static char str[12];

	if (country[0]) {
		snprintf(str, sizeof(str), "%c%c %s", country[0], country[1], get_flag_emoji(country));
		return str;
	} else {
		return "??";
	}
}

static void tg_get_host_names(struct record *r, char *str, int size) {

	int count;

	assert(size > 0);
	for (count=0; count<RECORD_NUM_HOSTS; ++count) if (!r->hosts[count]) break;

	if (count == 0) {
		str[0] = 0;
		return;
	} else if (count == 1) {
		snprintf(str, size, "Host: <b>%s</b>\n", dns_get_by_id(r->hosts[0]));
		return;
	}

	int len = snprintf(str, size, "Remote hosts:\n");

	for (int i=0; i<RECORD_NUM_HOSTS; ++i) {
		if (!r->hosts[i]) break;
		const char *domain = dns_get_by_id(r->hosts[i]);
		len += snprintf(str + len, size - len, "- %s\n", domain);
		if (len >= size) {
			str[size-4] = '.';
			str[size-3] = '.';
			str[size-2] = '\n';
			break;
		}
	}
}

static void tg_format_incoming(struct record *r, struct tg_msg_entry *tg_msg)
{
	char msg[1024];
	const char *client_name = NULL;
	char *ext_str = strdup(format_ipaddr(r->family, &r->last_ext_addr, 1));
	int len = 0;

	tg_check_muted(r, tg_msg->notify_flag, msg, &len, sizeof(msg));

	len += snprintf(msg+len, sizeof(msg)-len, "%c%c%c%c <b>INBOUND</b> connection from %s\n", 0xf0, 0x9f, 0x94, 0xbd, tg_get_country_str(r->country));

	char info[128] = {};
	if (r && (tg_msg->message_id != -1)) {
		snprintf(info, sizeof(info), "Conns:%ld In:%.1fMB Out:%.1fMB\n", be64toh(r->count), (float)be64toh(r->in_bytes)/(1024*1024), (float)be64toh(r->out_bytes)/(1024*1024));
	}

	if (r->type & RECORD_TYPE_WAN) {
		len += snprintf(msg + len, sizeof(msg) - len, "To %c%c%c%c<b>OpenWrt</b> router (<b>%s</b>)\nUsing <b>%s</b>\n%s\n%s<a href=\"https://www.abuseipdb.com/check/%s\">abuseipdb.com/check/%s</a>", 0xf0, 0X9f, 0X9a, 0Xa5, get_wan_name(r->src_addr.wan_idx), get_protocol_name(r->proto, ntohs(r->dst_port)), lookup_asn(r->asn), info, ext_str, ext_str);
	} else {
		char client_name_str[MAX_HOST_NAME + INET6_ADDRSTRLEN + 10];
		client_name = lookup_hostname(&r->src_mac.ea);
		if (client_name) {
			sprintf(client_name_str, "<b>%s</b> (%s)", client_name, format_ipaddr(r->family, &r->src_addr, 1));
		} else {
			strcpy(client_name_str, format_ipaddr(r->family, &r->src_addr, 1));
		}
		len += snprintf(msg + len, sizeof(msg) - len, "To %s\nUsing <b>%s</b>\n%s\n%s<a href=\"https://www.abuseipdb.com/check/%s\">abuseipdb.com/check/%s</a>", client_name_str, get_protocol_name(r->proto, ntohs(r->dst_port)), lookup_asn(r->asn), info, ext_str, ext_str);
	}

	free(ext_str);

	if ((TGCallbackStateMsgID != -1) && (tg_msg->message_id == TGCallbackStateMsgID)) {
		tg_format_inline_keys(tg_msg, msg + len, sizeof(msg) - len);
	} else {
		int keys = 0;
		tg_add_inline_key(&keys, "Refresh", NULL);
		if (!(r->type & RECORD_TYPE_WAN)) tg_add_inline_key(&keys, "Name", client_name);
		tg_add_inline_key(&keys, "Mute...", "mute");
		if (abuseipdb_enabled()) tg_add_inline_key(&keys, "Report", "report");
	}

	tg_api_send_msg(msg);
}

static void tg_format_outgoing(struct record *r, struct tg_msg_entry *tg_msg)
{
	char msg[1024];
	const char *client_name = NULL;
	char *ext_str = strdup(format_ipaddr(r->family, &r->last_ext_addr, 1));
	char domains[256];
	int len = 0;

	tg_get_host_names(r, domains, sizeof(domains));

	tg_check_muted(r, tg_msg->notify_flag, msg, &len, sizeof(msg));

	if (tg_msg->flags & TG_MSG_ID_FLAG_OUTGOING_NO_DNS) {
		len += snprintf(msg+len, sizeof(msg)-len, "%c%c%c%c <b>No DNS</b> for outbound connection to %s\n", 0xf0, 0x9f, 0x8c, 0x90, tg_get_country_str(r->country));
	} else {
		len += snprintf(msg+len, sizeof(msg)-len, "%c%c%c%c <b>OUTBOUND</b> connection to %s\n", 0xf0, 0x9f, 0x94, 0xba, tg_get_country_str(r->country));
	}

	char info[128] = {};
	if (r && (tg_msg->message_id != -1)) {
		snprintf(info, sizeof(info), "Conns:%ld In:%.1fMB Out:%.1fMB\n", be64toh(r->count), (float)be64toh(r->in_bytes)/(1024*1024), (float)be64toh(r->out_bytes)/(1024*1024));
	}

	if (r->type & RECORD_TYPE_WAN) {
		len += snprintf(msg + len, sizeof(msg) - len, "From %c%c%c%c<b>OpenWrt</b> router (<b>%s</b>)\nUsing <b>%s</b>\n%s%s\n%s<a href=\"https://www.abuseipdb.com/check/%s\">abuseipdb.com/check/%s</a>", 0xf0, 0X9f, 0X9a, 0Xa5, get_wan_name(r->src_addr.wan_idx), get_protocol_name(r->proto, ntohs(r->dst_port)), domains, lookup_asn(r->asn), info, ext_str, ext_str);
	} else {
		char client_name_str[MAX_HOST_NAME + INET6_ADDRSTRLEN + 10];
		client_name = lookup_hostname(&r->src_mac.ea);
		if (client_name) {
			sprintf(client_name_str, "<b>%s</b> (%s)", client_name, format_ipaddr(r->family, &r->src_addr, 1));
		} else {
			strcpy(client_name_str, format_ipaddr(r->family, &r->src_addr, 1));
		}
		len += snprintf(msg + len, sizeof(msg) - len, "From %s\nUsing <b>%s</b>\n%s%s\n%s<a href=\"https://www.abuseipdb.com/check/%s\">abuseipdb.com/check/%s</a>", client_name_str, get_protocol_name(r->proto, ntohs(r->dst_port)), domains, lookup_asn(r->asn), info, ext_str, ext_str);
	}
	free(ext_str);

	if ((TGCallbackStateMsgID != -1) && (tg_msg->message_id == TGCallbackStateMsgID)) {
		tg_format_inline_keys(tg_msg, msg + len, sizeof(msg) - len);
	} else {
		int keys = 0;
		tg_add_inline_key(&keys, "Refresh", NULL);
		if (!(r->type & RECORD_TYPE_WAN)) tg_add_inline_key(&keys, "Name", client_name);
		tg_add_inline_key(&keys, "Mute...", "mute");
	}

	tg_api_send_msg(msg);
}

static void tg_format_upload(struct record *r, struct tg_msg_entry *tg_msg)
{
	char msg[1024];
	const char *client_name = NULL;
	char *ext_str = strdup(format_ipaddr(r->family, &r->last_ext_addr, 1));
	char domains[256];
	int len = 0;

	tg_get_host_names(r, domains, sizeof(domains));
	tg_check_muted(r, tg_msg->notify_flag, msg, &len, sizeof(msg));

	char emoji[] = {0xf0, 0x9f, 0x94, 0xba,
		0xf0, 0x9f, 0x94, 0xba,
		0xf0, 0x9f, 0x94, 0xba, 0};

	len += snprintf(msg+len, sizeof(msg)-len, "%s <b>Significant outbound data</b> to %s\n", emoji, tg_get_country_str(r->country));

	char info[128] = {};
	snprintf(info, sizeof(info), "Conns:%ld In:%.1fMB Out:%.1fMB\n", be64toh(r->count), (float)be64toh(r->in_bytes)/(1024*1024), (float)be64toh(r->out_bytes)/(1024*1024));

	if (r->type & RECORD_TYPE_WAN) {
		len += snprintf(msg + len, sizeof(msg) - len, "From %c%c%c%c<b>OpenWrt</b> router (<b>%s</b>)\n%sUsing <b>%s</b>\n%s%s\n<a href=\"https://www.abuseipdb.com/check/%s\">abuseipdb.com/check/%s</a>", 0xf0, 0X9f, 0X9a, 0Xa5, get_wan_name(r->src_addr.wan_idx), info, get_protocol_name(r->proto, ntohs(r->dst_port)), domains, lookup_asn(r->asn), ext_str, ext_str);
	} else {
		char client_name_str[MAX_HOST_NAME + INET6_ADDRSTRLEN + 10];
		client_name = lookup_hostname(&r->src_mac.ea);
		if (client_name) {
			sprintf(client_name_str, "<b>%s</b> (%s)", client_name, format_ipaddr(r->family, &r->src_addr, 1));
		} else {
			strcpy(client_name_str, format_ipaddr(r->family, &r->src_addr, 1));
		}
		len += snprintf(msg + len, sizeof(msg) - len, "From %s\n%sUsing <b>%s</b>\n%s%s\n<a href=\"https://www.abuseipdb.com/check/%s\">abuseipdb.com/check/%s</a>", client_name_str, info, get_protocol_name(r->proto, ntohs(r->dst_port)), domains, lookup_asn(r->asn), ext_str, ext_str);
	}
	free(ext_str);

	if ((TGCallbackStateMsgID != -1) && (tg_msg->message_id == TGCallbackStateMsgID)) {
		tg_format_inline_keys(tg_msg, msg + len, sizeof(msg) - len);
	} else {
		int keys = 0;
		tg_add_inline_key(&keys, "Refresh", NULL);
		if (!(r->type & RECORD_TYPE_WAN)) tg_add_inline_key(&keys, "Name", client_name);
		tg_add_inline_key(&keys, "Mute...", "mute");
	}

	tg_api_send_msg(msg);
}

static void tg_format_client_info(struct record *r, struct tg_msg_entry *tg_msg)
{
	char msg[1024];
	int len = 0;

	assert(!(tg_msg->rec_key.type & RECORD_TYPE_WAN));
	assert(tg_msg->rec_key.src_mac.u64);

	const char *client_name = lookup_hostname(&tg_msg->rec_key.src_mac.ea);
	char host_emoji[] = {0Xf0, 0X9f, 0X8c, 0x90, 0};
	char new_emoji[] = {0Xf0, 0X9f, 0x86, 0x95, 0};

	if (tg_msg->flags & TG_MSG_ID_FLAG_CLIENT_INFO_NEW) {
		if (tg_msg->notify_flag == 1) {
			len = snprintf(msg, sizeof(msg), "%s <b>HOST INFO</b>\n", host_emoji);
		} else {
			len = snprintf(msg, sizeof(msg), "%s <b>NEW CLIENT</b>\n", new_emoji);
		}
	}

	if (client_name) {
		len += snprintf(msg+len, sizeof(msg) - len, "%s <b>%s</b> (%s)\n", host_emoji, client_name, format_macaddr(&tg_msg->rec_key.src_mac.ea));
	} else {
		len += snprintf(msg+len, sizeof(msg) - len, "%s %s\n", host_emoji, format_macaddr(&tg_msg->rec_key.src_mac.ea));
	}
	assert(len < sizeof(msg));

	struct record *rec = NULL;

	char client_ips[256];
	int ips_len = sprintf(client_ips, "\nIPs:\n");

	char domains[256] = {};
	int domains_len = 0;

	uint64_t in_bytes = 0, out_bytes = 0, conns = 0;

	while ((rec = database_next(gdbh, rec)) != NULL) {
		if (rec->src_mac.u64 != tg_msg->rec_key.src_mac.u64) continue;
		in_bytes += be64toh(rec->in_bytes);
		out_bytes += be64toh(rec->out_bytes);
		conns += be64toh(rec->count);

		char *ip_str = format_ipaddr(rec->family, &rec->src_addr, 1);
		if (!strstr(client_ips, ip_str)) {

			ips_len += snprintf(client_ips + ips_len, sizeof(client_ips) - ips_len, "- %s\n", ip_str);
			assert(ips_len < sizeof(client_ips));
		}

		if (domains_len < sizeof(domains)) {
			for (int i=0; i<RECORD_NUM_HOSTS; ++i) {
				if (!rec->hosts[i]) break;
				const char *domain = dns_get_by_id(rec->hosts[i]);
				if (strstr(domains, domain)) continue;

				domains_len += snprintf(domains + domains_len, sizeof(domains) - domains_len, "- %s\n", domain);
				if (domains_len >= sizeof(domain)) {
					domains[sizeof(domains)-4] = '.';
					domains[sizeof(domains)-3] = '.';
					domains[sizeof(domains)-2] = '\n';
					break;
				}
			}
		}
	}

	len += snprintf(msg + len, sizeof(msg) - len, "%s", client_ips);
	assert(len < sizeof(msg));

	if (domains_len) {
		len += snprintf(msg + len, sizeof(msg) - len, "\nRemote hosts:\n%s\n", domains);
		assert(len < sizeof(msg));
	}

	len += snprintf(msg + len, sizeof(msg) - len, "Conns:%ld In:%.1fMB Out:%.1fMB\n", conns, (float)in_bytes/(1024*1024), (float)out_bytes/(1024*1024));
	int keys = 0;

	if (tg_msg->flags & TG_MSG_ID_FLAG_CLIENT_INFO_SET_NAME) {
		TGNameReqAddr = tg_msg->rec_key.src_mac.ea;

		tg_msg->flags &= ~TG_MSG_ID_FLAG_CLIENT_INFO_SET_NAME;
		len += snprintf(msg + len, sizeof(msg) - len, "\n%c%c%c%c <b>Please type your preferred client name:</b>", 0Xf0, 0X9f, 0X91, 0X89);
		assert(len < sizeof(msg));

		tg_add_inline_key(&keys, "Cancel", "cancel");

		assert(!tg_send_msg_wait_input);
		tg_send_msg_wait_input = 1;
		TGNameReqMsgID = tg_msg->message_id;
		wait_input_tm.cb = tg_msg_wait_input_timer_cb;
		uloop_timeout_set(&wait_input_tm, 30 * 1000);
	} else {
		tg_add_inline_key(&keys, "Refresh", NULL);
		tg_add_inline_key(&keys, "Name", client_name);
	}

	tg_api_send_msg(msg);
}

static void tg_send_next_msg(void)
{
	if (!ChatID || !TGBotToken) return;

	if (tg_send_msg_state != TG_SEND_STATE_IDLE) return;

	assert(!TGCurrentMsg);

	if (CallbackQueryID) {
		tg_api_reply_callback();
		return;
	}

	if (tg_send_msg_wait_input) return;
	
	struct tg_msg_entry *msg = NULL;

	if (RefreshMsgQueueHead != RefreshMsgQueueTail) {
		int message_id = RefreshMsgQueue[RefreshMsgQueueHead];
		RefreshMsgQueueHead = (RefreshMsgQueueHead + 1) % TG_MMAP_CACHE_SIZE;

		struct tg_msg_entry *tmp;

		msg = avl_find_element(&tg_msg_avl, &message_id, tmp, node);

		if (!msg) {
			error_printf("Error - tg_send_next_msg can not find msg with message_id:%d\n", message_id);
			tg_send_next_msg();
			return;
		}
	}


	if (!msg && !list_empty(&requests_queue)) {

		struct tg_send_req *req;
		req = list_first_entry(&requests_queue, struct tg_send_req, list);
		list_del(&req->list);
		tg_api_send_msg(req->msg);
		free(req->msg);
		free(req);

		return;
	}

	if (!msg && (TGNextMsgIDToSend >= 0)) {
		msg = tg_msg_db + TGNextMsgIDToSend;

		TGNextMsgIDToSend = (TGNextMsgIDToSend + 1) % TG_MMAP_CACHE_SIZE;

		if (TGNextMsgIDToSend == *tg_msg_mmap_next_entry) {
			TGNextMsgIDToSend = -1;
		}
	}

	if (msg) {

		struct record *r = NULL;

		if (msg->type != TG_MSG_ID_TYPE_CLIENT_INFO) {

			r = database_find(&msg->rec_key, sizeof(msg->rec_key));

			if (!r) {
				error_printf("Error - tg_send_next_msg can not find db record\n");
				tg_send_next_msg();
				return;
			}
		}

		TGCurrentMsg = msg;

		switch (msg->type) {
			case TG_MSG_ID_TYPE_OUTGOING:
				tg_format_outgoing(r, msg);
				break;
			case TG_MSG_ID_TYPE_INCOMING:
				tg_format_incoming(r, msg);
				break;
			case TG_MSG_ID_TYPE_UPLOAD:
				tg_format_upload(r, msg);
				break;
			case TG_MSG_ID_TYPE_CLIENT_INFO:
				tg_format_client_info(r, msg);
				break;
		}
	}
}

static int tg_send_on_data_cb(struct ustream *s, int eof)
{
	char *buf;
	int len;
	
	if (!eof) return 0;

	debug_printf("Ready to parse body\n");
	buf = ustream_get_read_buf(s, &len);

	//Break json to be able to use str funcs.
	//Better use json parser
	buf[len-1] = 0;
	debug_printf("%s\n", buf);
	if (!strstr(buf, "\"ok\":true")) {
		error_printf("TG send msg - Error:%s\n", buf);
		goto exit_on_error;
	}

	char *message_id_str = strstr(buf, "\"message_id\":");
	if (!message_id_str) {
		if (!TGCurrentMsg) goto exit_ok;

		error_printf("Error in TG send msg. Can not parse message_id - %s\n", buf);
		tg_send_msg("Error in TG send msg. Can not parse message_id.");
		goto exit_on_error;
	}

	message_id_str += 13;
	int message_id = atoi(message_id_str);

	if (TGCurrentMsg && !strstr(buf, "\"edit_date\"")) {
		TGCurrentMsg->message_id = message_id;
		TGCurrentMsg->node.key = &TGCurrentMsg->message_id;
		debug_printf("tg_send_on_data_cb - adding message_id:%d to DB.\n", message_id);
		if (tg_send_msg_wait_input && !memcmp(&TGCurrentMsg->rec_key.src_mac.ea, &TGNameReqAddr, sizeof(TGNameReqAddr))) {
			TGNameReqMsgID = message_id;
		}

		MMAP_CACHE_INSERT(TGCurrentMsg, tg_msg);
	} else {
		debug_printf("tg_send_on_data_cb - TGCurrentMsg:%d edit_data:%d\n", TGCurrentMsg != NULL, strstr(buf, "\"edit_date\"") != NULL);
	}

exit_ok:
	TGCurrentMsg = NULL;
	ustream_consume(s, len);

	tg_send_errors = 0;

	tg_send_msg_state = TG_SEND_STATE_IDLE;
	tg_send_next_msg();

	return 0;

exit_on_error:
	ustream_consume(s, len);
	tg_send_errors++;
	if (tg_send_errors > 3) {
		error_printf("Error - Too many errors in sending TG msgs. Stopping until service restart.\n");
		return 0;
	}

	TGCurrentMsg = NULL;
	tg_send_msg_state = TG_SEND_STATE_IDLE;
	tg_send_next_msg();

	return -1;
}

int tg_send_msg(const char *msg)
{
	if (!TGBotToken) return -1;

	struct tg_send_req *req = calloc(1, sizeof(*req));
	list_add_tail(&req->list, &requests_queue);

	req->msg = strdup(msg);
	req->type = TG_MSG_TYPE_TEXT;

	if (!ChatID) {
		error_printf("TG has no chat ID. Please send a message to your bot.\n");
	} else if (tg_send_msg_state == TG_SEND_STATE_IDLE) {
		tg_send_next_msg();
	}

	return 0;
}

static void tg_send_on_https_error(void)
{
	tg_send_errors++;
	if (tg_send_errors < 3) {
		error_printf("Error sending TG msg. Will skip current messages and try the next ones..");
		TGCurrentMsg = NULL;
		tg_send_msg_state = TG_SEND_STATE_IDLE;
		tg_send_next_msg();
	} else {
		error_printf("Error sending TG msg. Will stop until service restart.");
	}
}

static struct https_cbs tg_send_https_cbs = {
	.data = tg_send_on_data_cb,
	.error = tg_send_on_https_error,
};
	
static void tg_send_msg_with_id(uint8_t type, uint8_t flags, struct record *r, struct tg_msg_entry *msg, uint8_t notify_flag)
{
	struct tg_msg_entry *ptr;

	if (!TGBotToken) return;

	// Don't reuse pinned messages
	if (tg_msg_mmap_db_len == TG_MMAP_CACHE_SIZE) {
		for (int i=0; i<TG_MMAP_CACHE_SIZE; ++i) {
			struct tg_msg_entry *m = tg_msg_db + *tg_msg_mmap_next_entry;
			if (!m->node.key || (!(m->flags & TG_MSG_ID_FLAG_PINNED))) break;
			*tg_msg_mmap_next_entry = (*tg_msg_mmap_next_entry + 1) % TG_MMAP_CACHE_SIZE;
		}
	}

	MMAP_CACHE_GET_NEXT(ptr, tg_msg, TG_MMAP_CACHE_SIZE, NULL);

	/* current implementation assumes that key == 0 is the end of the cache */
	ptr->message_id = -1;

	if (ptr == TGCurrentMsg) {
		error_printf("Error - tg_send_msg_with_id wrap around before send reponse\n");
		TGCurrentMsg = NULL;
	}

	int tg_msg_idx = MMAP_GET_IDX(tg_msg, ptr);

	if (tg_msg_idx == TGNextMsgIDToSend) {
		error_printf("Error - tg_send_msg_with_id reusing a slot of a message that was not yet sent\n");
		TGNextMsgIDToSend = (TGNextMsgIDToSend + 1) % TG_MMAP_CACHE_SIZE;
	}

	ptr->type = type;
	ptr->flags = flags;
	ptr->notify_flag = notify_flag;

	if (r) {
		ptr->ext_addr = r->last_ext_addr;
		assert(sizeof(ptr->rec_key) == db_keysize);
		memcpy(&ptr->rec_key, r, db_keysize);
	} else if (msg) {
		ptr->ext_addr = msg->ext_addr;
		memcpy(&ptr->rec_key, &msg->rec_key, db_keysize);
	}

	if (TGNextMsgIDToSend == -1) {
		TGNextMsgIDToSend = tg_msg_idx;
		tg_send_next_msg();
	}
}

void tg_notify_outgoing(struct record *r, uint8_t notify_flag)
{
	tg_send_msg_with_id(TG_MSG_ID_TYPE_OUTGOING, 0, r, NULL, notify_flag);
}

void tg_notify_incoming(struct record *r, uint8_t notify_flag)
{
	tg_send_msg_with_id(TG_MSG_ID_TYPE_INCOMING, 0, r, NULL, notify_flag);
}

void tg_notify_upload(struct record *r, uint8_t notify_flag)
{
	tg_send_msg_with_id(TG_MSG_ID_TYPE_UPLOAD, 0, r, NULL, notify_flag);
}

void tg_notify_new_client(struct ether_addr *mac) {
	struct tg_msg_entry msg = {};
	msg.rec_key.src_mac.ea = *mac;
	tg_send_msg_with_id(TG_MSG_ID_TYPE_CLIENT_INFO, TG_MSG_ID_FLAG_CLIENT_INFO_NEW, NULL, &msg, 0);
}

void tg_notify_no_dns(struct record *r, uint8_t notify_flag) {
	tg_send_msg_with_id(TG_MSG_ID_TYPE_OUTGOING, TG_MSG_ID_FLAG_OUTGOING_NO_DNS, r, NULL, notify_flag);
}

const char *tg_get_token(void)
{
	return TGBotToken;
}

static void tg_msg_refresh(int message_id)
{
	RefreshMsgQueue[RefreshMsgQueueTail] = message_id;
	RefreshMsgQueueTail = (RefreshMsgQueueTail + 1) % TG_MMAP_CACHE_SIZE;
	if (RefreshMsgQueueTail == RefreshMsgQueueHead) {
		error_printf("Error - refresh queue is full. Removing oldest msg\n");
		RefreshMsgQueueHead = (RefreshMsgQueueHead + 1) % TG_MMAP_CACHE_SIZE;
	}
}

static void tg_msg_wait_input_timer_cb(struct uloop_timeout *tm)
{
	tg_send_msg_wait_input = 0;
	tg_send_msg("No name was entered. Cancelled.");
	assert(TGNameReqMsgID != -1);
	if (TGNameReqMsgID != -1) {
		tg_msg_refresh(TGNameReqMsgID);
		tg_send_next_msg();
	}
	TGNameReqMsgID = -1;
}

static void tg_msg_refresh_all(struct ether_addr *addr)
{
	for (int i=0; i<tg_msg_mmap_db_len; ++i) {
		struct tg_msg_entry *msg = tg_msg_db + i;
		if (!msg->message_id || !msg->node.key) continue;

		struct record *r = database_find(&msg->rec_key, sizeof(msg->rec_key));

		if (!r) continue;
		if (memcmp(&r->src_mac.ea, addr, sizeof(*addr))) continue;

		tg_msg_refresh(msg->message_id);
	}
}

static void abuseipdb_result_cb(int confidence, const char *err_msg, void *ptr) {

	static char msg[50];
	if (err_msg) {
		CallbackMsgReply = err_msg;
	} else {
		snprintf(msg, sizeof(msg), "Reported! IP abuse confidence:%d", confidence);
		CallbackMsgReply = msg;
	}

	CallbackQueryID = ptr;
	tg_send_next_msg();

	RefreshNum=999;
	tg_msg_refresh(TGCallbackStateMsgID);
	TGCallbackStateMsgID = -1;
	tg_send_next_msg();
}

static void tg_handle_state_callback(struct tg_msg_entry *msg, char *callback_data, char *callback_query_id)
{
	int state = atoi(callback_data);
	
	if (TGCallbackState[0] == 1) {
		for (int i=1; i<5; ++i) {
			if (!TGCallbackState[i]) {
				TGCallbackState[i] = state;
				tg_msg_refresh(msg->message_id);
				tg_send_next_msg();
				return;
			}
		}

		int valid = 0;
		for (int i=1; i<5; ++i) {
			if (TGCallbackState[i] != 9) {
				valid = 1;
				break;
			}
		}
		
		if (!valid) {
			CallbackQueryID = strdup(callback_query_id);
			CallbackMsgReply = "Rule must contain at least one specified condition";
			tg_send_next_msg();
		}

		struct notify_params params = {};
		params.notify_flag = msg->notify_flag;
		if (TGCallbackState[1] == 1) params.asn = msg->rec_key.asn;
		else if (TGCallbackState[1] == 2) params.topl_domain = msg->rec_key.topl_domain;
		if (TGCallbackState[2] == 1) memcpy(params.country, msg->rec_key.country, sizeof(params.country));
		if (TGCallbackState[3] == 1) {
			params.proto = msg->rec_key.proto;
			params.dst_port = msg->rec_key.dst_port;
		} else if (TGCallbackState[3] == 2) {
			params.proto = msg->rec_key.proto;
			params.dst_port = 0;
		}

		if (TGCallbackState[4] == 1) {
			if (msg->rec_key.type & RECORD_TYPE_WAN) {
				params.type |= RECORD_TYPE_WAN;
				params.src.wan_idx = msg->rec_key.src_addr.wan_idx;
			} else {
				params.src.u64 = msg->rec_key.src_mac.u64;
			}
		}

		if (msg->rec_key.type & RECORD_TYPE_WAN_IN) params.type |= RECORD_TYPE_WAN_IN;

		int err = notify_mute_add(&params);
		CallbackQueryID = strdup(callback_query_id);
		if (err == -EEXIST) {
			CallbackMsgReply = "Identical rule already exists";
		} else {
			CallbackMsgReply = "Rule added successfully";
		}
		tg_send_next_msg();
		TGCallbackStateMsgID = -1;
		tg_msg_refresh(msg->message_id);
		tg_send_next_msg();

		// update other messages if they are now muted
		if (!err) {
			for (int i=1; i<tg_msg_mmap_db_len; ++i) {
				struct tg_msg_entry *m = tg_msg_db + i;
				if (m->message_id == -1) continue;
				struct record *r = database_find(&m->rec_key, sizeof(m->rec_key));
				if (!r) continue;
				if (notify_is_muted(r, m->notify_flag, &params)) {
					tg_msg_refresh(m->message_id);
					tg_send_next_msg();
				}
			}
		}


	} else if (TGCallbackState[0] == 2) {
		if (state == 99) {
			char categories_str[100] = {};
			int len = 0;
			for (int i=1; i<sizeof(TGCallbackState); ++i) {
				if (TGCallbackState[i] == 0) break;
				len += snprintf(categories_str + len, sizeof(categories_str) - len, "%s%d",
						i > 1 ? "," : "", TGCallbackState[i]);
				assert(len < sizeof(categories_str));
			}

			assert(categories_str[0]);

			abuseipdb_report(format_ipaddr(msg->rec_key.family, &msg->ext_addr, 1), categories_str, abuseipdb_result_cb, strdup(callback_query_id));
			return;
		}
		for (int i=1; i<sizeof(TGCallbackState); ++i) {
			if (!TGCallbackState[i]) {
				TGCallbackState[i] = state;
				tg_msg_refresh(msg->message_id);
				tg_send_next_msg();
				return;
			}
		}
		assert(0);
		return;
	}

}

void tg_on_poll_callback(int chat_id, int message_id, char *callback_query_id, char *callback_data)
{
	if (tg_send_msg_wait_input) {
		uloop_timeout_cancel(&wait_input_tm);
		memset(&TGNameReqAddr, 0, sizeof(TGNameReqAddr));
		tg_send_msg_wait_input = 0;

		tg_send_msg("Name change cancelled.");
		tg_send_next_msg();

		assert(TGNameReqMsgID != -1);
		if (TGNameReqMsgID != -1) {
			tg_msg_refresh(TGNameReqMsgID);
			tg_send_next_msg();
		}
		TGNameReqMsgID = -1;
	}

	if (!strcmp(callback_data, "cancel")) {
		TGCallbackStateMsgID = -1;
	}

	struct tg_msg_entry *msg, *tmp;

	msg = avl_find_element(&tg_msg_avl, &message_id, tmp, node);

	if (!msg) {
		error_printf("Error - tg_on_poll_callback can not find msg with message_id:%d\n", message_id);
		CallbackQueryID = strdup(callback_query_id);
		CallbackMsgReply = "Message is too old.";
		tg_send_next_msg();
		return;
	}

	if (TGCallbackStateMsgID != -1) {
		if (TGCallbackStateMsgID == msg->message_id) {
			tg_handle_state_callback(msg, callback_data, callback_query_id);
			return;
		}
		tg_msg_refresh(TGCallbackStateMsgID);
		TGCallbackStateMsgID = -1;
		tg_send_next_msg();
	}

	if (!strcmp(callback_data, "name")) {
		if (msg->type == TG_MSG_ID_TYPE_CLIENT_INFO) {
			msg->flags |= TG_MSG_ID_FLAG_CLIENT_INFO_SET_NAME;
			tg_msg_refresh(message_id);
			tg_send_next_msg();
			return;
		}

		CallbackQueryID = strdup(callback_query_id);
		if (!msg->rec_key.src_mac.u64) {
			CallbackMsgReply = "Mac address unresolved for this entry.";
			tg_send_next_msg();
			return;
		}

		CallbackMsgReply = NULL;
		tg_send_next_msg();

		tg_send_msg_with_id(TG_MSG_ID_TYPE_CLIENT_INFO, TG_MSG_ID_FLAG_CLIENT_INFO_SET_NAME, NULL, msg, 0);
		return;
	}

	struct record *r = database_find(&msg->rec_key, sizeof(msg->rec_key));

	if (!strncmp(callback_data, "Refresh", 7) || !strcmp(callback_data, "cancel")) {
		if (r || (msg->type == TG_MSG_ID_TYPE_CLIENT_INFO)) {
			if (r && !strncmp(callback_data, "Refresh", 7)) {
				msg->ext_addr = r->last_ext_addr;
			}
			RefreshNum = atoi(callback_data + 7) + 1;
			tg_msg_refresh(message_id);
			tg_send_next_msg();
			return;
		}
	}

	if (!r) {
		error_printf("Error - tg_on_poll_callback can not find db record for message_id:%d\n", message_id);
		CallbackQueryID = strdup(callback_query_id);
		CallbackMsgReply = "Can not find this record in this period's DB.";
		tg_send_next_msg();
		return;
	}

	if (!strcmp(callback_data, "mute")) {
		if (!(r->type & RECORD_TYPE_WAN) && !r->src_mac.u64) {
			CallbackQueryID = strdup(callback_query_id);
			CallbackMsgReply = "Can not resolve mac address for this entry.";
			tg_send_next_msg();
			return;
		}
		TGCallbackStateMsgID = message_id;
		memset(TGCallbackState, 0, sizeof(TGCallbackState));
		TGCallbackState[0] = 1;
		tg_msg_refresh(message_id);
		tg_send_next_msg();
		return;
	}

	if (!strcmp(callback_data, "report")) {
		TGCallbackStateMsgID = message_id;
		memset(TGCallbackState, 0, sizeof(TGCallbackState));
		TGCallbackState[0] = 2;
		tg_msg_refresh(message_id);
		tg_send_next_msg();
		return;
	}

	// Just refresh message, probably a button from an old process run
	RefreshNum=999;
	tg_msg_refresh(message_id);
	tg_send_next_msg();
}

// Helper struct for sorting hosts
struct host_sort_entry {
    struct hosts_stat *stat;
    size_t index;
};

static int compare_hosts(const void *a, const void *b) {
    const struct host_sort_entry *ha = a;
    const struct host_sort_entry *hb = b;
    // Sort by connection count, highest first
    if (ha->stat[ha->index].conn_count > hb->stat[hb->index].conn_count) return -1;
    if (ha->stat[ha->index].conn_count < hb->stat[hb->index].conn_count) return 1;
    return 0;
}

static int format_host_entry(char *buf, size_t size, const struct hosts_stat *stat) {
    int len = 0;
    
    // Format hostname if exists, otherwise just MAC
    if (stat->record->hostname[0]) {
        len += snprintf(buf + len, size - len, "<b>%s</b> (%s)\n", 
            stat->record->hostname, format_macaddr(&stat->record->mac_addr));
    } else {
        len += snprintf(buf + len, size - len, "<b>%s</b>\n", 
            format_macaddr(&stat->record->mac_addr));
    }
    
    // Add connection count
    len += snprintf(buf + len, size - len, "Connections: %lu\n", stat->conn_count);
    
    // Add IPs
    len += snprintf(buf + len, size - len, "IPs:\n");
    for (int i = 0; i < NEIGH_MAX_STAT_IPS && stat->ip[i].family; i++) {
        len += snprintf(buf + len, size - len, "- %s\n", 
            format_ipaddr(stat->ip[i].family, &stat->ip[i].addr, 1));
    }
    
    len += snprintf(buf + len, size - len, "\n");
    return len;
}

static void send_hosts_list(void) {
    size_t count;
    struct hosts_stat *stats = hosts_get_all(&count);
    if (!stats || count == 0) {
        tg_send_msg("No hosts found.");
        return;
    }

    // Create sorted array of indices
    struct host_sort_entry *sorted = calloc(count, sizeof(struct host_sort_entry));
    if (!sorted) {
        free(stats);
        tg_send_msg("Memory allocation error");
        return;
    }

    // Initialize sorting array
    for (size_t i = 0; i < count; i++) {
        sorted[i].stat = stats;
        sorted[i].index = i;
    }

    // Sort by connection count
    qsort(sorted, count, sizeof(struct host_sort_entry), compare_hosts);

    // Send messages in chunks
    char msg[1024];
    int msg_len = 0;
    int hosts_in_msg = 0;

    for (size_t i = 0; i < count; i++) {
        // Skip hosts without hostname
        if (!stats[sorted[i].index].record->hostname[0]) continue;

        // Format this host entry into a temporary buffer
        char host_buf[256];
        int host_len = format_host_entry(host_buf, sizeof(host_buf), &stats[sorted[i].index]);

        // If this host entry would overflow the message, send current message and start new one
        if (msg_len + host_len >= sizeof(msg)) {
            if (msg_len > 0) {
                tg_send_msg(msg);
                msg_len = 0;
                hosts_in_msg = 0;
            }
        }

        // Add host entry to message
        strcpy(msg + msg_len, host_buf);
        msg_len += host_len;
        hosts_in_msg++;
    }

    // Send any remaining hosts
    if (hosts_in_msg > 0) {
        tg_send_msg(msg);
    }

    // Now send unknown hosts in a separate message if any exist
    msg_len = 0;
    hosts_in_msg = 0;
    for (size_t i = 0; i < count; i++) {
        // Only process hosts without hostname
        if (stats[sorted[i].index].record->hostname[0]) continue;

        // Format this host entry into a temporary buffer
        char host_buf[256];
        int host_len = format_host_entry(host_buf, sizeof(host_buf), &stats[sorted[i].index]);

        // If this host entry would overflow the message, send current message and start new one
        if (msg_len + host_len >= sizeof(msg)) {
            if (msg_len > 0) {
                tg_send_msg(msg);
                msg_len = 0;
                hosts_in_msg = 0;
            }
        }

        if (hosts_in_msg == 0) {
            msg_len = snprintf(msg, sizeof(msg), "Unknown hosts:\n\n");
        }

        strcpy(msg + msg_len, host_buf);
        msg_len += host_len;
        hosts_in_msg++;
    }

    // Send any remaining unknown hosts
    if (hosts_in_msg > 0) {
        tg_send_msg(msg);
    }

    free(sorted);
    free(stats);
}

void tg_on_poll_text(int chat_id, int message_id, char *text)
{
    if (!ChatID) {
        ChatID = chat_id;
		char chat_id_str[100];
		snprintf(chat_id_str, sizeof(chat_id_str), "%d", chat_id);
		if (config_set("tg_chat_id", chat_id_str) != 0) {
			error_printf("Error saving chat id in config file.\n");
		}
		tg_api_send_msg("Hi there! I'm ready and will send notifications to this channel.");
    } else if (chat_id != ChatID) {
        tg_api_send_msg("Received a message from a different TG ID. Ignoring.");
        return;
    }

    if (!strcmp(text, "/hosts")) {
        send_hosts_list();
        return;
    }

	if (!strcmp(text, "/hosts clean")) {
        hosts_clean();
		int num_removed = hosts_clean();
		char msg[64];
		snprintf(msg, sizeof(msg), "%d hosts removed from database.", num_removed);
		tg_send_msg(msg);
        return;
    }

    if (strncmp(text, "/host ", 6) == 0) {
        const char *ip = text + 6;
        struct in_addr ip4_addr;
        struct in6_addr ip6_addr;
        int family;
        
        // Try to parse as IPv4 first
        if (inet_pton(AF_INET, ip, &ip4_addr) == 1) {
            ip4_addr.s_addr = be32toh(ip4_addr.s_addr);
            family = AF_INET;
        } 
        // Then try IPv6
        else if (inet_pton(AF_INET6, ip, &ip6_addr) == 1) {
            family = AF_INET6;
        }
        else {
            tg_send_msg("Invalid IP address format");
            return;
        }
        
        // Try to find MAC address for this IP
        struct record *rec = NULL;
        while ((rec = database_next(gdbh, rec)) != NULL) {
            if (rec->family == family) {
                if ((family == AF_INET && memcmp(&rec->src_addr.in, &ip4_addr, sizeof(ip4_addr)) == 0) ||
                    (family == AF_INET6 && memcmp(&rec->src_addr.in6, &ip6_addr, sizeof(ip6_addr)) == 0)) {
                    struct tg_msg_entry msg = {};
                    msg.rec_key.src_mac.ea = rec->src_mac.ea;
                    tg_send_msg_with_id(TG_MSG_ID_TYPE_CLIENT_INFO, TG_MSG_ID_FLAG_CLIENT_INFO_NEW, NULL, &msg, 1);
                    return;
                }
            }
        }
        
        tg_send_msg("Could not find a device with this IP address in current database.");
        return;
    }

    if (tg_send_msg_wait_input) {
        uloop_timeout_cancel(&wait_input_tm);
		tg_send_msg_wait_input = 0;
		int res = hosts_update_by_addr(text, &TGNameReqAddr, TYPE_USER_PROVIDED);

		char msg[256];
		if (res == 0) {
			snprintf(msg, sizeof(msg), "Name set to: '%s'", lookup_hostname(&TGNameReqAddr));
		} else {
			snprintf(msg, sizeof(msg), "Error setting name.");
		}

		tg_api_send_msg(msg);

		if (res == 0) {
			tg_msg_refresh_all(&TGNameReqAddr);
		}

		assert(TGNameReqMsgID != -1);
		if (TGNameReqMsgID != -1) {
			tg_msg_refresh(TGNameReqMsgID);
			tg_send_next_msg();
		}
		TGNameReqMsgID = -1;
		memset(&TGNameReqAddr, 0, sizeof(TGNameReqAddr));
    }
}

void tg_on_poll_pinned(int chat_id, int message_id)
{
	struct tg_msg_entry *msg, *tmp;

	msg = avl_find_element(&tg_msg_avl, &message_id, tmp, node);

	if (!msg) {
		error_printf("Error - tg_send_on_data_cb can not find pinned msg with message_id:%d\n", message_id);
		return;
	}

	msg->flags |= TG_MSG_ID_FLAG_PINNED;
	MMAP_CACHE_SAVE(tg_msg, TG_MMAP_CACHE_SIZE, NULL, 0);
}

__attribute__((constructor)) static void tg_send_init(void)
{
        tg_send_https_ctx = https_init(&tg_send_https_cbs, "api.telegram.org", 443, 10);
}

static int
avl_cmp_tg_msg(const void *k1, const void *k2, void *ptr)
{
	return *(int *)k1 - *(int *)k2;
}

static char *format_tg_key(const void *ptr) {
	const int *message_id = (int *)ptr;
	
	static char key_str[16];
	snprintf(key_str, sizeof(key_str), "%d", *message_id);

	return key_str;
}

static int tg_mmap_persist(const char *path, uint32_t timestamp)
{
	MMAP_CACHE_SAVE(tg_msg, TG_MMAP_CACHE_SIZE, path, 0);
	return 0;
}

int init_tg(const char *db_path) {
	nlbwmon_add_presistence_cb(tg_mmap_persist);
	MMAP_CACHE_INIT(tg_msg, TG_MMAP_CACHE_SIZE, avl_cmp_tg_msg, message_id, format_tg_key);
	if (!tg_msg_db) return -errno;

	if (tg_msg_mmap_db_len == 0) {
		MMAP_CACHE_LOAD(tg_msg, TG_MMAP_CACHE_SIZE, message_id, db_path, 0, format_tg_key);
	}

	const char *token = config_get("tg_bot_token");
	if (token) {
		TGBotToken = strdup(token);
		init_tg_poll();
	} else {
		error_printf("Missing tg_bot_token in config file. Telegram bot is disabled.\n");
	}

	const char *chat_id_str = config_get("tg_chat_id");
	if (chat_id_str) ChatID = atoi(chat_id_str);

	return 0;
}

