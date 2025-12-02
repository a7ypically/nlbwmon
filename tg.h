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

#ifndef __TG_H__
#define __TG_H__

#include <netinet/in.h>
#include <libubox/ustream-ssl.h>
#include "database.h"

extern char *tg_host;
extern char *tg_port;

int tg_send_msg(const char *msg);
const char *tg_get_token(void);
void tg_send_set_chat_id(int chat_id, char *bot_token);
void tg_notify_incoming(struct record *r, uint8_t notify_flag);
void tg_notify_outgoing(struct record *r, uint8_t notify_flag);
void tg_notify_no_dns(struct record *r, uint8_t notify_flag);
void tg_notify_upload(struct record *r, uint8_t notify_flag);
void tg_notify_new_client(struct ether_addr *mac);
void tg_on_poll_callback(int chat_id, int message_id, char *callback_query_id, char *callback_data);
void tg_on_poll_text(int chat_id, int message_id, char *text);
void tg_on_poll_pinned(int chat_id, int message_id);
int init_tg_poll(void);
int init_tg(const char *db_path);
void tg_dns_topl_remap(const uint16_t *remap, uint32_t len);

#endif
