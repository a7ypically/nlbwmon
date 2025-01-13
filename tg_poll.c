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

#include <libubox/usock.h>
#include <libubox/uloop.h>

#include "https.h"
#include "utils.h"
#include "tg.h"

static int MsgOffset;
static struct https_ctx *tg_poll_https_ctx;
static int TGPollErrors;

static void send_poll_command(void);

static int tg_poll_on_data_cb(struct ustream *s, int eof) {

	if (!eof) return 0;

	char *buf;
	int len;
	
	debug_printf("Ready to parse body\n");
	buf = ustream_get_read_buf(s, &len);

	//Break json to be able to use str funcs.
	//Better use json parser
	buf[len-1] = 0;
	debug_printf("%s\n", buf);
	if (!strstr(buf, "\"ok\":true")) {
		debug_printf("TG poll - Error:%s\n", buf);
		TGPollErrors++;
		if (TGPollErrors > 5) {
			error_printf("Too many errors in tg_poll. Stopping until service restart.\n");
			tg_send_msg("Too many errors in tg_poll. Stopping until service restart.");
			ustream_consume(s, len);
			return 0;
		}
		goto exit_and_poll;
	}

	char *update_id_str = strstr(buf, "\"update_id\":");
	if (!update_id_str) {
                debug_printf("TG poll - missing update id:%s\n", buf);
		goto exit_and_poll;
	}

	int update_id = atoi(update_id_str + 12);
	if (!update_id) {
		error_printf("Error in TG polling. Can not parse update_id - %s\n", buf);
		tg_send_msg("Error in TG polling. Will not receive any new messages until restart.");
		ustream_consume(s, len);
		return 0;
	}

	MsgOffset = update_id;

	char *chat_id_str = strstr(buf, "\"chat\":{\"id\":");
	if (!chat_id_str) {
		error_printf("Error in TG polling. Can not parse chat_id - %s\n", buf);
		tg_send_msg("Error in TG polling. Can not parse chat_id.");
		goto exit_and_poll;
	}

	chat_id_str += 13;

	int chat_id = atoi(chat_id_str);

	char *pin_msg = strstr(buf, "\"pinned_message\":");
	if (pin_msg) {
		buf = pin_msg;
	}

	char *message_id_str = strstr(buf, "\"message_id\":");
	if (!message_id_str) {
		error_printf("Error in TG polling. Can not parse message_id - %s\n", buf);
		tg_send_msg("Error in TG polling. Can not parse message_id.");
		goto exit_and_poll;
	}

	message_id_str += 13;
	int message_id = atoi(message_id_str);

	if (pin_msg) {
		tg_on_poll_pinned(chat_id, message_id);
		goto exit_and_poll;
	}

	TGPollErrors = 0;

	char *cb = strstr(buf, "\"callback_query\":");
	if (cb) {
		cb += 18;
		if (strncmp(cb, "\"id\":", 5)) {
			goto error_callback;
		}

		char callback_query_id[50];
		char *start = strchr(cb+5, '\"') + 1;
		char *end = strchr(start, '\"');
		end -= 1;
		if ((end-start+2) > sizeof(callback_query_id)) {
			goto error_callback;
		}

		strncpy(callback_query_id, start, end-start+1);
		callback_query_id[end-start+1] = 0;

		char *cb_data = strstr(cb, "\"data\":");
		if (!cb_data) {
			goto error_callback;
		}

		char callback_data[50];
		start = strchr(cb_data+7, '\"') + 1;
		end = strchr(start, '\"');
		end -= 1;
		if ((end-start+2) > sizeof(callback_data)) {
			goto error_callback;
		}

		strncpy(callback_data, start, end-start+1);
		callback_data[end-start+1] = 0;

		tg_on_poll_callback(chat_id, message_id, callback_query_id, callback_data);

		goto exit_and_poll;
	}


	char *text = strstr(buf, "\"text\":\"");
	if (!text) {
		tg_send_msg("Error in TG polling. Unknown message..");
		error_printf("Error in parsing TG message - %s\n", buf);
	} else {
		text += 8;

		char *end = strchr(text, '\"');
		*end = 0;

		debug_printf("Message: '%s'\n", text);
		tg_on_poll_text(chat_id, message_id, text);
	}

exit_and_poll:

	ustream_consume(s, len);
	send_poll_command();

	return 0;

error_callback:
	error_printf("Error in TG polling. Can not parse callback id - %s\n", buf);
	tg_send_msg("Error in TG polling. Can not parse callback id - time for json parser!");
	return 0;
}

static void send_poll_command(void)
{
	char url[512];
	snprintf(url, sizeof(url), "/bot%s/getUpdates?timeout=900&offset=%d", tg_get_token(), MsgOffset+1);

	https_send_msg(tg_poll_https_ctx, url, NULL, NULL);
}

static void tg_poll_on_https_error(void)
{
	error_printf("Error in https!\n");
	tg_send_msg("Error in TG polling. Will not receive any new messages until restart.");
}

static struct https_cbs tg_poll_https_cbs = {
	.data = tg_poll_on_data_cb,
	.error = tg_poll_on_https_error,
};
	
int init_tg_poll(void) {
	tg_poll_https_ctx = https_init(&tg_poll_https_cbs, "api.telegram.org", 443, 0);

	if (!tg_get_token()) {
		error_printf("Telegram token is not set. TG will not be used.\n");
	} else {
		send_poll_command();
	}
	return 0;
}

#ifdef TG_TEST_POLL
int main(int argc, char **argv)
{
	uloop_init();
	init_tg_poll();
	uloop_run();

	uloop_done();
	return 0;
}
#endif
