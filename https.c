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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/ustream-ssl.h>

#include "utils.h"
#include "https.h"

#define STREAM_STATE_NOT_CONNECTED 0
#define STREAM_STATE_CONNECTING 1
#define STREAM_STATE_IDLE 2
#define STREAM_STATE_IN_PROG 3
#define STREAM_STATE_RETRY 4

#define HTTPS_MAX_RETRIES 5

struct http_ctx_data {
	int is_body;
	int data_len;
	int data_consumed;
};

struct https_ctx {
	char *host;
	uint16_t port;
	struct https_cbs *cbs;
	int state;
	char *req_body;
	struct uloop_fd fd;
	struct uloop_timeout retry_tm;
	int num_retries;
	int max_retries;
	int retry_delay;
	struct ustream_fd stream;
	struct ustream_ssl ssl;
	void *ustream_ssl_ctx;
	struct http_ctx_data http_ctx;
};

static int process_http(struct http_ctx_data *http_ctx, struct ustream *s, int *eof) {
	char *newline, *str;

	do {
		int len;
		str = ustream_get_read_buf(s, &len);
		if (!str)
			break;

		if (!http_ctx->is_body) {
			newline = memchr(str, '\n', len);
			if (!newline)
				break;

			*newline = 0;
			debug_printf("%s\n", str);

			if (!strncmp(str, "HTTP/", 5)) {
				int status = atoi(strchr(str, ' ') + 1);
				debug_printf("Status:%d\n", status);
				if (status >= 500) {
					ustream_consume(s, len);
					return -1;
				}

			} else if (!strncmp(str, "content-length:", 15) || !strncmp(str, "Content-Length:", 15)) {
				assert(http_ctx->data_len == 0);
				http_ctx->data_len = atoi(str+15);
				debug_printf("Length %d\n", http_ctx->data_len);
			}

			if (!strcmp(str, "\r")) {
				http_ctx->is_body = 1;
				debug_printf("End of headers\n");
			}

			ustream_consume(s, newline + 1 - str);

		} else {
			assert(!http_ctx->data_len || (len+http_ctx->data_consumed <= http_ctx->data_len));
			if ((len + http_ctx->data_consumed) >= http_ctx->data_len) {
				*eof = 1;
				return 1;
			}
			*eof = 0;
			return 1;
		}

	} while(1);
	
	*eof = 0;
	return 0;
}

static void connect_client(struct https_ctx *ctx);

static void retry_client_cb(struct uloop_timeout *tm)
{
	struct https_ctx *ctx = container_of(tm, struct https_ctx, retry_tm);
	connect_client(ctx);
}

static void retry(struct https_ctx *ctx)
{
	close(ctx->stream.fd.fd);
	ctx->num_retries++;
	ctx->state = STREAM_STATE_RETRY;
	if (ctx->num_retries >= ctx->max_retries) {
		error_printf("Error in http. Out of retries.\n");
		ctx->cbs->error();
	} else {
		error_printf("Error in http. Will retry. %d/%d\n", ctx->num_retries, ctx->max_retries);
		ctx->retry_tm.cb = retry_client_cb;
		uloop_timeout_set(&ctx->retry_tm, ctx->retry_delay * 1000);
	}
}


static void send_body(struct https_ctx *ctx)
{
	assert(ctx->state == STREAM_STATE_IDLE);
	ctx->state = STREAM_STATE_IN_PROG;
	memset(&ctx->http_ctx, 0, sizeof(ctx->http_ctx));

	ustream_write(&ctx->ssl.stream, ctx->req_body, strlen(ctx->req_body), false);
}

static void client_ssl_notify_read(struct ustream *s, int bytes)
{
	int size, size_left;
	int eof;
	
	struct https_ctx *ctx = container_of((struct ustream_ssl *)s, struct https_ctx, ssl);

	int res = process_http(&ctx->http_ctx, s, &eof);

	if (res < 0) {
		retry(ctx);
		return;
	}

	if (res == 0) return;

	if (eof) {
		free(ctx->req_body);
		ctx->req_body = NULL;
		ctx->num_retries = 0;
		ctx->state = STREAM_STATE_IDLE;
	}

	ustream_get_read_buf(s, &size);

	ctx->cbs->data(s, eof);

	if (!eof) {
		ustream_get_read_buf(s, &size_left);
		ctx->http_ctx.data_consumed += size - size_left;
	}
}

static void client_ssl_notify_write(struct ustream *s, int bytes)
{
	debug_printf("Wrote %d bytes, pending %d\n", bytes, s->w.data_bytes);
}

static void client_notify_connected(struct ustream_ssl *ssl)
{
	debug_printf("SSL connection established (CN verified: %d)\n", ssl->valid_cn);
	struct https_ctx *ctx = container_of(ssl, struct https_ctx, ssl);

	ctx->state = STREAM_STATE_IDLE;

	if (ctx->req_body) send_body(ctx);
}

static void https_client_notify_error(struct ustream_ssl *ssl, int error, const char *str)
{
	error_printf("SSL connection error(%d): %s\n", error, str);
	struct https_ctx *ctx = container_of(ssl, struct https_ctx, ssl);

	retry(ctx);
}

static void client_notify_verify_error(struct ustream_ssl *ssl, int error, const char *str)
{
	error_printf("WARNING: SSL certificate error(%d): %s\n", error, str);
}

static void client_notify_state(struct ustream *s)
{
	if (!s->write_error && !s->eof)
		return;

	debug_printf("Connection closed\n");
	struct https_ctx *ctx = container_of((struct ustream_ssl *)s, struct https_ctx, ssl);

	int cur_state = ctx->state;

	https_close(ctx);

	if (cur_state == STREAM_STATE_RETRY) return;

	if (ctx->req_body) {
		connect_client(ctx);
	}
}

static void connect_ssl(struct https_ctx *ctx)
{
	debug_printf("Starting SSL negotiation\n");

	ctx->ssl.notify_error = https_client_notify_error;
	ctx->ssl.notify_verify_error = client_notify_verify_error;
	ctx->ssl.notify_connected = client_notify_connected;
	ctx->ssl.stream.notify_read = client_ssl_notify_read;
	ctx->ssl.stream.notify_write = client_ssl_notify_write;
	ctx->ssl.stream.notify_state = client_notify_state;

	ctx->ssl.server_name = ctx->host;

	ustream_ssl_set_peer_cn(&ctx->ssl, ctx->host);
	ustream_fd_init(&ctx->stream, ctx->fd.fd);
	ustream_ssl_init(&ctx->ssl, &ctx->stream.stream, ctx->ustream_ssl_ctx, false);
}

static void https_send_connect_cb(struct uloop_fd *f, unsigned int events)
{
	struct https_ctx *ctx = container_of(f, struct https_ctx, fd);

	if (f->eof || f->error) {
		debug_printf("Connection failed\n");
		retry(ctx);
		return;
	}

	debug_printf("Connection established\n");
	uloop_fd_delete(f);
	connect_ssl(ctx);
}

static void connect_client(struct https_ctx *ctx)
{
	char port_str[10];
	sprintf(port_str, "%d", ctx->port);
	ctx->fd.fd = usock(USOCK_TCP | USOCK_NONBLOCK, ctx->host, port_str);
	ctx->fd.cb = https_send_connect_cb;
	ctx->state = STREAM_STATE_CONNECTING;
	uloop_fd_add(&ctx->fd, ULOOP_WRITE | ULOOP_EDGE_TRIGGER);
}

void *https_init(struct https_cbs *cbs, const char *host, uint32_t port)
{
	struct https_ctx *ctx = (struct https_ctx *) calloc(1, sizeof(*ctx));
	ctx->cbs = cbs;
	ctx->host = strdup(host);
	ctx->port = port;
	ctx->max_retries = HTTPS_MAX_RETRIES;
	ctx->retry_delay = 10;
	ctx->ustream_ssl_ctx = ustream_ssl_context_new(false);
	ustream_ssl_context_add_ca_crt_file(ctx->ustream_ssl_ctx, "/etc/ssl/certs/ca-certificates.crt");

	return ctx;
}

void https_set_retries(struct https_ctx *ctx, int retries, int delay)
{
	ctx->max_retries = retries;
	ctx->retry_delay = delay;
}

void https_set_require_validation(struct https_ctx *ctx, int require)
{
	ustream_ssl_context_set_require_validation(ctx->ustream_ssl_ctx, require);
}

void https_send_msg(struct https_ctx *ctx, const char *url, const char *data, const char *data_content_type)
{
	assert(!ctx->req_body);
	assert((ctx->state == STREAM_STATE_IDLE) ||
			(ctx->state == STREAM_STATE_NOT_CONNECTED));

	int size = strlen(url) + 100;
	int data_size = 0;
	if (data) {
		data_size = strlen(data);
		size += data_size + strlen(data_content_type) + 100;
	}
	char *buf = malloc(size);

	int len = snprintf(buf, size, "%s %s HTTP/1.1\nHost: %s\nUser-Agent: nlbmon/2.0\n", data ? "POST": "GET", url, ctx->host);
	assert(len < size);

	if (data) {
		len += snprintf(buf + len, size - len, "Content-Type: %s\nContent-Length: %d\n\n%s", data_content_type, data_size, data);
	} else {
		buf[len] = '\n';
		buf[len+1] = 0;
		++len;
	}

	assert(len < size);

	ctx->req_body = buf;
	if (ctx->state == STREAM_STATE_IDLE) {
		send_body(ctx);
	} else {
		connect_client(ctx);
	}
}

void https_close(struct https_ctx *ctx)
{
	ustream_free(&ctx->ssl.stream);
	ustream_free(&ctx->stream.stream);
	if (ctx->stream.fd.fd != -1) close(ctx->stream.fd.fd);
	ctx->state = STREAM_STATE_NOT_CONNECTED;
}

char* urlencode(const char* data)
{
	static char encoded[1500];
	const char *hex = "0123456789abcdef";

	int pos = 0;
	while (*data) {
		if ((sizeof(encoded) - pos) < 4) break;
		if (('a' <= *data && *data <= 'z')
				|| ('A' <= *data && *data <= 'Z')
				|| ('0' <= *data && *data <= '9')) {
			encoded[pos++] = *data;
		} else if (((unsigned char)data[0] == 0xf0) && ((unsigned char)data[1] == 0x9f)) {// &&
				//((unsigned char)data[2] == 0x87) &&
				//(0xa6 <= (unsigned char)data[3] && (unsigned char)data[3] <= (0xa6 + 'Z' - 'A'))) {
			encoded[pos++] = data[0];
			encoded[pos++] = data[1];
			encoded[pos++] = data[2];
			encoded[pos++] = data[3];
			data += 3;
		} else {
			encoded[pos++] = '%';
			encoded[pos++] = hex[*data >> 4];
			encoded[pos++] = hex[*data & 15];
		}
		data++;
	}

	assert(!*data);
	encoded[pos] = '\0';
	return encoded;
}

