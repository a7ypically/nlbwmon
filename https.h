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

#ifndef __HTTPS_H__
#define __HTTPS_H__

struct ustream;

typedef int (*https_client_on_data_cb)(struct ustream *s, int eof);
typedef void (*https_client_on_error_cb)(void);
struct https_cbs {
	https_client_on_data_cb data;
	https_client_on_error_cb error;
};

struct https_ctx;

void *https_init(struct https_cbs *cbs, const char *host, uint32_t port, uint8_t timeout);
void https_set_require_validation(struct https_ctx *ctx, int require);
void https_set_retries(struct https_ctx *ctx, int retries, int delay);
void https_send_msg(struct https_ctx *ctx, const char *url, const char *data, const char *data_content_type);
void https_close(struct https_ctx *ctx);
char* urlencode(const char* data);

#endif
