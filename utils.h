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

#ifndef __UTILS_H__
#define __UTILS_H__

#include <netinet/in.h>
#include <netinet/ether.h>

#ifdef DEBUG_LOG
#define debug_printf(fmt, ...) do { \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
} while (0)
#else
#define debug_printf(fmt, ...)
#endif

#define error_printf(fmt, ...) do { \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
} while (0)

#define _unused(x) ((void)(x))

int rmkdir(const char *path);

char * format_macaddr(struct ether_addr *mac);
char * format_ipaddr(int family, const void *addr, int is_host_order);

int tp_diff(struct timespec *start, struct timespec *end);

#endif /* __UTILS_H__ */
