#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "libubox/ustream.h"
#include "libubox/uloop.h"
#include "libubox/usock.h"

#include "utils.h"
#include "dns.h"

#include "dns_listen.h"

static struct uloop_fd server;

#define CLIENT_STATE_READ_HDRS 0
#define CLIENT_STATE_READ_DATA 1

struct client {
	struct sockaddr_in sin;

	struct ustream_fd s;
	int ctr;
	int data_len;
	int state;
};

static void client_read_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of(s, struct client, s.stream);
	struct ustream_buf *buf = s->r.head;
	char *newline, *str;

	do {
		str = ustream_get_read_buf(s, NULL);
		if (!str)
			break;

		if (cl->state == CLIENT_STATE_READ_HDRS) {
			newline = strchr(buf->data, '\n');
			if (!newline)
				break;

			*newline = 0;
			if (!cl->data_len && !strncmp(str, "Content-Length:", 15)) {
				cl->data_len = atoi(str+15);
			}

			ustream_consume(s, newline + 1 - str);
			cl->ctr += newline + 1 - str;
			if (str[0] == '\r') {
				cl->state = CLIENT_STATE_READ_DATA;
			}
			continue;
		}

		if (cl->state == CLIENT_STATE_READ_DATA) {
			if (strlen(str) < cl->data_len) break;

			int data_ok = 0;
			ustream_consume(s, cl->data_len);
			debug_printf("dns_listen  - data:%s\n", str);
			char *name = str;
			char *ttl_s = strchr(str, ',');
			if (!ttl_s) goto dns_listen_error;
			*ttl_s++ = 0;
			char *addr = strchr(ttl_s, ',');
			if (!addr) goto dns_listen_error;
			*addr++ = 0;
			uint32_t ttl = atoi(ttl_s);
			char *c_addr = strchr(addr, ',');
			if (!c_addr) goto dns_listen_error;
			*c_addr++ = 0;

			data_ok = 1;
			dns_update(name, ttl, addr, c_addr);
dns_listen_error:
			if (!data_ok) {
				error_printf("dns_listen - error in data: %s", str);
			}

			ustream_printf(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: keep-alive\r\nServer: dns_listen/1.0\r\n\r\n{}");
			cl->data_len = 0;
			cl->state = CLIENT_STATE_READ_HDRS;
		}
	} while(1);
}

static void client_close(struct ustream *s)
{
	struct client *cl = container_of(s, struct client, s.stream);

	debug_printf("dns_listen - Connection closed\n");
	ustream_free(s);
	close(cl->s.fd.fd);
	free(cl);
}

static void client_notify_write(struct ustream *s, int bytes)
{
	debug_printf("dns_listen - Wrote %d bytes, pending: %d\n", bytes, s->w.data_bytes);

	if (s->w.data_bytes < 128 && ustream_read_blocked(s)) {
		debug_printf("dns_listen - Unblock read\n");
		ustream_set_read_blocked(s, false);
	}
}

static void client_notify_state(struct ustream *s)
{
	struct client *cl = container_of(s, struct client, s.stream);

	if (!s->eof)
		return;

	debug_printf("dns_listen - eof!, pending: %d, total: %d\n", s->w.data_bytes, cl->ctr);
	//if (!s->w.data_bytes)
	return client_close(s);

}

static void server_cb(struct uloop_fd *fd, unsigned int events)
{
	struct sockaddr_in sa;
	unsigned int sl = sizeof(struct sockaddr_in);
	int sfd;

	while (1) {

		sfd = accept(server.fd, (struct sockaddr *) &sa, &sl);
		if (sfd < 0) {
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
				error_printf("dns_listen - Accept failed %s\n", strerror(errno));
			}
			return;
		}

		struct client *cl = calloc(1, sizeof(*cl));
		cl->sin = sa;
		cl->s.stream.string_data = true;
		cl->s.stream.notify_read = client_read_cb;
		cl->s.stream.notify_state = client_notify_state;
		cl->s.stream.notify_write = client_notify_write;
		ustream_fd_init(&cl->s, sfd);
		debug_printf("dns_listen - New connection\n");
	}
}

int dns_listen_run(const char *port)
{

	server.cb = server_cb;
	server.fd = usock(USOCK_TCP | USOCK_SERVER | USOCK_IPV4ONLY | USOCK_NUMERIC | USOCK_NONBLOCK, "127.0.0.1", port);
	if (server.fd < 0) {
		error_printf("dns_listen - usock");
		return -1;
	}

	uloop_fd_add(&server, ULOOP_READ);

	return 0;
}

