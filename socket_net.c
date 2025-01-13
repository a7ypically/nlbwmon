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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libubox/uloop.h>
#include <libubox/usock.h>

#include "socket_net.h"
#include "database.h"
#include "timing.h"
#include "protocol.h"
#include "asn.h"
#include "dns.h"
#include "wans.h"
#include "hosts.h"
#include "utils.h"
#include "nlbwmon.h"

struct command {
	const char *cmd;
	int (*cb)(int sock, const char *arg);
};

static int ctrl_socket;
static struct uloop_fd sock_fd = { };
static struct uloop_timeout sock_tm = { };


static ssize_t
send_data(int sock, const void *buf, size_t len)
{
	ssize_t rv, sent = 0;

	while (len) {
		rv = send(sock, buf + sent, len, 0);

		if (rv == -1 && errno == EAGAIN)
			continue;

		if (rv <= 0)
			return rv;

		len -= rv;
		sent += rv;
	}

	return sent;
}

static int
handle_dump(int sock, const char *arg)
{
	struct dbhandle *h;
	struct record *rec = NULL;
	int err = 0, timestamp = 0;
	char *e;

	if (arg) {
		timestamp = strtoul(arg, &e, 10);

		if (arg == e || *e)
			return -EINVAL;
	}

	if (timestamp == 0) {
		h = gdbh;
	}
	else {
		h = database_init(&opt.archive_interval, false, 0);

		if (!h) {
			err = ENOMEM;
			goto out;
		}

		err = database_load(h, opt.db.directory, timestamp);

		if (err)
			goto out;
	}

	if (send_data(sock, h->db, sizeof(*h->db)) != sizeof(*h->db)) {
		err = errno;
		goto out;
	}

	while ((rec = database_next(h, rec)) != NULL)
		if (send_data(sock, rec, db_recsize) != db_recsize) {
			err = errno;
			goto out;
		}

out:
	if (h != gdbh)
		database_free(h);

	return -err;
}

static int
handle_list(int sock, const char *arg)
{
	int err;
	int delta = 0;
	uint32_t timestamp;

	while (true) {
		timestamp = interval_timestamp(&opt.archive_interval, delta--);
		err = database_load(NULL, opt.db.directory, timestamp);

		if (err) {
			if (-err != ENOENT)
				fprintf(stderr, "Corrupted database detected: %d (%s)\n",
				        timestamp, strerror(-err));

			break;
		}

		if (send(sock, &timestamp, sizeof(timestamp), 0) != sizeof(timestamp))
			return -errno;
	}

	return 0;
}

static int
handle_commit(int sock, const char *arg)
{
	uint32_t timestamp = interval_timestamp(&opt.archive_interval, 0);
	char buf[128];
	int err, len;

	err = nlbwmon_save_persistent(timestamp);
	len = snprintf(buf, sizeof(buf), "%d %s", -err,
	               err ? strerror(-err) : "ok");

	if (send_data(sock, buf, len) != len)
		return -errno;

	return 0;
}

static char *format_proto(uint8_t prnum)
{
	static char prstr[16];
	struct protoent *pr = getprotobynumber(prnum);
	if (pr && pr->p_name) {
		snprintf(prstr, sizeof(prstr), "%s", pr->p_name);
	} else {
		snprintf(prstr, sizeof(prstr), "%u", prnum);
	}
	endprotoent();
	return prstr;
}


static int handle_json(int sock, const char *arg)
{
	struct dbhandle *h = NULL;
	struct record *rec = NULL;
	char outbuf[1024]; // Increased buffer size to accommodate more data
	int timestamp = 0, err = 0;
	char *endptr;
	bool first_record = true;

	if (arg) {
		timestamp = strtoul(arg, &endptr, 10);
		if (arg == endptr || *endptr)
			return -EINVAL;
	}

	if (timestamp == 0) {
		h = gdbh;
	} else {
		h = database_init(&opt.archive_interval, false, 0);
		if (!h) {
			err = ENOMEM;
			goto done;
		}
		err = database_load(h, opt.db.directory, timestamp);
		if (err)
			goto done;
	}

	snprintf(outbuf, sizeof(outbuf), "{\"columns\":[\"family\",\"proto\",\"mac\",\"ip\",\"client_name\",\"port\",\"protocol\",\"direction\",\"asn\",\"country\",\"lonlat\",\"conns\",\"rx_bytes\",\"rx_pkts\",\"tx_bytes\",\"tx_pkts\",\"duration\",\"topl_domain\",\"hosts\",\"last_ext_addr\"],\"data\":[");
	if (send_data(sock, outbuf, strlen(outbuf)) != (ssize_t)strlen(outbuf)) {
		err = errno;
		goto done;
	}

	while ((rec = database_next(h, rec)) != NULL) {
		//if (rec->type & RECORD_TYPE_WAN)
		//	continue;

		if (!first_record) {
			if (send_data(sock, ",", 1) != 1) {
				err = errno;
				goto done;
			}
		}
		first_record = false;

		// Build hosts array string
		char hosts_str[512] = "[";
		for (int i = 0; i < RECORD_NUM_HOSTS; i++) {
			if (!rec->hosts[i]) break;
			const char *hostname = dns_get_by_id(rec->hosts[i]);
			if (hostname) {
				if (strlen(hosts_str) > 1) strcat(hosts_str, ",");
				strcat(hosts_str, "\"");
				strcat(hosts_str, hostname);
				strcat(hosts_str, "\"");
			}
		}
		strcat(hosts_str, "]");

		const char *asn_name = lookup_asn(rec->asn);
		const char *topl_domain = rec->topl_domain? dns_get_topl(rec->topl_domain): "";
		const char *client_name;
		if (rec->type & RECORD_TYPE_WAN) {
			client_name = get_wan_name(rec->src_addr.wan_idx);
		} else {
			client_name = lookup_hostname(&rec->src_mac.ea);
		}
		char ext_addr_str[INET6_ADDRSTRLEN];

		strcpy(ext_addr_str, format_ipaddr(rec->family, &rec->last_ext_addr, 1));

		snprintf(outbuf, sizeof(outbuf),
		         "[%d,\"%s\",\"%s\",\"%s\",\"%s\",%u,\"%s\",\"%s\",\"%s\",\"%c%c\",[%f,%f],%"
		         PRIu64 ",%" PRIu64 ",%" PRIu64 ",%"
		         PRIu64 ",%" PRIu64 ",%ld,\"%s\",%s,\"%s\"]",
		         (rec->family == AF_INET ? 4 : 6),
		         format_proto(rec->proto),
		         format_macaddr(&rec->src_mac.ea),
		         rec->type & RECORD_TYPE_WAN ? "0.0.0.0" : format_ipaddr(rec->family, &rec->src_addr, 1),
		         client_name ? client_name : "",
		         be16toh(rec->dst_port),
				 get_protocol_name(rec->proto, be16toh(rec->dst_port)),
				 rec->type & RECORD_TYPE_WAN_IN ? "in" : "out",
		         asn_name ? asn_name : "",
		         rec->country[0] ? rec->country[0] : ' ',
		         rec->country[1] ? rec->country[1] : ' ',
		         rec->lonlat[0]/1000000.0, rec->lonlat[1]/1000000.0,
		         be64toh(rec->count),
		         be64toh(rec->in_bytes),
		         be64toh(rec->in_pkts),
		         be64toh(rec->out_bytes),
		         be64toh(rec->out_pkts),
		         rec->duration,
		         topl_domain ? topl_domain : "",
		         hosts_str,
		         ext_addr_str);

		if (send_data(sock, outbuf, strlen(outbuf)) != (ssize_t)strlen(outbuf)) {
			err = errno;
			goto done;
		}
	}

	if (send_data(sock, "]}", 2) != 2)
		err = errno;

done:
	if (h && h != gdbh)
		database_free(h);

	return -err;
}

static struct command commands[] = {
	{ "dump", handle_dump },
	{ "list", handle_list },
	{ "commit", handle_commit },
	{ "json", handle_json },
};


static void
handle_client_accept(struct uloop_fd *ufd, unsigned int ev);

static void
handle_client_timeout(struct uloop_timeout *tm)
{
	uloop_timeout_cancel(&sock_tm);

	uloop_fd_delete(&sock_fd);
	close(sock_fd.fd);

	sock_fd.cb = handle_client_accept;
	sock_fd.fd = ctrl_socket;

	uloop_fd_add(&sock_fd, ULOOP_READ);
}

static void
handle_client_request(struct uloop_fd *ufd, unsigned int ev)
{
	char *cmd, *arg, buf[32] = { };
	size_t len;
	int i, err;

	len = recv(ufd->fd, buf, sizeof(buf) - 1, 0);

	if (len > 0) {
		cmd = strtok(buf, " \t\n");
		arg = strtok(NULL, " \t\n");

		for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
			if (!strcmp(commands[i].cmd, cmd)) {
				err = commands[i].cb(ufd->fd, arg);
				if (err) {
					fprintf(stderr, "Unable to handle '%s' command: %s\n",
					        buf, strerror(-err));
				}
			}
	}

	handle_client_timeout(&sock_tm);
}

static void
handle_client_accept(struct uloop_fd *ufd, unsigned int ev)
{
	int fd, lfd = ufd->fd;

	while (1) {
		fd = accept(lfd, NULL, NULL);

		if (fd < 0)
			return;

		uloop_fd_delete(ufd);

		ufd->cb = handle_client_request;
		ufd->fd = fd;

		uloop_fd_add(ufd, ULOOP_READ);

		sock_tm.cb = handle_client_timeout;
		uloop_timeout_set(&sock_tm, 100);
	}
}


int
socket_net_init(const char *port)
{

	ctrl_socket = usock(USOCK_TCP | USOCK_SERVER | USOCK_IPV4ONLY | USOCK_NUMERIC | USOCK_NONBLOCK, "127.0.0.1", port);

	if (ctrl_socket < 0)
		return -errno;

	sock_fd.fd = ctrl_socket;
	sock_fd.cb = handle_client_accept;

	uloop_fd_add(&sock_fd, ULOOP_READ);

	return 0;
}
