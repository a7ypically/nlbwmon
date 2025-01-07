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
#include <libubox/ustream.h>

#include "utils.h"
#include "config.h"
#include "https.h"
#include "abuseipdb.h"

static char *AbuseipdbToken;
static AbuseipdbCB AbuseipdbRespCB;
static void *AbuseipdbRespCBData;
static int AbuseipdbInProgress;
static struct https_ctx *abuseipdb_https_ctx;
static char AbuseipdbErrMsg[128];

static int abuseipdb_on_data_cb(struct ustream *s, int eof) {

	if (!eof) return 0;
	if (!AbuseipdbInProgress) return -1;

	char *buf;
	int len;
	
	debug_printf("Ready to parse body\n");
	buf = ustream_get_read_buf(s, &len);

	//Break json to be able to use str funcs.
	//Better use json parser
	buf[len-1] = 0;
	debug_printf("%s\n", buf);

	if (!strstr(buf, "\"errors\":") && strstr(buf, "\"data\":")) {
		int confidence = -1;
		const char *score_pos = "\"abuseConfidenceScore\":";
		char *score = strstr(buf, score_pos);
		if (score) confidence = atoi(score + strlen(score_pos));

		(*AbuseipdbRespCB)(confidence, NULL, AbuseipdbRespCBData);

	} else {
		// Error

		char *start = strstr(buf, "\"detail\":");
		if (start) {
			start = strchr(start+9, '\"') + 1;
			char *end = strchr(start, '\"');
			*end = 0;
			snprintf(AbuseipdbErrMsg, sizeof(AbuseipdbErrMsg), "%s", start);
			(*AbuseipdbRespCB)(-1, AbuseipdbErrMsg, AbuseipdbRespCBData);
		} else {
			(*AbuseipdbRespCB)(-1, "Error reporting IP", AbuseipdbRespCBData);
		}

	}

	ustream_consume(s, len);

	AbuseipdbInProgress = 0;
	return 0;
}

int abuseipdb_report(const char *addr, const char *categories, AbuseipdbCB cb, void *cb_data)
{
	char url[50];
	char data[768];
	snprintf(url, sizeof(url), "/api/v2/report");

	assert(AbuseipdbToken);

	if (AbuseipdbInProgress) {
		(*cb) (1, "Another report is in progress. Try again later.", cb_data);
		return -1;
	}

	AbuseipdbRespCBData = cb_data;
	AbuseipdbRespCB = cb;

	int data_len = snprintf(data, sizeof(data), "key=%s&ip=%s&categories=%s", AbuseipdbToken, urlencode(addr), categories);
	assert(data_len < sizeof(data));
	_unused(data_len);

	AbuseipdbInProgress = 1;

	https_send_msg(abuseipdb_https_ctx, url, data, "application/x-www-form-urlencoded");

	return 0;
}

static void abuseipdb_on_https_error(void)
{
	error_printf("Error in https!\n");
	AbuseipdbRespCB(-1, "Error calling abuseipdb API.", AbuseipdbRespCBData);
}

static struct https_cbs abuseipdb_https_cbs = {
	.data = abuseipdb_on_data_cb,
	.error = abuseipdb_on_https_error,
};

int abuseipdb_enabled(void)
{
	return AbuseipdbToken != NULL;
}

int init_abuseipdb(void)
{
	const char *token = config_get("abuseipdb_token");
	if (!token) return -1;

	AbuseipdbToken = strdup(token);
	abuseipdb_https_ctx = https_init(&abuseipdb_https_cbs, "api.abuseipdb.com", 443, 10);
	https_set_retries(abuseipdb_https_ctx, 0, 10);

	return 0;
}

#ifdef ABUSE_REPORT_TEST
int main(int argc, char **argv)
{
	uloop_init();
	init_abuseipdb();
	abuseipdb_report("167.248.133.188", "14,18", NULL, NULL);
	uloop_run();

	uloop_done();
	return 0;
}
#endif
