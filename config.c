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

#include <stdlib.h>
#include <uci.h>

#include "utils.h"
#include "config.h"

#define CONFIG_PATH_PREFIX "nlbwmon.@nlbwmon[0]."

static struct uci_context *config_uci_ctx;
static struct uci_ptr config_uci_ptr;

const char *config_get(const char *key)
{
	char path[100];

	if (!config_uci_ctx) {
		error_printf("Error in luci init.\n");
		return NULL;
	}

	snprintf(path, sizeof(path), "%s%s", CONFIG_PATH_PREFIX, key);

	if ((uci_lookup_ptr(config_uci_ctx, &config_uci_ptr, path, true) != UCI_OK) ||
			(config_uci_ptr.o==NULL || config_uci_ptr.o->v.string==NULL))

	{

		return NULL;

	}

	return config_uci_ptr.o->v.string;
}

uint32_t config_get_uint32(const char *key, uint32_t def)
{
	const char *v = config_get(key);

	if (!v) return def;

	return atoi(v);
}

int config_set(const char *key, const char *value)
{
	char path[100];

	if (!config_uci_ctx) {
		error_printf("Error in luci init.\n");
		return -1;
	}

	snprintf(path, sizeof(path), "%s%s", CONFIG_PATH_PREFIX, key);

	if (uci_lookup_ptr(config_uci_ctx, &config_uci_ptr, path, true) != UCI_OK) {
		return -1;
	}

	config_uci_ptr.value = value;

	if ((uci_set(config_uci_ctx, &config_uci_ptr) != UCI_OK) || (config_uci_ptr.o==NULL || config_uci_ptr.o->v.string==NULL))
            return -1;

	uci_commit(config_uci_ctx, &config_uci_ptr.p, false);

	return 0;
}

__attribute__((constructor)) static void config_ctor(void)
{
	config_uci_ctx = uci_alloc_context();
}
