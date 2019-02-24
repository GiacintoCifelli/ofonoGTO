/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018 Gemalto M2M
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ofono/modem.h>
#include <ofono/gprs-context.h>
#include <ofono/log.h>
#include <ofono/lte.h>

#include "gatchat.h"
#include "gatresult.h"

#include "gemaltomodem.h"

static const char *none_prefix[] = { NULL };

struct gemalto_lte_driver_data {
	GAtChat *chat;
	struct ofono_lte_default_attach_info pending_info;
	struct ofono_modem *modem;
};

static void gemalto_lte_set_auth_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_lte_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));
	cb(&error, cbd->data);
}

static void gemalto_lte_set_default_attach_info_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_lte_cb_t cb = cbd->cb;
	void *data = cbd->data;
	struct gemalto_lte_driver_data *ldd = cbd->user;
	struct ofono_error error;
	char *buf;
	enum ofono_gprs_auth_method auth_method;

	if (!ok) {
		decode_at_error(&error, g_at_result_final_response(result));
		cb(&error, data);
		return;
	}

	auth_method = ldd->pending_info.auth_method;

	/* change the authentication method if the  parameters are invalid */
	if (!*ldd->pending_info.username || !*ldd->pending_info.password)
		auth_method = OFONO_GPRS_AUTH_METHOD_NONE;

	buf = gemalto_get_auth_command(ldd->modem, 0, auth_method,
			ldd->pending_info.username, ldd->pending_info.password);
	cbd = cb_data_ref(cbd);

	if (g_at_chat_send(ldd->chat, buf, none_prefix,
			gemalto_lte_set_auth_cb, cbd, cb_data_unref) > 0)
		goto end;

	cb_data_unref(cbd);
	CALLBACK_WITH_FAILURE(cb, data);
end:
	g_free(buf);
}

static void gemalto_lte_set_default_attach_info(const struct ofono_lte *lte,
			const struct ofono_lte_default_attach_info *info,
			ofono_lte_cb_t cb, void *data)
{
	struct ofono_modem *modem = ofono_lte_get_modem(lte);
	struct gemalto_lte_driver_data *ldd = ofono_lte_get_data(lte);
	struct cb_data *cbd = cb_data_new(cb, data);
	char *buf = gemalto_get_cgdcont_command(modem, 0, info->proto,
								info->apn);

	cbd->user = ldd;
	memcpy(&ldd->pending_info, info, sizeof(ldd->pending_info));
	ldd->modem = modem;

	if (g_at_chat_send(ldd->chat, buf, none_prefix,
					gemalto_lte_set_default_attach_info_cb,
					cbd, cb_data_unref) > 0)
		goto end;

	cb_data_unref(cbd);
	CALLBACK_WITH_FAILURE(cb, data);
end:
	g_free(buf);
}

static gboolean gemalto_lte_delayed_register(gpointer user_data)
{
	struct ofono_lte *lte = user_data;

	ofono_lte_register(lte);

	return FALSE;
}

static int gemalto_lte_probe(struct ofono_lte *lte, unsigned int vendor,
								void *data)
{
	GAtChat *chat = data;
	struct gemalto_lte_driver_data *ldd;

	ldd = g_new0(struct gemalto_lte_driver_data, 1);

	ldd->chat = g_at_chat_clone(chat);

	ofono_lte_set_data(lte, ldd);

	g_idle_add(gemalto_lte_delayed_register, lte);

	return 0;
}

static void gemalto_lte_remove(struct ofono_lte *lte)
{
	struct gemalto_lte_driver_data *ldd = ofono_lte_get_data(lte);

	g_at_chat_unref(ldd->chat);

	ofono_lte_set_data(lte, NULL);

	g_free(ldd);
}

static const struct ofono_lte_driver driver = {
	.name				= "gemaltomodem",
	.probe				= gemalto_lte_probe,
	.remove				= gemalto_lte_remove,
	.set_default_attach_info	= gemalto_lte_set_default_attach_info,
};

void gemalto_lte_init(void)
{
	ofono_lte_driver_register(&driver);
}

void gemalto_lte_exit(void)
{
	ofono_lte_driver_unregister(&driver);
}
