/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2017 Piotr Haber. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include "gatchat.h"
#include "gatresult.h"

#include "gemaltomodem.h"

static const char *none_prefix[] = { NULL };

enum state {
	STATE_IDLE,
	STATE_ENABLING,
	STATE_DISABLING,
	STATE_ACTIVE,
};

struct gprs_context_data {
	GAtChat *chat;
	unsigned int active_context;
	enum state state;
	ofono_gprs_context_cb_t cb;
	void *cb_data;
	int use_wwan;
};

static void failed_setup(struct ofono_gprs_context *gc,
				GAtResult *result, gboolean deactivate)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_error error;
	char buf[64];

	DBG("deactivate %d", deactivate);

	if (deactivate == TRUE) {
		if (gcd->use_wwan)
			sprintf(buf, "AT^SWWAN=0,%u", gcd->active_context);
		else
			sprintf(buf, "AT+CGACT=%u,0", gcd->active_context);

		g_at_chat_send(gcd->chat, buf, none_prefix, NULL, NULL, NULL);
	}

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;

	if (result == NULL) {
		CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
		return;
	}

	decode_at_error(&error, g_at_result_final_response(result));
	gcd->cb(&error, gcd->cb_data);
}

static void activate_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	const char *interface;

	DBG("ok %d", ok);

	if (!ok) {
		ofono_error("Unable to activate context");
		failed_setup(gc, result, FALSE);
		return;
	}

	gcd->state = STATE_ACTIVE;
	interface = ofono_modem_get_string(modem, "NetworkInterface");
	ofono_gprs_context_set_interface(gc, interface);

	/* use DHCP for all modems for compatibility with the entire family */
	ofono_gprs_context_set_ipv4_address(gc, NULL, FALSE);

	CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static void gemalto_gprs_activate_primary(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);
	char *buf_apn;
	char *buf_auth;
	char buf[256];

	DBG("cid %u", ctx->cid);

	gcd->use_wwan = ofono_modem_get_integer(modem, "GemaltoWwan");
	gcd->active_context = ctx->cid;
	gcd->cb = cb;
	gcd->cb_data = data;
	gcd->state = STATE_ENABLING;

	buf_apn = gemalto_get_cgdcont_command(modem, ctx->cid, ctx->proto,
								ctx->apn);
	buf_auth = gemalto_get_auth_command(modem, gcd->active_context,
				ctx->auth_method, ctx->username, ctx->password);

	/*
	 * note that if the cgdcont or auth commands are not ok we ignore them
	 * and continue but if the sending fails we do an error
	 */
	if (!g_at_chat_send(gcd->chat, buf_apn, none_prefix,
						NULL, NULL, NULL) ||
			!g_at_chat_send(gcd->chat, buf_auth, none_prefix,
						NULL, NULL, NULL)) {
		failed_setup(gc, NULL, FALSE);
		goto end;
	}

	if (gcd->use_wwan)
		sprintf(buf, "AT^SWWAN=1,%u", gcd->active_context);
	else
		sprintf(buf, "AT+CGACT=%u,1", gcd->active_context);

	if (g_at_chat_send(gcd->chat, buf, none_prefix,
					activate_cb, gc, NULL) > 0){
		goto end;
	}

	failed_setup(gc, NULL, FALSE);
end:
	g_free(buf_apn);
	g_free(buf_auth);
}

static void deactivate_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("ok %d", ok);

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;

	CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static void gemalto_gprs_deactivate_primary(struct ofono_gprs_context *gc,
					unsigned int cid,
					ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	char buf[64];

	DBG("cid %u", cid);

	gcd->state = STATE_DISABLING;
	gcd->cb = cb;
	gcd->cb_data = data;

	if (gcd->use_wwan)
		sprintf(buf, "AT^SWWAN=0,%u", gcd->active_context);
	else
		sprintf(buf, "AT+CGACT=%u,0", gcd->active_context);

	if (g_at_chat_send(gcd->chat, buf, none_prefix,
						deactivate_cb, gc, NULL) > 0)
		return;

	CALLBACK_WITH_SUCCESS(cb, data);
}

static void cgev_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	const char *event;
	int cid;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CGEV:"))
		return;

	if (!g_at_result_iter_next_unquoted_string(&iter, &event))
		return;

	DBG("%s", event);

	if (!g_str_has_prefix(event, "NW DEACT"))
		return;

	if (!g_at_result_iter_skip_next(&iter)) // "DEACT"
		return;

	if (!g_at_result_iter_next_number(&iter, &cid))
		return;

	DBG("cid %d", cid);

	if ((unsigned int) cid != gcd->active_context)
		return;

	ofono_gprs_context_deactivated(gc, gcd->active_context);

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;
}

static int gemalto_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int vendor, void *data)
{
	GAtChat *chat = data;
	struct gprs_context_data *gcd;

	DBG("");

	gcd = g_try_new0(struct gprs_context_data, 1);
	if (gcd == NULL)
		return -ENOMEM;

	gcd->chat = g_at_chat_clone(chat);

	ofono_gprs_context_set_data(gc, gcd);

	g_at_chat_register(chat, "+CGEV:", cgev_notify, FALSE, gc, NULL);

	return 0;
}

static void gemalto_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	g_at_chat_unref(gcd->chat);
	g_free(gcd);
}

static const struct ofono_gprs_context_driver driver = {
	.name			= "gemaltomodemswwan",
	.probe			= gemalto_gprs_context_probe,
	.remove			= gemalto_gprs_context_remove,
	.activate_primary	= gemalto_gprs_activate_primary,
	.deactivate_primary	= gemalto_gprs_deactivate_primary,
};

void gemalto_gprs_context_swwan_init(void)
{
	ofono_gprs_context_driver_register(&driver);
}

void gemalto_gprs_context_swwan_exit(void)
{
	ofono_gprs_context_driver_unregister(&driver);
}
