/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <stdio.h>
#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>

#include "gatchat.h"
#include "gatresult.h"

#include "atmodem.h"
#include "vendor.h"

static const char *none_prefix[] = { NULL };
static const char *gcap_prefix[] = { "+GCAP:", NULL };

struct devinfo_data {
	GAtChat *chat;
	unsigned int vendor;
};

static void info_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_devinfo_query_cb_t cb = cbd->cb;
	struct ofono_error error;
	char *attr;
	GAtResultIter iter;
	size_t len=0;

	decode_at_error(&error, g_at_result_final_response(result));
	if(!ok){
		cb(&error, NULL, cbd->data);
		return;
	}
	g_at_result_iter_init(&iter, result);
	while(g_at_result_iter_next(&iter, NULL))
		len += strlen(g_at_result_iter_raw_line(&iter))+1;
	attr = g_new0(char, len+1);
	g_at_result_iter_init(&iter, result);
	while(g_at_result_iter_next(&iter, NULL))
		sprintf(attr+strlen(attr),*attr?" %s":"%s", g_at_result_iter_raw_line(&iter));
	cb(&error, attr, cbd->data);
	return;
}

static void at_query_information(struct ofono_devinfo *info, ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	const char *info_cmd = "ATI";
	if(dd->vendor==OFONO_VENDOR_GEMALTO) info_cmd = "ATI1";
	if(dd->vendor==OFONO_VENDOR_ZTE_VANILLA) info_cmd = "AT";

	if (g_at_chat_send(dd->chat, info_cmd, NULL, info_cb, cbd, g_free) > 0)
		return;
	g_free(cbd);
	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void attr_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_devinfo_query_cb_t cb = cbd->cb;
	const char *prefix = cbd->user;
	struct ofono_error error;
	const char *attr;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, NULL, cbd->data);
		return;
	}

	if (at_util_parse_attr(result, prefix, &attr) == FALSE) {
		CALLBACK_WITH_FAILURE(cb, NULL, cbd->data);
		return;
	}

	cb(&error, attr, cbd->data);
}

static void at_query_manufacturer(struct ofono_devinfo *info, ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	cbd->user = "+CGMI:";

	if (g_at_chat_send(dd->chat, "AT+CGMI", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void at_query_model(struct ofono_devinfo *info, ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	cbd->user = "+CGMM:";

	if (g_at_chat_send(dd->chat, "AT+CGMM", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void at_query_revision(struct ofono_devinfo *info, ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	cbd->user = "+CGMR:";

	if (g_at_chat_send(dd->chat, "AT+CGMR", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void at_query_serial(struct ofono_devinfo *info, ofono_devinfo_query_cb_t cb, void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	cbd->user = "+CGSN:";

	if (g_at_chat_send(dd->chat, "AT+CGSN", NULL, attr_cb, cbd, g_free) > 0)
		return;

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, NULL, data);
}

static void capability_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_devinfo *info = user_data;

	ofono_devinfo_register(info);
}

static int at_devinfo_probe(struct ofono_devinfo *info, unsigned int vendor,
				void *data)
{
	struct devinfo_data *dd = g_new0(struct devinfo_data, 1);

	dd->chat = g_at_chat_clone(data);
	dd->vendor = vendor;

	ofono_devinfo_set_data(info, dd);
	if(vendor==OFONO_VENDOR_ZTE_VANILLA)
		g_at_chat_send(dd->chat, "AT", none_prefix, capability_cb, info, NULL);
	else
		g_at_chat_send(dd->chat, "AT+GCAP", gcap_prefix, capability_cb, info, NULL);
	return 0;
}

static void at_devinfo_remove(struct ofono_devinfo *info)
{
	struct devinfo_data *dd = ofono_devinfo_get_data(info);

	ofono_devinfo_set_data(info, NULL);

	g_at_chat_unref(dd->chat);
	g_free(dd);
}

static const struct ofono_devinfo_driver driver = {
	.name			= "atmodem",
	.probe			= at_devinfo_probe,
	.remove			= at_devinfo_remove,
	.query_manufacturer	= at_query_manufacturer,
	.query_model		= at_query_model,
	.query_revision		= at_query_revision,
	.query_information	= at_query_information,
	.query_serial		= at_query_serial,
};

void at_devinfo_init(void)
{
	ofono_devinfo_driver_register(&driver);
}

void at_devinfo_exit(void)
{
	ofono_devinfo_driver_unregister(&driver);
}
