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
#include <glib.h>
#include <errno.h>
#include <gdbus.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include "ofono.h"
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/history.h>
#include <ofono/types.h>
#include <ofono/dbus.h>

#include "common.h"

#define SMS_HISTORY_INTERFACE OFONO_SERVICE ".smsHistory"

static int history_sms_report_disable(struct ofono_modem *modem);
static int history_sms_report_enable(struct ofono_modem *modem);
static int history_sms_signal(struct ofono_modem *modem, const char *smsid , enum ofono_history_sms_status status);

static int history_probe(struct ofono_history_context *context)
{

	DBG("Probe History modem: %p", context->modem);

	return history_sms_report_enable(context->modem);

}

static void history_remove(struct ofono_history_context *context)
{
	DBG("Remove History modem: %p", context->modem);
	history_sms_report_disable(context->modem);
}

static void history_sms_received(struct ofono_history_context *context,
						const struct ofono_uuid *uuid,
						const char *from,
						const struct tm *remote,
						const struct tm *local,
						const char *text)
{
	DBG("Incoming SMS on modem: %p", context->modem);
}

static void history_sms_send_pending(struct ofono_history_context *context,
						const struct ofono_uuid *uuid,
						const char *to, time_t when,
						const char *text)
{
	DBG("Sending SMS on modem: %p", context->modem);
}

static void history_sms_send_status(
					struct ofono_history_context *context,
					const struct ofono_uuid *uuid,
					time_t when,
					enum ofono_history_sms_status s)
{
	DBG("%p",context->modem);

	switch (s) {
	case OFONO_HISTORY_SMS_STATUS_PENDING:
		break;
	case OFONO_HISTORY_SMS_STATUS_SUBMITTED:
		DBG("SMS %s submitted successfully ",
					ofono_uuid_to_str(uuid));
		break;
	case OFONO_HISTORY_SMS_STATUS_SUBMIT_FAILED:
		DBG("Sending SMS %s failed", ofono_uuid_to_str(uuid));
		break;
	case OFONO_HISTORY_SMS_STATUS_SUBMIT_CANCELLED:
		DBG("Submission of SMS %s was canceled",
					ofono_uuid_to_str(uuid));
		break;
	case OFONO_HISTORY_SMS_STATUS_DELIVERED:
		DBG("SMS delivered, msg_id: %s",
					ofono_uuid_to_str(uuid));
		break;
	case OFONO_HISTORY_SMS_STATUS_DELIVER_FAILED:
		DBG("SMS undeliverable, msg_id: %s",
					ofono_uuid_to_str(uuid));
		break;
	default:
		break;
	}

	history_sms_signal(context->modem,ofono_uuid_to_str(uuid),s);
}

static const GDBusSignalTable smsUpdate_signals[] = {
	{ GDBUS_SIGNAL("smsStatusUpdate",
			GDBUS_ARGS({ "update", "a{sv}" }) )},
	{}
};

static int history_sms_report_disable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	if (g_dbus_unregister_interface(conn, path,
				SMS_HISTORY_INTERFACE))
		ofono_modem_remove_interface(modem,
				SMS_HISTORY_INTERFACE);

   return 0;
}

static int history_sms_report_enable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	DBG("%p",modem);

	if (!g_dbus_register_interface(conn, path,
					SMS_HISTORY_INTERFACE,
					NULL,
					smsUpdate_signals,
					NULL,
					NULL,
					NULL)) {
		DBG("SMS History : Could not register interface %s, path %s",
					SMS_HISTORY_INTERFACE, path);
		return -EIO;
	} else {
		ofono_info("SMS History : Registered inteface %s, path %s",
					SMS_HISTORY_INTERFACE, path);
	}

	ofono_modem_add_interface(modem, SMS_HISTORY_INTERFACE);
	return 0;

}

static int history_sms_signal(struct ofono_modem *modem, const char *smsid , enum ofono_history_sms_status status)
{
	DBusMessageIter dict,iter;
	dbus_uint16_t sms_status = status;

	const char *path = ofono_modem_get_path(modem);
	DBusConnection *conn = ofono_dbus_get_connection();
	DBusMessage *signal = dbus_message_new_signal(path,
					SMS_HISTORY_INTERFACE,
					"smsStatusUpdate");
	if (signal == NULL) {
		DBG("Cannot create new signal message");
		return -1;
	}

	dbus_message_iter_init_append(signal, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);
	ofono_dbus_dict_append(&dict, "SmsId",
					DBUS_TYPE_STRING, &smsid);
    ofono_dbus_dict_append(&dict, "Status",
					DBUS_TYPE_UINT16, &sms_status);

	dbus_message_iter_close_container(&iter, &dict);
	return g_dbus_send_message(conn, signal);
}


static struct ofono_history_driver history_driver = {
	.name = "History",
	.probe = history_probe,
	.remove = history_remove,
	.sms_received = history_sms_received,
	.sms_send_pending = history_sms_send_pending,
	.sms_send_status = history_sms_send_status,
};

static int history_init(void)
{
	return ofono_history_driver_register(&history_driver);
}

static void history_exit(void)
{
	ofono_history_driver_unregister(&history_driver);
}

OFONO_PLUGIN_DEFINE(sms_history, "SMS History",
			VERSION, OFONO_PLUGIN_PRIORITY_DEFAULT,
			history_init, history_exit)
