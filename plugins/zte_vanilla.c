/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2019 Gemalto M2M
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <gatchat.h>
#include <gattty.h>
#include <gdbus.h>
#include "ofono.h"
#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/dbus.h>
#include <ofono/plugin.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>
#include <ofono/netreg.h>
#include <ofono/sim.h>
#include <ofono/cbs.h>
#include <ofono/sms.h>
#include <ofono/ussd.h>
#include <ofono/gprs.h>
#include <ofono/gprs-context.h>
#include <ofono/phonebook.h>
#include <ofono/log.h>
#include <ofono/lte.h>

#include <drivers/atmodem/atutil.h>
#include <drivers/atmodem/vendor.h>

static const char *none_prefix[] = { NULL };

struct zte_data {
	GAtChat *aux;
	gboolean have_sim;
	struct at_util_sim_state_query *sim_state_query;
};

static int zte_probe(struct ofono_modem *modem)
{
	struct zte_data *data;

	DBG("%p", modem);

	data = g_try_new0(struct zte_data, 1);
	if (data == NULL)
		return -ENOMEM;

	ofono_modem_set_data(modem, data);

	return 0;
}

static void zte_remove(struct ofono_modem *modem)
{
	struct zte_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_modem_set_data(modem, NULL);

	/* Cleanup potential SIM state polling */
	at_util_sim_state_query_free(data->sim_state_query);

	/* Cleanup after hot-unplug */
	g_at_chat_unref(data->aux);

	g_free(data);
}

static void zte_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static GAtChat *open_device(struct ofono_modem *modem,
				const char *key, char *debug)
{
	const char *device;
	GIOChannel *channel;
	GAtSyntax *syntax;
	GAtChat *chat;
	GHashTable *options;

	device = ofono_modem_get_string(modem, key);
	if (device == NULL)
		return NULL;

	DBG("%s %s", key, device);

	options = g_hash_table_new(g_str_hash, g_str_equal);
	if (options == NULL)
		return NULL;

	g_hash_table_insert(options, "Baud", "115200");
	g_hash_table_insert(options, "Parity", "none");
	g_hash_table_insert(options, "StopBits", "1");
	g_hash_table_insert(options, "DataBits", "8");
	g_hash_table_insert(options, "XonXoff", "off");
	g_hash_table_insert(options, "RtsCts", "on");
	g_hash_table_insert(options, "Local", "on");
	g_hash_table_insert(options, "Read", "on");

	channel = g_at_tty_open(device, options);

	g_hash_table_destroy(options);

	if (channel == NULL)
		return NULL;

	syntax = g_at_syntax_new_gsm_permissive();
	chat = g_at_chat_new(channel, syntax);
	g_at_syntax_unref(syntax);

	g_io_channel_unref(channel);

	if (chat == NULL)
		return NULL;

	if (getenv("OFONO_AT_DEBUG"))
		g_at_chat_set_debug(chat, zte_debug, debug);

	return chat;
}

static void cfun_enable(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct zte_data *data = ofono_modem_get_data(modem);
	DBG("");
	if (!ok) {
		g_at_chat_unref(data->aux);
		data->aux = NULL;
		ofono_modem_set_powered(modem, FALSE);
		return;
	}
	ofono_modem_set_powered(modem, TRUE);
}

static void sim_state_cb(gboolean present, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct zte_data *data = ofono_modem_get_data(modem);
	at_util_sim_state_query_free(data->sim_state_query);
	data->sim_state_query = NULL;
	data->have_sim = present;
	g_at_chat_send(data->aux, "AT+CFUN=4", none_prefix, cfun_enable, modem, NULL);
}

/*******************************************************************************
 * Command passthrough interface
 * keeping the gemalto name for ease of filtering in dbus rules
 ******************************************************************************/

#define COMMAND_PASSTHROUGH_INTERFACE OFONO_SERVICE ".gemalto.CommandPassthrough"

static int command_passthrough_signal_answer(const char *answer, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);
	DBusMessage *signal;
	DBusMessageIter iter;

	if (!conn || !path)
		return -1;

	signal = dbus_message_new_signal(path, COMMAND_PASSTHROUGH_INTERFACE,
								"Answer");
	if (!signal) {
		ofono_error("Unable to allocate new %s.PropertyChanged signal",
						COMMAND_PASSTHROUGH_INTERFACE);
		return -1;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &answer);

	DBG("");

	return g_dbus_send_message(conn, signal);
}

static void command_passthrough_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	guint len = 0;
	char *answer;

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, NULL)) {
		len += strlen(g_at_result_iter_raw_line(&iter))+2;
	}

	len += strlen(g_at_result_final_response(result))+3;
	answer = g_new0(char, len);
	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, NULL)) {
		sprintf(answer+strlen(answer),"%s\r\n",
					g_at_result_iter_raw_line(&iter));
	}

	sprintf(answer+strlen(answer),"%s\r\n",
					g_at_result_final_response(result));

	DBG("answer_len: %u, answer_string: %s", len, answer);
	command_passthrough_signal_answer(answer, user_data);

	g_free(answer);
}

static DBusMessage *command_passthrough_simple(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct zte_data *data = ofono_modem_get_data(modem);

	DBusMessageIter iter;
	const char *command;

	if (!dbus_message_iter_init(msg, &iter))
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
							"No arguments given");

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &command);

	g_at_chat_send(data->aux, command, NULL, command_passthrough_cb,
								modem, NULL);

	return dbus_message_new_method_return(msg);
}

static void executeWithPrompt(GAtChat *port, const char *command,
			const char *prompt, const char *argument, void *cb,
			void *cbd, void *freecall)
{
	char *buf;
	const char *expected_array[2] = {0,0};

	buf = g_strdup_printf("%s\r%s", command, argument);

	if (strlen(argument)>=2 && g_str_equal(argument+strlen(argument)-2,
									"^Z"))
		sprintf(buf+strlen(buf)-2,"\x1a");

	if (strlen(argument)>=2 && g_str_equal(argument+strlen(argument)-2,
									"\\r"))
		sprintf(buf+strlen(buf)-2,"\r");

	expected_array[0]=prompt;
	g_at_chat_send_and_expect_short_prompt(port, buf, expected_array,
							cb, cbd, freecall);
	free(buf);
}

static DBusMessage *command_passthrough_with_prompt(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct zte_data *data = ofono_modem_get_data(modem);
	DBusMessageIter iter;
	const char *command, *prompt, *argument;

	if (!dbus_message_iter_init(msg, &iter))
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
							"No arguments given");

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &command);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &prompt);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(msg, DBUS_ERROR_INVALID_ARGS,
					"Invalid argument type: '%c'",
					dbus_message_iter_get_arg_type(&iter));

	dbus_message_iter_get_basic(&iter, &argument);

	executeWithPrompt(data->aux, command, prompt, argument,
					command_passthrough_cb, modem, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *command_passthrough_send_break(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct zte_data *data = ofono_modem_get_data(modem);
	GIOChannel *channel = g_at_chat_get_channel(data->aux);

	g_io_channel_write_chars(channel, "\r", 1, NULL, NULL);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable command_passthrough_methods[] = {
	{ GDBUS_ASYNC_METHOD("Simple",
		GDBUS_ARGS({ "command", "s" }),
		NULL,
		command_passthrough_simple) },
	{ GDBUS_ASYNC_METHOD("WithPrompt",
		GDBUS_ARGS({ "command", "s" }, { "prompt", "s" },
							{ "argument", "s" }),
		NULL,
		command_passthrough_with_prompt) },
	{ GDBUS_ASYNC_METHOD("SendBreak",
		NULL,
		NULL,
		command_passthrough_send_break) },
	{}
};

static const GDBusSignalTable command_passthrough_signals[] = {
	{ GDBUS_SIGNAL("Answer",
		GDBUS_ARGS({ "answer", "s" })) },
	{ }
};

static void gemalto_command_passthrough_enable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	/* Create Command Passthrough DBus interface */
	if (!g_dbus_register_interface(conn, path, COMMAND_PASSTHROUGH_INTERFACE,
					command_passthrough_methods,
					command_passthrough_signals,
					NULL,
					modem,
					NULL)) {
		ofono_error("Could not register %s interface under %s",
					COMMAND_PASSTHROUGH_INTERFACE, path);
		return;
	}

	ofono_modem_add_interface(modem, COMMAND_PASSTHROUGH_INTERFACE);
}

static void gemalto_command_passthrough_disable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	/* Create Command Passthrough DBus interface */
	if (!g_dbus_unregister_interface(conn, path, COMMAND_PASSTHROUGH_INTERFACE)) {
		ofono_error("Could not register %s interface under %s",
			COMMAND_PASSTHROUGH_INTERFACE, path);
		return;
	}

	ofono_modem_remove_interface(modem, COMMAND_PASSTHROUGH_INTERFACE);
}

static int zte_enable(struct ofono_modem *modem)
{
	struct zte_data *data = ofono_modem_get_data(modem);
	DBG("%p", modem);
	data->aux = open_device(modem, "Aux", "Aux: ");
	if(data->aux==NULL) return -EIO;
	g_at_chat_blacklist_terminator(data->aux, G_AT_CHAT_TERMINATOR_NO_CARRIER);
	g_at_chat_send(data->aux, "AT", NULL, NULL, NULL, NULL); /* most likely will return an error at first boot: cannot fix */
	g_at_chat_send(data->aux, "ATE0", NULL, NULL, NULL, NULL);
	g_at_chat_send(data->aux, "AT+CMEE=1", NULL, NULL, NULL, NULL);
	g_at_chat_send(data->aux, "AT+CSCS=\"GSM\"", none_prefix, NULL, NULL, NULL);
	g_at_chat_send(data->aux, "AT+CGAUTO=1", none_prefix, NULL, NULL, NULL);

	data->sim_state_query = at_util_sim_state_query_new(data->aux, 2, 20, sim_state_cb, modem, NULL);
	gemalto_command_passthrough_enable(modem);
	return -EINPROGRESS;
}

static void cfun_disable(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct zte_data *data = ofono_modem_get_data(modem);

	DBG("");

	g_at_chat_unref(data->aux);
	data->aux = NULL;

	if (ok)
		ofono_modem_set_powered(modem, FALSE);
}

static void zoprt_disable(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct zte_data *data = ofono_modem_get_data(modem);

	DBG("");

	g_at_chat_send(data->aux, "AT+CFUN=0", NULL,
					cfun_disable, modem, NULL);
}

static int zte_disable(struct ofono_modem *modem)
{
	struct zte_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);

	gemalto_command_passthrough_disable(modem);
	g_at_chat_cancel_all(data->aux);
	g_at_chat_unregister_all(data->aux);

	/* Switch to offline mode first */
	g_at_chat_send(data->aux, "AT+CFUN=4", none_prefix,
					zoprt_disable, modem, NULL);

	return -EINPROGRESS;
}

static void set_online_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_modem_online_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));
	cb(&error, cbd->data);
}

static void zte_set_online(struct ofono_modem *modem, ofono_bool_t online,
				ofono_modem_online_cb_t cb, void *user_data)
{
	struct zte_data *data = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char const *command = online ? "AT+CFUN=1" : "AT+CFUN=4";

	DBG("modem %p %s", modem, online ? "online" : "offline");

	if (g_at_chat_send(data->aux, command, none_prefix,
					set_online_cb, cbd, g_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, cbd->data);

	g_free(cbd);
}

static void zte_pre_sim(struct ofono_modem *modem)
{
	struct zte_data *data = ofono_modem_get_data(modem);
	struct ofono_sim *sim;

	DBG("%p", modem);

	ofono_devinfo_create(modem, OFONO_VENDOR_ZTE_VANILLA, "atmodem", data->aux);
	sim = ofono_sim_create(modem, OFONO_VENDOR_ZTE_VANILLA, "atmodem", data->aux);

	if (sim && data->have_sim == TRUE)
		ofono_sim_inserted_notify(sim, TRUE);
}

static void zte_post_sim(struct ofono_modem *modem)
{
	struct zte_data *data = ofono_modem_get_data(modem);
	DBG("%p", modem);
	ofono_phonebook_create(modem, 0, "atmodem", data->aux);
	ofono_sms_create(modem, 0, "atmodem", data->aux);
	ofono_lte_create(modem, 0, "ztevanillamodem", data->aux);
}

static void zte_post_online(struct ofono_modem *modem) // untested
{
	struct zte_data *data = ofono_modem_get_data(modem);
	struct ofono_gprs *gprs;
	struct ofono_gprs_context *gc;
	DBG("%p", modem);
	ofono_netreg_create(modem, OFONO_VENDOR_ZTE_VANILLA, "atmodem", data->aux);

	gprs = ofono_gprs_create(modem, OFONO_VENDOR_ZTE_VANILLA, "atmodem", data->aux);
	ofono_gprs_set_cid_range(gprs, 1, 1);
	gc = ofono_gprs_context_create(modem, 0, "ztevanilla", data->aux);

	if (gprs && gc)
		ofono_gprs_add_context(gprs, gc);

}

static struct ofono_modem_driver zte_driver = {
	.name		= "zte_vanilla",
	.probe		= zte_probe,
	.remove		= zte_remove,
	.enable		= zte_enable,
	.disable	= zte_disable,
	.set_online	= zte_set_online,
	.pre_sim	= zte_pre_sim,
	.post_sim	= zte_post_sim,
	.post_online	= zte_post_online,
};

static int zte_init(void)
{
	return ofono_modem_driver_register(&zte_driver);
}

static void zte_exit(void)
{
	ofono_modem_driver_unregister(&zte_driver);
}

OFONO_PLUGIN_DEFINE(zte_vanilla, "ZTE vanilla modem driver", VERSION,
		OFONO_PLUGIN_PRIORITY_DEFAULT, zte_init, zte_exit)
