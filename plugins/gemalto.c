/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2017 Vincent Cesson. All rights reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include <gatchat.h>
#include <gattty.h>
#include <gdbus.h>
#include "ofono.h"
#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/dbus.h>
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/devinfo.h>
#include <ofono/netreg.h>
#include <ofono/phonebook.h>
#include <ofono/sim.h>
#include <ofono/sms.h>
#include <ofono/gprs.h>
#include <ofono/gprs-context.h>
#include <ofono/location-reporting.h>
#include <drivers/atmodem/atutil.h>
#include <drivers/atmodem/vendor.h>
#include <string.h>

#include <ell/ell.h>
#include <drivers/mbimmodem/mbim.h>
#include <drivers/mbimmodem/mbim-message.h>
#include <drivers/mbimmodem/mbim-desc.h>

#include <drivers/qmimodem/qmi.h>
#include <src/storage.h>
#include <ofono/gemalto.h>

/* debug utilities - begin */

#define REDCOLOR "\x1b\x5b\x30\x31\x3b\x33\x31\x6d"
#define NOCOLOR "\x1b\x5b\x30\x30\x6d"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

void print_trace();

void print_trace() {
	char pid_buf[30];
	char name_buf[512];
	int child_pid;
	sprintf(pid_buf, "%d", getpid());
	name_buf[readlink("/proc/self/exe", name_buf, 511)]=0;
	child_pid = fork();
	if (!child_pid) {
		dup2(2,1); // redirect output to stderr
		fprintf(stdout,"stack trace for %s pid=%s\n",name_buf,pid_buf);
		execlp("gdb", "gdb", "--batch", "-n", "-ex", "thread", "-ex", "bt", name_buf, pid_buf, NULL);
		abort(); /* If gdb failed to start */
	} else {
		waitpid(child_pid,NULL,0);
	}
}

/* debug utilities - end */

enum gemalto_connection_type {
	GEMALTO_CONNECTION_SERIAL = 1,
	GEMALTO_CONNECTION_USB = 2,
};

enum gemalto_device_state {
	STATE_ABSENT = 0,
	STATE_PROBE = 1,
	STATE_PRESENT = 2,
};

enum gprs_option {
	NO_GPRS = 0,
	USE_SWWAN = 1,
	USE_CTX17 = 2,
	USE_CTX3 = 3,
	USE_PPP = 4,
	USE_SWWAN_INV = 5,	/* inverted syntax idx,act */
	USE_CTX_INV = 6,	/* inverted syntax idx,act */
};

static const char *none_prefix[] = { NULL };
static const char *cfun_prefix[] = { "+CFUN:", NULL };
static const char *sctm_prefix[] = { "^SCTM:", NULL };
static const char *sbv_prefix[] = { "^SBV:", NULL };
static const char *sqport_prefix[] = { "^SQPORT:", NULL };
static const char *sgpsc_prefix[] = { "^SGPSC:", NULL };

typedef void (*OpenResultFunc)(gboolean success, struct ofono_modem *modem);

struct gemalto_data {
	gboolean init_done;
	GIOChannel *channel;
	GAtChat *tmp_chat;
	OpenResultFunc open_cb;
	guint portfd;
	GAtChat *app;
	GAtChat *mdm;
	int cfun;

	struct ofono_sim *sim;
	gboolean have_sim;
	struct at_util_sim_state_query *sim_state_query;
	guint modem_ready_id;

	char modelstr[32];
	char sqport[32];

	guint model;
	guint probing_timer;
	guint init_waiting_time;
	guint waiting_time;
	guint online_timer;

	enum gemalto_connection_type conn;
	enum gemalto_device_state mbim;
	enum gemalto_device_state qmi;
	enum gemalto_device_state ecmncm;
	enum gemalto_device_state gina;
	gboolean voice_avail;
	enum auth_option auth_syntax;
	enum gprs_option gprs_opt;
	gboolean has_lte;
	gboolean autoattach;
	gboolean autoconfig;
	gboolean autoactivation;
	gboolean vts_with_quotes;

	struct ofono_netreg *netreg;

	struct mbim_device *mbimd;
	struct qmi_device  *qmid;

	/* mbim data */
	uint16_t max_segment;
	uint8_t max_outstanding;
	uint8_t max_sessions;

	/* hardware monitor variables */
	struct {
		DBusMessage *msg;
		int32_t temperature;
		int32_t voltage;
		guint sctm;
		guint sbc;
	} hwmon;
	/* gnss variables */
	DBusMessage *gnss_msg;
	/* hardware control variables */
	DBusMessage *hc_msg;
	gboolean powersave;
};

/*******************************************************************************
 * Generic functions
 ******************************************************************************/

static void gemalto_at_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (getenv("OFONO_AT_DEBUG"))
		ofono_info("%s%s", prefix, str);
}

static void gemalto_mbim_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (getenv("OFONO_MBIM_DEBUG"))
		ofono_info("%s%s", prefix, str);
}

static void gemalto_qmi_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (getenv("OFONO_QMI_DEBUG"))
		ofono_info("%s%s", prefix, str);
}

static const char *gemalto_get_string(struct ofono_modem *modem, const char *k)
{
	const char *v;

	if (!modem || !k || !*k)
		return NULL;

	v = ofono_modem_get_string(modem, k);

	if (!v || !*v)
		return NULL;

	return v;
}

static void gemalto_signal(const char *iface, const char *name,
	const char *value, struct ofono_modem *modem)
{
	DBusMessageIter sub_iter,iter;
	const char *path = ofono_modem_get_path(modem);
	DBusConnection *conn = ofono_dbus_get_connection();

	DBusMessage *signal = dbus_message_new_signal(path,
					iface,
					name);

	DBG("");

	if (signal == NULL) {
		DBG("Cannot create new signal message");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
							"s", &sub_iter);
	if (!dbus_message_iter_append_basic(&sub_iter,
				DBUS_TYPE_STRING, &value)) {
		DBG("Out of memory!");
		return;
	}

	dbus_message_iter_close_container(&iter, &sub_iter);
	g_dbus_send_message(conn, signal);
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

static void gemalto_exec_stored_cmd(struct ofono_modem *modem,
							const char *filename)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *vid = gemalto_get_string(modem, "Vendor");
	const char *pid = gemalto_get_string(modem, "Model");
	char store[64];
	int index;
	char *command, *prompt, *argument;
	char key[32];
	GKeyFile *f;

	sprintf(store,"%s-%s/%s", vid, pid, filename);
	f = storage_open(NULL, store);

	if (!f)
		return;

	for (index = 0; ; index++) {
		sprintf(key, "command_%d", index);
		command = g_key_file_get_string(f, "Simple", key, NULL);

		if (!command)
			break;

		DBG(REDCOLOR"executing stored command simple: %s"NOCOLOR, command);
		g_at_chat_send(data->app, command, NULL, NULL, NULL, NULL);
	}

	for (index = 0; ; index++) {
		sprintf(key, "command_%d", index);
		command = g_key_file_get_string(f, "WithPrompt", key, NULL);
		sprintf(key, "prompt_%d", index);
		prompt = g_key_file_get_string(f, "WithPrompt", key, NULL);
		sprintf(key, "argument_%d", index);
		argument = g_key_file_get_string(f, "WithPrompt", key, NULL);

		if (!command || !prompt || !argument)
			break;

		DBG("executing stored command with prompt: %s", command);
		executeWithPrompt(data->app, command, prompt, argument,
			NULL, NULL, NULL);
	}

	storage_close(NULL, store, f, FALSE);
}

/*******************************************************************************
 * Hardware monitor interface
 ******************************************************************************/

#define HARDWARE_MONITOR_INTERFACE OFONO_SERVICE ".gemalto.HardwareMonitor"
#define CINTERION_LEGACY_HWMON_INTERFACE OFONO_SERVICE ".cinterion.HardwareMonitor"

static void gemalto_sctmb_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	gint value;
	char *val;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^SCTM_B:");
	g_at_result_iter_next_number(&iter, &value);

	switch(value) {
	case -1:
		val="Below low temperature alert limit";
		break;
	case 0:
		val="Normal operating temperature";
		break;
	case 1:
		val="Above upper temperature alert limit";
		break;
	case 2:
		val="Above uppermost temperature limit";
		break;
	default: /* unvalid value, do not output signal*/
		return;
	}

	gemalto_signal(HARDWARE_MONITOR_INTERFACE, "CriticalTemperature", val,
								user_data);
}

static void gemalto_sbc_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *value;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^SBC:");
	g_at_result_iter_next_unquoted_string(&iter, &value);
	gemalto_signal(HARDWARE_MONITOR_INTERFACE, "CriticalVoltage", value,
								user_data);
}

static void gemalto_sctm_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = user_data;
	DBusMessage *reply;
	GAtResultIter iter;
	DBusMessageIter dbus_iter;
	DBusMessageIter dbus_dict;

	if (data->hwmon.msg == NULL)
		return;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "^SCTM:"))
		goto error;

	if (!g_at_result_iter_skip_next(&iter))
		goto error;

	if (!g_at_result_iter_skip_next(&iter))
		goto error;

	if (!g_at_result_iter_next_number(&iter, &data->hwmon.temperature))
		goto error;

	reply = dbus_message_new_method_return(data->hwmon.msg);

	dbus_message_iter_init_append(reply, &dbus_iter);

	dbus_message_iter_open_container(&dbus_iter, DBUS_TYPE_ARRAY,
			OFONO_PROPERTIES_ARRAY_SIGNATURE,
			&dbus_dict);

	ofono_dbus_dict_append(&dbus_dict, "Temperature",
			DBUS_TYPE_INT32, &data->hwmon.temperature);

	ofono_dbus_dict_append(&dbus_dict, "Voltage",
			DBUS_TYPE_UINT32, &data->hwmon.voltage);

	dbus_message_iter_close_container(&dbus_iter, &dbus_dict);

	__ofono_dbus_pending_reply(&data->hwmon.msg, reply);

	return;

error:
	__ofono_dbus_pending_reply(&data->hwmon.msg,
			__ofono_error_failed(data->hwmon.msg));
}

static void gemalto_sbv_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = user_data;
	GAtResultIter iter;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "^SBV:"))
		goto error;

	if (!g_at_result_iter_next_number(&iter, &data->hwmon.voltage))
		goto error;

	if (g_at_chat_send(data->app, "AT^SCTM?", sctm_prefix, gemalto_sctm_cb,
				data, NULL) > 0)
		return;

error:
	__ofono_dbus_pending_reply(&data->hwmon.msg,
			__ofono_error_failed(data->hwmon.msg));
}

static DBusMessage *hardware_monitor_get_statistics(DBusConnection *conn,
							DBusMessage *msg,
							void *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	DBG("");

	if (data->hwmon.msg != NULL)
		return __ofono_error_busy(msg);

	if (!g_at_chat_send(data->app, "AT^SBV", sbv_prefix, gemalto_sbv_cb,
			data, NULL))
		return __ofono_error_failed(msg);

	data->hwmon.msg = dbus_message_ref(msg);

	return NULL;
}

static const GDBusMethodTable hardware_monitor_methods[] = {
	{ GDBUS_ASYNC_METHOD("GetStatistics",
			NULL, GDBUS_ARGS({ "Statistics", "a{sv}" }),
			hardware_monitor_get_statistics) },
	{}
};

static const GDBusSignalTable hardware_monitor_signals[] = {
	{ GDBUS_SIGNAL("CriticalTemperature",
			GDBUS_ARGS({ "temperature", "a{sv}" }) )},
	{ GDBUS_SIGNAL("CriticalVoltage",
			GDBUS_ARGS({ "voltage", "a{sv}" }) )},
	{}
};

static void gemalto_hardware_monitor_enable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	/* Listen to over/undertemperature URCs (activated with AT^SCTM) */
	data->hwmon.sctm = g_at_chat_register(data->app, "^SCTM_B:",
		gemalto_sctmb_notify, FALSE, NULL, NULL);
	/* Listen to over/under voltage URCs (automatic URC) */
	data->hwmon.sbc = g_at_chat_register(data->app, "^SBC:",
		gemalto_sbc_notify, FALSE, NULL, NULL);
	/* Enable temperature URC and value output */
	g_at_chat_send(data->app, "AT^SCTM=1,1", none_prefix, NULL, NULL, NULL);

	if (!g_dbus_register_interface(conn, path, HARDWARE_MONITOR_INTERFACE,
					hardware_monitor_methods,
					hardware_monitor_signals,
					NULL,
					modem,
					NULL)) {
		ofono_error("Could not register %s interface under %s",
					HARDWARE_MONITOR_INTERFACE, path);
		return;
	}

	ofono_modem_add_interface(modem, HARDWARE_MONITOR_INTERFACE);

	if (!g_dbus_register_interface(conn, path,
					CINTERION_LEGACY_HWMON_INTERFACE,
					hardware_monitor_methods,
					NULL,
					NULL,
					modem,
					NULL)) {
		ofono_error("Could not register %s interface under %s",
					CINTERION_LEGACY_HWMON_INTERFACE, path);
		return;
	}

	ofono_modem_add_interface(modem, CINTERION_LEGACY_HWMON_INTERFACE);
}

static void gemalto_hardware_monitor_disable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	/* Disable temperature URC */
	if (data->app) {
		g_at_chat_send(data->app, "AT^SCTM=0", none_prefix, NULL, NULL, NULL);
		if (data->hwmon.sbc) g_at_chat_unregister(data->app, data->hwmon.sbc);
		if (data->hwmon.sctm) g_at_chat_unregister(data->app, data->hwmon.sctm);
	}

	if (!g_dbus_unregister_interface(conn, path, HARDWARE_MONITOR_INTERFACE)) {
		ofono_error("Could not unregister %s interface under %s",
			HARDWARE_MONITOR_INTERFACE, path);
	}

	ofono_modem_remove_interface(modem, HARDWARE_MONITOR_INTERFACE);

	if (!g_dbus_unregister_interface(conn, path, CINTERION_LEGACY_HWMON_INTERFACE)) {
		ofono_error("Could not unregister %s interface under %s",
			CINTERION_LEGACY_HWMON_INTERFACE, path);
	}

	ofono_modem_remove_interface(modem, CINTERION_LEGACY_HWMON_INTERFACE);
}

/*******************************************************************************
 * Time services interface
 ******************************************************************************/

#define GEMALTO_NITZ_TIME_INTERFACE OFONO_SERVICE ".gemalto.TimeServices"

static DBusMessage *set_modem_datetime(DBusConnection *conn,
							DBusMessage *msg,
							void *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	time_t t = time(NULL);
	struct tm tm;
	gchar cclk_cmd[32];

	/* Set date and time */
	tm = *localtime(&t);
	strftime(cclk_cmd, 32, "AT+CCLK=\"%y/%m/%d,%T\"", &tm);
	g_at_chat_send(data->app, cclk_cmd, none_prefix, NULL, NULL, NULL);
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable gsmTime_methods[] = {
	{ GDBUS_ASYNC_METHOD("SetModemDatetime",
			NULL, NULL, set_modem_datetime) },
	{}
};

static const GDBusSignalTable gsmTime_signals[] = {
	{ GDBUS_SIGNAL("NitzUpdated",
			GDBUS_ARGS({ "time", "a{sv}" }) )},
	{}
};

static void gemalto_time_enable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	if (!g_dbus_register_interface(conn, path,
					GEMALTO_NITZ_TIME_INTERFACE,
					gsmTime_methods,
					gsmTime_signals,
					NULL,
					modem,
					NULL)) {
		ofono_error("Could not register %s interface under %s",
					GEMALTO_NITZ_TIME_INTERFACE, path);
		return;
	}

	ofono_modem_add_interface(modem, GEMALTO_NITZ_TIME_INTERFACE);
}

static void gemalto_time_disable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	if (!g_dbus_unregister_interface(conn, path, GEMALTO_NITZ_TIME_INTERFACE)) {
		ofono_error("Could not unregister %s interface under %s",
			GEMALTO_NITZ_TIME_INTERFACE, path);
		return;
	}

	ofono_modem_remove_interface(modem, GEMALTO_NITZ_TIME_INTERFACE);
}

/*******************************************************************************
 * Command passthrough interface
 ******************************************************************************/

#define COMMAND_PASSTHROUGH_INTERFACE OFONO_SERVICE ".gemalto.CommandPassthrough"

static int command_passthrough_signal_answer(const char *answer,
							gpointer user_data)
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

static void command_passthrough_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
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

static DBusMessage *command_passthrough_simple(DBusConnection *conn,
							DBusMessage *msg,
							void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
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

	g_at_chat_send(data->app, command, NULL, command_passthrough_cb,
								modem, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *command_passthrough_with_prompt(DBusConnection *conn,
							DBusMessage *msg,
							void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
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

	executeWithPrompt(data->app, command, prompt, argument,
					command_passthrough_cb, modem, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *command_passthrough_send_break(DBusConnection *conn,
							DBusMessage *msg,
							void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	GIOChannel *channel = g_at_chat_get_channel(data->app);

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

/*******************************************************************************
 * GNSS interface
 ******************************************************************************/

#define GNSS_INTERFACE OFONO_SERVICE ".gemalto.GNSS"

static void gnss_get_properties_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *port = ofono_modem_get_string(modem, "GNSS");
	GAtResultIter iter;
	DBusMessage *reply;
	DBusMessageIter dbusiter;
	DBusMessageIter dict;

	if (data->gnss_msg == NULL)
		return;

	if (!ok)
		goto error;

	reply = dbus_message_new_method_return(data->gnss_msg);
	dbus_message_iter_init_append(reply, &dbusiter);
	dbus_message_iter_open_container(&dbusiter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);
	g_at_result_iter_init(&iter, result);

	/* supported format: ^SGPSC: "Nmea/Output","off" */
	while (g_at_result_iter_next(&iter, "^SGPSC:")) {
		const char *name = "";
		const char *val = "";

		if (!g_at_result_iter_next_string(&iter, &name))
			continue;

		/*
		 * skip the "Info" property:
		 * different line format and different usage
		 */
		if (g_str_equal(name,"Info"))
			continue;

		if (!g_at_result_iter_next_string(&iter, &val))
			continue;

		ofono_dbus_dict_append(&dict, name, DBUS_TYPE_STRING, &val);
	}

	ofono_dbus_dict_append(&dict, "Port", DBUS_TYPE_STRING, &port);
	dbus_message_iter_close_container(&dbusiter, &dict);
	__ofono_dbus_pending_reply(&data->gnss_msg, reply);
	return;

error:
	__ofono_dbus_pending_reply(&data->gnss_msg,
			__ofono_error_failed(data->gnss_msg));
}

static DBusMessage *gnss_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->gnss_msg != NULL)
		return __ofono_error_busy(msg);

	if (!g_at_chat_send(data->app, "AT^SGPSC?", sgpsc_prefix,
					gnss_get_properties_cb, modem, NULL))
		return __ofono_error_failed(msg);

	data->gnss_msg = dbus_message_ref(msg);

	return NULL;
}

static void gnss_set_properties_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusMessage *reply;

	if (data->gnss_msg == NULL)
		return;

	if (!ok) {
		__ofono_dbus_pending_reply(&data->gnss_msg,
					__ofono_error_failed(data->gnss_msg));
		return;
	}

	reply = dbus_message_new_method_return(data->gnss_msg);
	__ofono_dbus_pending_reply(&data->gnss_msg, reply);
}

static DBusMessage *gnss_set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusMessageIter iter, var;
	const char *name;
	char *value;
	char buf[256];

	if (data->gnss_msg != NULL)
		return __ofono_error_busy(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &var);

	if (dbus_message_iter_get_arg_type(&var) !=
					DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&var, &value);

	snprintf(buf, sizeof(buf), "AT^SGPSC=\"%s\",\"%s\"", name, value);

	if (!g_at_chat_send(data->app, buf, sgpsc_prefix,
					gnss_set_properties_cb, modem, NULL))
		return __ofono_error_failed(msg);

	data->gnss_msg = dbus_message_ref(msg);
	return NULL;
}

static const GDBusMethodTable gnss_methods[] = {
	{ GDBUS_ASYNC_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			gnss_get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "property", "s" }, { "value", "v" }),
			NULL, gnss_set_property) },
	{ }
};

static void gnss_exec_stored_param(struct ofono_modem *modem,
							const char *filename) {
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *vid = ofono_modem_get_string(modem, "Vendor");
	const char *pid = ofono_modem_get_string(modem, "Model");
	char store[64];
	int index;
	char *property, *value;
	char key[32];
	GKeyFile *f;
	char *command;

	sprintf(store,"%s-%s/%s", vid, pid, filename);
	f = storage_open(NULL, store);

	if (!f)
		return;

	for (index=0;;index++) {
		sprintf(key, "property_%d", index);
		property = g_key_file_get_string(f, "Properties", key, NULL);

		sprintf(key, "value_%d", index);
		value = g_key_file_get_string(f, "Properties", key, NULL);

		if(!property || !value)
			break;

		command = g_strdup_printf("AT^SGPSC=%s,%s", property, value);
		DBG(REDCOLOR"setting GNSS property: %s"NOCOLOR, command);
		g_at_chat_send(data->app, command, NULL, NULL, NULL, NULL);
		free(command);
	}

	storage_close(NULL, store, f, FALSE);
}

static void gemalto_gnss_enable_cb(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	if (!ok)
		return; /* the module does not support GNSS */

	gnss_exec_stored_param(modem, "gnss_startup");

	/* Create GNSS DBus interface */
	if (!g_dbus_register_interface(conn, path, GNSS_INTERFACE,
					gnss_methods,
					NULL,
					NULL,
					modem,
					NULL)) {
		ofono_error("Could not register %s interface under %s",
					GNSS_INTERFACE, path);
		return;
	}

	ofono_modem_add_interface(modem, GNSS_INTERFACE);
}

static void gemalto_gnss_enable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	g_at_chat_send(data->app, "AT^SGPSC?", sgpsc_prefix,
					gemalto_gnss_enable_cb, modem, NULL);
}

static void gemalto_gnss_disable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	gnss_exec_stored_param(modem, "gnss_shutdown"); // FIXME where to describe/read

	/* Create GNSS DBus interface */
	if (!g_dbus_unregister_interface(conn, path, GNSS_INTERFACE)) {
		ofono_error("Could not unregister %s interface under %s",
			GNSS_INTERFACE, path);
		return;
	}

	ofono_modem_remove_interface(modem, GNSS_INTERFACE);
}

/*******************************************************************************
 * Hardware control interface
 ******************************************************************************/

#define HARDWARE_CONTROL_INTERFACE OFONO_SERVICE ".gemalto.HardwareControl"

static DBusMessage *hc_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusMessage *reply;
	DBusMessageIter dbusiter;
	DBusMessageIter dict;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &dbusiter);
	dbus_message_iter_open_container(&dbusiter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);

	ofono_dbus_dict_append(&dict, "Powersave", DBUS_TYPE_BOOLEAN,
							&data->powersave);
	dbus_message_iter_close_container(&dbusiter, &dict);

	return reply;
}

/*
 * powersave for older modules:
 *	command_0=AT+CFUN=7
 * return:
 *	command_0=AT+CFUN=1
 *
 * powersave example for modules with GNSS (could also only stop the output):
 *	command_0=AT+CREG=0
 *	command_1=AT+CGREG=0
 *	command_2=AT+CEREG=0
 *	command_3=AT^SGPSC="Engine","0"
 *	command_4=AT^SGPSC="Power/Antenna","off"
 * return:
 *	command_0=AT+CREG=2
 *	command_1=AT+CGREG=2
 *	command_2=AT+CEREG=2
 *	command_4=AT^SGPSC="Power/Antenna","on"
 *	command_3=AT^SGPSC="Engine","1"
 */

static void gemalto_powersave_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusMessage *reply;

	/* flip the state in any case */
	data->powersave = !data->powersave;

	if (data->hc_msg == NULL)
		return;

	reply = dbus_message_new_method_return(data->hc_msg);
	__ofono_dbus_pending_reply(&data->hc_msg, reply);
}

static void mbim_subscriptions(struct ofono_modem *modem, gboolean subscribe);
void manage_csq_source(struct ofono_netreg *netreg, gboolean add);

static DBusMessage *hc_set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusMessageIter iter, var;
	const char *name;
	gboolean enable;

	if (data->hc_msg != NULL)
		return __ofono_error_busy(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &name);

	if (!g_str_equal(name, "Powersave"))
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &var);

	if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_BOOLEAN)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&var, &enable);

	if (data->powersave == enable)
		return dbus_message_new_method_return(msg);

	gemalto_exec_stored_cmd(modem, enable ? "power_mode_powersave" :
							"power_mode_normal");

	gnss_exec_stored_param(modem, enable ? "gnss_powersave" :
								"gnss_normal");

	if(data->netreg)
		manage_csq_source(data->netreg, !enable);

	if(data->mbim == STATE_PRESENT)
		mbim_subscriptions(modem, !enable);

	if (!g_at_chat_send(data->app, "AT", none_prefix,
				gemalto_powersave_cb, modem, NULL))
		return __ofono_error_failed(msg);

	data->hc_msg = dbus_message_ref(msg);
	return NULL;
}

static void gemalto_smso_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusMessage *reply;

	if (data->hc_msg == NULL)
		return;

	if (data->conn == GEMALTO_CONNECTION_SERIAL && ok) {
	  ofono_modem_set_powered(modem, FALSE);
	}

	reply = dbus_message_new_method_return(data->hc_msg);
	__ofono_dbus_pending_reply(&data->hc_msg, reply);
}

static DBusMessage *hc_shutdown(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->hc_msg != NULL)
		return __ofono_error_busy(msg);

	if (!g_at_chat_send(data->app, "AT^SMSO", none_prefix,
						gemalto_smso_cb, modem, NULL))
		return __ofono_error_failed(msg);

	data->hc_msg = dbus_message_ref(msg);
	return NULL;
}

static void gemalto_detect_sysstart(GAtResult *result, gpointer user_data);

static void gemalto_reset_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	DBusMessage *reply;

	if (data->hc_msg == NULL)
		return;

	if (data->conn != GEMALTO_CONNECTION_SERIAL)
		goto finished;

	data->modem_ready_id = g_at_chat_register(data->app,
		"^SYSSTART", gemalto_detect_sysstart, FALSE,
		modem, NULL);

finished:
	reply = dbus_message_new_method_return(data->hc_msg);
	__ofono_dbus_pending_reply(&data->hc_msg, reply);
}

static DBusMessage *hc_reset(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->hc_msg != NULL)
		return __ofono_error_busy(msg);

	if (!g_at_chat_send(data->app, "AT+CFUN=1,1", none_prefix,
						gemalto_reset_cb, modem, NULL))
		return __ofono_error_failed(msg);

	data->hc_msg = dbus_message_ref(msg);
	return NULL;
}

static const GDBusMethodTable hardware_control_methods[] = {
	{ GDBUS_ASYNC_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			hc_get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "property", "s" }, { "value", "v" }),
			NULL, hc_set_property) },
	{ GDBUS_ASYNC_METHOD("Shutdown",
			NULL, NULL, hc_shutdown) },
	{ GDBUS_ASYNC_METHOD("Reset",
			NULL, NULL, hc_reset) },
	{ }
};

static void gemalto_hardware_control_enable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	/* Create Hardware Control DBus interface */
	if (!g_dbus_register_interface(conn, path, HARDWARE_CONTROL_INTERFACE,
					hardware_control_methods,
					NULL,
					NULL,
					modem,
					NULL)) {
		ofono_error("Could not register %s interface under %s",
					HARDWARE_CONTROL_INTERFACE, path);
		return;
	}

	ofono_modem_add_interface(modem, HARDWARE_CONTROL_INTERFACE);
}

static void gemalto_hardware_control_disable(struct ofono_modem *modem)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = ofono_modem_get_path(modem);

	/* Create Hardware Control DBus interface */
	if (!g_dbus_unregister_interface(conn, path, HARDWARE_CONTROL_INTERFACE)) {
		ofono_error("Could not unregister %s interface under %s",
			HARDWARE_CONTROL_INTERFACE, path);
		return;
	}

	ofono_modem_remove_interface(modem, HARDWARE_CONTROL_INTERFACE);
}

/*******************************************************************************
 * modem plugin
 ******************************************************************************/

static int mbim_parse_descriptors(struct gemalto_data *md, const char *file)
{
	void *data;
	size_t len;
	const struct mbim_desc *desc = NULL;
	const struct mbim_extended_desc *ext_desc = NULL;

	data = l_file_get_contents(file, &len);
	if (!data)
		return -EIO;

	if (!mbim_find_descriptors(data, len, &desc, &ext_desc)) {
		l_free(data);
		return -ENOENT;
	}

	if (desc)
		md->max_segment = L_LE16_TO_CPU(desc->wMaxControlMessage);

	if (ext_desc)
		md->max_outstanding = ext_desc->bMaxOutstandingCommandMessages;

	l_free(data);
	return 0;
}

static int mbim_probe(struct ofono_modem *modem, struct gemalto_data *data)
{
	const char *descriptors;
	int err;

	descriptors = gemalto_get_string(modem, "DescriptorFile");

	if (!descriptors)
		return -EINVAL;

	data->max_outstanding = 1;

	err = mbim_parse_descriptors(data, descriptors);
	if (err < 0) {
		DBG("Warning, unable to load descriptors, setting defaults");
		data->max_segment = 512;
	}

	DBG("MaxSegment: %d, MaxOutstanding: %d",
		data->max_segment, data->max_outstanding);

	return 0;
}

static int gemalto_probe(struct ofono_modem *modem)
{
	struct gemalto_data *data;

	data = g_try_new0(struct gemalto_data, 1);
	if (data == NULL)
		return -ENOMEM;

	mbim_probe(modem, data);
	ofono_modem_set_data(modem, data);

	return 0;
}

static void gemalto_remove(struct ofono_modem *modem)
{
	struct gemalto_data *data;

	DBG("");

	if (!modem)
		return;

	data = ofono_modem_get_data(modem);

	if (!data)
		return;

	/*
	 * Stop the probing, if present
	*/
	if (data->probing_timer) {
		g_source_remove(data->probing_timer);
		data->probing_timer = 0;
	}

	if (data->online_timer) {
		g_source_remove(data->online_timer);
		data->online_timer = 0;
	}

	if (data->mbim == STATE_PRESENT) { // FIXME
		mbim_device_shutdown(data->mbimd);
		mbim_device_unref(data->mbimd); // FIXME
		data->mbim = STATE_ABSENT;
	}

	if (data->qmi == STATE_PRESENT) {
		qmi_device_unref(data->qmid);
	}

	if (data->app) {
		/* Cleanup potential SIM state polling */
		at_util_sim_state_query_free(data->sim_state_query);
		data->sim_state_query = NULL;

		g_at_chat_cancel_all(data->app);
		g_at_chat_unregister_all(data->app);
		g_at_chat_unref(data->app);
		if (data->mdm == data->app) {
		  data->mdm = NULL;
		}
		data->app = NULL;
	}

	if (data->mdm) {
		g_at_chat_cancel_all(data->mdm);
		g_at_chat_unregister_all(data->mdm);
		g_at_chat_unref(data->mdm);
		data->mdm = NULL;
	}

	ofono_modem_set_data(modem, NULL);
	g_free(data);
}

static void sim_ready_cb(gboolean present, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct ofono_sim *sim = data->sim;

	at_util_sim_state_query_free(data->sim_state_query);
	data->sim_state_query = NULL;

	ofono_sim_inserted_notify(sim, present);
}

static int gemalto_ciev_simstatus_delayed(void *modem) {
	struct gemalto_data *data = ofono_modem_get_data(modem);
	data->sim_state_query = at_util_sim_state_query_new(data->app,
				1, 20, sim_ready_cb, modem,
				NULL);
	return FALSE; /* to kill the timer */
}

static void gemalto_ciev_simstatus_notify(GAtResultIter *iter,
					struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct ofono_sim *sim = data->sim;
	int status;

	if (!g_at_result_iter_next_number(iter, &status))
		return;

	DBG("sim status %d", status);

	switch (status) {
	/* SIM is removed from the holder */
	case 0:
		ofono_sim_inserted_notify(sim, FALSE);
		break;

	/* SIM is inserted inside the holder */
	case 1:
		/* delay for 2 seconds the AT+CPIN? check, to make sure the sim is powered, otherwise we can get a SIM failure (error 13) */
		g_timeout_add_seconds(2, gemalto_ciev_simstatus_delayed, modem);
		break;

	/* USIM initialization completed. UE has finished reading USIM data. */
	case 5:
		ofono_sim_initialized_notify(sim);
		break;

	default:
		break;
	}
}

static void gemalto_ciev_nitz_notify(GAtResultIter *iter,
					struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *nitz_data;
	char buf[32];

	/* Example: +CIEV: nitz,<time>,<timezone>,<daylight> */
	if (!g_at_result_iter_next_string(iter, &nitz_data))
		return;

	DBG("nitz_data  %s", nitz_data);

	sprintf(buf, "AT+CCLK=\"%s\"", nitz_data);
	g_at_chat_send(data->app, buf, none_prefix, NULL, NULL, NULL);

	gemalto_signal(GEMALTO_NITZ_TIME_INTERFACE, "NitzUpdated", nitz_data,
									modem);
}

static void gemalto_ciev_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;

	const char *sim_status = "simstatus";
	const char *nitz_status = "nitz";
	const char *ind_str;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	/* Example: +CIEV: simstatus,<status> */
	if (!g_at_result_iter_next(&iter, "+CIEV:"))
		return;

	if (!g_at_result_iter_next_unquoted_string(&iter, &ind_str))
		return;

	if (g_str_equal(sim_status, ind_str)) {
		gemalto_ciev_simstatus_notify(&iter, modem);
	} else if (g_str_equal(nitz_status, ind_str)) {
		gemalto_ciev_nitz_notify(&iter, modem);
	}
}

static void sim_state_cb(gboolean present, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	at_util_sim_state_query_free(data->sim_state_query);
	data->sim_state_query = NULL;

	data->have_sim = present;
	ofono_modem_set_powered(modem, TRUE);

	/* Register for specific sim status reports */
	g_at_chat_register(data->app, "+CIEV:",
			gemalto_ciev_notify, FALSE, modem, NULL);

	g_at_chat_send(data->app, "AT^SIND=\"simstatus\",1", none_prefix,
			NULL, NULL, NULL);
	g_at_chat_send(data->app, "AT^SIND=\"nitz\",1", none_prefix,
			NULL, NULL, NULL);
}

static void gemalto_exit_urc_notify(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *error_message;

	g_at_result_iter_init(&iter, result);
	g_at_result_iter_next(&iter, "^EXIT:");
	g_at_result_iter_next_unquoted_string(&iter, &error_message);
	ofono_error("Modem exited! Cause: %s", error_message);
}

static void saic_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->voice_avail = TRUE;
	else
		data->voice_avail = FALSE;
}

static void sgauth_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->auth_syntax = GEMALTO_AUTH_USE_SGAUTH |
						GEMALTO_AUTH_ORDER_PWD_USR;
	else
		data->auth_syntax = GEMALTO_AUTH_DEFAULTS;
}

static void gemalto_set_cfun_cb(gboolean ok, GAtResult *result,
					gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (!ok || data->cfun == 41) {
		g_at_chat_cancel_all(data->app);
		ofono_modem_set_powered(modem, FALSE);
	} else {
		data->sim_state_query = at_util_sim_state_query_new(data->app,
					2, 20, sim_state_cb, modem, NULL);
	}
}

static void gemalto_cfun_query(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(user_data);
	char buf[256];
	GAtResultIter iter;
	int mode;

	sprintf(buf, "AT+CFUN=%d", data->cfun==41?4:data->cfun);

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CFUN:"))
		goto error;

	if (!g_at_result_iter_next_number(&iter, &mode))
		goto error;

	if (mode == data->cfun)
		sprintf(buf, "AT");

error:
	if (g_at_chat_send(data->app, buf, none_prefix, gemalto_set_cfun_cb,
				modem, NULL) > 0)
		return;

	if (data->cfun == 41)
		ofono_modem_set_powered(modem, FALSE);
}

static void gemalto_set_cfun(GAtChat *app, int mode, struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	data->cfun=mode;
	g_at_chat_send(app, "AT+CFUN?", cfun_prefix, gemalto_cfun_query, modem, NULL);
}

static void gemalto_initialize(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	char *urcdest;
	guint m = data->model;

	DBG("app:%d, mdm:%d, mbim:%d, qmi:%d",
		data->app!=NULL,
		data->mdm!=NULL,
		data->mbim == STATE_PRESENT,
		data->qmi == STATE_PRESENT);

	if (!data->app  && !data->mdm) {
		DBG("no AT interface available. Removing this device.");
		ofono_modem_set_powered(modem, FALSE);
		return;
	}

	urcdest = "AT^SCFG=\"URC/DstIfc\",\"app\"";

	if (!data->app) {
		data->app = data->mdm;
		urcdest = "AT^SCFG=\"URC/DstIfc\",\"mdm\"";
	}

	if (!data->mdm && (data->gina == STATE_PRESENT)) {
		/*these modems can start PPP from any port*/
		data->mdm = data->app;
	}

	if (data->mdm && data->gprs_opt == NO_GPRS)
		data->gprs_opt = USE_PPP;

	/*
	 * The msec time must be higher than the time between the most
	 * frequent polling commands (e.g. if gemalto_csq_query is polled
	 * every 5s then msec shall be more. In this case we put it to 6s)
	 */
	g_at_chat_set_wakeup_command(data->app, "AT\r", 1000, 6000);

	g_at_chat_send(data->app, "ATE0", none_prefix, NULL, NULL, NULL);

	if (data->gina != STATE_PRESENT)
		g_at_chat_send(data->app, urcdest, none_prefix, NULL, NULL,
									NULL);

	/* numeric error codes are interpreted by atmodem/atutil.c functions */
	g_at_chat_send(data->app, "AT+CMEE=1", none_prefix, NULL, NULL, NULL);

	if (data->mdm)
		g_at_chat_send(data->mdm, "AT&C0", none_prefix, NULL, NULL,
									NULL);

	g_at_chat_send(data->app, "AT&C0", none_prefix, NULL, NULL, NULL);

	/* watchdog */
	g_at_chat_register(data->app, "^EXIT", gemalto_exit_urc_notify, FALSE,
								modem, NULL);
	ofono_devinfo_create(modem, OFONO_VENDOR_GEMALTO, "atmodem", data->app);
	g_at_chat_send(data->app,
		"AT^SCFG=\"MEopMode/PwrSave\",\"enabled\",52,50", none_prefix,
							NULL, NULL, NULL);

	if (m != 0x5b && m != 0x5c && m != 0x5d && m != 0xa0) {
		g_at_chat_send(data->app, "AT^SGAUTH?", NULL, sgauth_probe,
								modem, NULL);
	}

	g_at_chat_send(data->app, "AT^SAIC?", NULL, saic_probe, modem, NULL);

	gemalto_exec_stored_cmd(modem, "enable");

	gemalto_command_passthrough_enable(modem);
	gemalto_hardware_monitor_enable(modem);
	gemalto_time_enable(modem);
	gemalto_gnss_enable(modem);
	gemalto_hardware_control_enable(modem);

	gemalto_set_cfun(data->app, 4, modem);
	data->init_done = TRUE;
	data->online_timer = 0;
}

#include <asm/ioctls.h>
#include <linux/serial.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <poll.h>

static int write_fd(int fd, void *buf, size_t size) {
	size_t written = 0;
	int error = 0;
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLOUT | POLLERR | POLLHUP | POLLNVAL;
	while(!error && written<size) {
		int pollret = poll(&pfd, 1, 10); /* block max 10ms */
		if(pollret<0) {
			error = errno;
		}  else if (pollret>0) {
			if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				error = -1000;
			} else
				written += write(fd, buf+written, size-written);
		}
	}
	if(error!=0) return error;
	return written;
}

static int read_fd(int fd, void *buf, size_t bufsize) {
	struct pollfd pfd;
	int pollret;
	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	pollret = poll(&pfd, 1, 10); /* block max 10ms */
	if(pollret<0)
		return errno;
	if(pollret>0) {
		if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			return -1000;
		return read(fd, buf, bufsize); /* POLLIN case */
	}
	return 0; /* pollret = 0 -> no data available, timeout expired */
}

static int gemalto_probe_device(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	int status;
	char buf[1024] = {0};
	size_t buflen = 1024;
	GAtSyntax *syntax;

	if (data->channel==NULL)
		return FALSE;

	/*
	 * the timer is removed and re-created at each pass, because the writing
	 * loop can in theory be longer than the timeout, hence causing parallel
	 * calls, with unpredictable effects
	 */
	g_source_remove(data->probing_timer);
	data->probing_timer = 0; /* remove the timer reference */
	data->waiting_time++;
	DBG("%d/%d", data->waiting_time, data->init_waiting_time+3);

	if (data->waiting_time > data->init_waiting_time+3) {
		data->waiting_time = 0;
		goto failed;
	}

	status = write_fd(data->portfd, "AT\r", 3);
	if(status<0)
		goto failed;

	status = read_fd(data->portfd, buf, buflen);
	if(status<0)
		goto failed;

	if(!strstr(buf, "OK")) {
		data->probing_timer = g_timeout_add_seconds(1,
						gemalto_probe_device, modem);
		return TRUE; /* keep waiting */
	}

	/* AT was answered with OK: port ready */
	g_io_channel_flush(data->channel, NULL);
	/* reset channel defaults*/
	g_io_channel_set_buffered(data->channel, TRUE);
	g_io_channel_set_encoding(data->channel, "UTF-8", NULL);
	syntax = g_at_syntax_new_gsm_permissive();
	data->tmp_chat = g_at_chat_new(data->channel, syntax);
	g_at_syntax_unref(syntax);
	if (data->tmp_chat == NULL)
		goto failed;
	g_io_channel_unref(data->channel);
	data->channel = NULL;
	g_at_chat_set_debug(data->tmp_chat, gemalto_at_debug, "App: ");
	data->open_cb(TRUE, modem);
	return FALSE; /* kill the timer: finished */

failed:
	DBG("timeout or port error: abort");
	g_io_channel_unref(data->channel);
	data->channel = NULL;
	data->tmp_chat = NULL;
	data->open_cb(FALSE, modem);
	return FALSE; /* abort */
}

static void gemalto_open_device(const char *device,
				OpenResultFunc func, struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	GHashTable *options;
	int fd;
	struct serial_struct old, new;
	int DTR_flag = TIOCM_DTR;

	if (!device  || !*device) {
		func(FALSE, modem);
		return;
	}

	options = g_hash_table_new(g_str_hash, g_str_equal);
	if (options == NULL) {
		func(FALSE, modem);
		return;
	}

	g_hash_table_insert(options, "Baud", "115200");
	g_hash_table_insert(options, "StopBits", "1");
	g_hash_table_insert(options, "DataBits", "8");
	g_hash_table_insert(options, "Parity", "none");
	g_hash_table_insert(options, "XonXoff", "off");
	g_hash_table_insert(options, "RtsCts", "on");
	g_hash_table_insert(options, "Local", "on");
	g_hash_table_insert(options, "Read", "on");

	DBG("Opening device %s", device);

	data->channel = g_at_tty_open(device, options);
	g_hash_table_destroy(options);

	if (!data->channel) {
		func(FALSE, modem);
		return;
	}

	fd = g_io_channel_unix_get_fd(data->channel);
	ioctl(fd, TIOCGSERIAL, &old);
	new = old;
	new.closing_wait = ASYNC_CLOSING_WAIT_NONE;
	ioctl(fd, TIOCSSERIAL, &new);

	ioctl(fd, TIOCMBIS, &DTR_flag);

	g_io_channel_flush(data->channel, NULL);
	/* the channel is set by default to "UTF-8" and buffered */
	g_io_channel_set_encoding(data->channel, NULL, NULL);
	g_io_channel_set_buffered(data->channel, FALSE);
	data->open_cb = func;
	data->portfd = fd;
	data->probing_timer = g_timeout_add_seconds(1, gemalto_probe_device,
									modem);
}

static void gemalto_enable_mdm_cb(gboolean success, struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	data->mdm = data->tmp_chat;
	data->tmp_chat = NULL;
	gemalto_initialize(modem);
}

static void gemalto_enable_app_cb(gboolean success, struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *mdm = gemalto_get_string(modem, "Modem");

	data->app = data->tmp_chat;
	data->tmp_chat = NULL;
	gemalto_open_device(mdm, gemalto_enable_mdm_cb, modem);
}

static int gemalto_enable_app(struct ofono_modem *modem)
{
	const char *app = gemalto_get_string(modem, "Application");

	gemalto_open_device(app, gemalto_enable_app_cb, modem);
	return -EINPROGRESS;
}

static void mbim_subscriptions(struct ofono_modem *modem, gboolean subscribe)
{
	struct gemalto_data *md = ofono_modem_get_data(modem);
	struct mbim_message *message;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST,
					MBIM_COMMAND_TYPE_SET);

	if(subscribe)
		/* subscribe all */
		mbim_message_set_arguments(message, "av", 5,
					"16yuuuuuuuuuuuu",
					mbim_uuid_basic_connect, 11,
					MBIM_CID_SUBSCRIBER_READY_STATUS,
					MBIM_CID_RADIO_STATE,
					MBIM_CID_PREFERRED_PROVIDERS,
					MBIM_CID_REGISTER_STATE,
					MBIM_CID_PACKET_SERVICE,
					MBIM_CID_SIGNAL_STATE,
					MBIM_CID_CONNECT,
					MBIM_CID_PROVISIONED_CONTEXTS,
					MBIM_CID_IP_CONFIGURATION,
					MBIM_CID_EMERGENCY_MODE,
					MBIM_CID_MULTICARRIER_PROVIDERS,
					"16yuuuu", mbim_uuid_sms, 3,
					MBIM_CID_SMS_CONFIGURATION,
					MBIM_CID_SMS_READ,
					MBIM_CID_SMS_MESSAGE_STORE_STATUS,
					"16yuu", mbim_uuid_ussd, 1,
					MBIM_CID_USSD,
					"16yuu", mbim_uuid_phonebook, 1,
					MBIM_CID_PHONEBOOK_CONFIGURATION,
					"16yuu", mbim_uuid_stk, 1,
					MBIM_CID_STK_PAC);
	else
		/* unsubscribe all */
		mbim_message_set_arguments(message, "av", 0);

	mbim_device_send(md->mbimd, 0, message, NULL, NULL, NULL);
}


static void mbim_device_caps_info_cb(struct mbim_message *message, void *user)
{
	struct ofono_modem *modem = user;
	struct gemalto_data *md = ofono_modem_get_data(modem);
	uint32_t device_type;
	uint32_t cellular_class;
	uint32_t voice_class;
	uint32_t sim_class;
	uint32_t data_class;
	uint32_t sms_caps;
	uint32_t control_caps;
	uint32_t max_sessions;
	char *custom_data_class;
	char *device_id;
	char *firmware_info;
	char *hardware_info;
	bool r;

	if (mbim_message_get_error(message) != 0)
		goto error;

	r = mbim_message_get_arguments(message, "uuuuuuuussss",
					&device_type, &cellular_class,
					&voice_class, &sim_class, &data_class,
					&sms_caps, &control_caps, &max_sessions,
					&custom_data_class, &device_id,
					&firmware_info, &hardware_info);
	if (!r)
		goto error;

	md->max_sessions = max_sessions;

	DBG("DeviceId: %s", device_id);
	DBG("FirmwareInfo: %s", firmware_info);
	DBG("HardwareInfo: %s", hardware_info);

	ofono_modem_set_string(modem, "DeviceId", device_id);
	ofono_modem_set_string(modem, "FirmwareInfo", firmware_info);

	l_free(custom_data_class);
	l_free(device_id);
	l_free(firmware_info);
	l_free(hardware_info);

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST,
					MBIM_COMMAND_TYPE_SET);

	/* unsubscribe all */
	//mbim_message_set_arguments(message, "av", 0);

	/* subscribe all */
	mbim_message_set_arguments(message, "av", 5,
					"16yuuuuuuuuuuuu",
					mbim_uuid_basic_connect, 11,
					MBIM_CID_SUBSCRIBER_READY_STATUS,
					MBIM_CID_RADIO_STATE,
					MBIM_CID_PREFERRED_PROVIDERS,
					MBIM_CID_REGISTER_STATE,
					MBIM_CID_PACKET_SERVICE,
					MBIM_CID_SIGNAL_STATE,
					MBIM_CID_CONNECT,
					MBIM_CID_PROVISIONED_CONTEXTS,
					MBIM_CID_IP_CONFIGURATION,
					MBIM_CID_EMERGENCY_MODE,
					MBIM_CID_MULTICARRIER_PROVIDERS,
					"16yuuuu", mbim_uuid_sms, 3,
					MBIM_CID_SMS_CONFIGURATION,
					MBIM_CID_SMS_READ,
					MBIM_CID_SMS_MESSAGE_STORE_STATUS,
					"16yuu", mbim_uuid_ussd, 1,
					MBIM_CID_USSD,
					"16yuu", mbim_uuid_phonebook, 1,
					MBIM_CID_PHONEBOOK_CONFIGURATION,
					"16yuu", mbim_uuid_stk, 1,
					MBIM_CID_STK_PAC);

	if (mbim_device_send(md->mbimd, 0, message,
				NULL, NULL, NULL)) {
		md->mbim = STATE_PRESENT;
		goto other_devices;
	}


error:
	mbim_device_shutdown(md->mbimd);

other_devices:

	if (md->init_done)
		return;

	gemalto_enable_app(modem);  /* continue with mdm interface */
}

static void mbim_device_ready(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *md = ofono_modem_get_data(modem);
	struct mbim_message *message =
		mbim_message_new(mbim_uuid_basic_connect,
					1, MBIM_COMMAND_TYPE_QUERY);

	mbim_message_set_arguments(message, "");
	mbim_device_send(md->mbimd, 0, message, mbim_device_caps_info_cb,
		modem, NULL);
}

static void mbim_device_closed(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *md = ofono_modem_get_data(modem);

	if (!md)
		return;

	/*
	 * if state=probe, it  means that we are in the init phase
	 * and that we have failed the MBIM_OPEN
	 */
	if (md->mbim == STATE_PROBE) {
		DBG(REDCOLOR"MBIM OPEN failed!"NOCOLOR);
		gemalto_enable_app(modem); /* continue with other interfaces */
	}

	/* reset the state for future attempts */
	md->mbim = STATE_PROBE;

	if(md->mbimd)
		mbim_device_unref(md->mbimd);

	md->mbimd = NULL;
}

static int mbim_enable(struct ofono_modem *modem)
{
	const char *device;
	int fd;
	struct serial_struct old, new;
	int DTR_flag = TIOCM_DTR;
	struct gemalto_data *md = ofono_modem_get_data(modem);

	DBG("modem struct: %p", modem);

	device = gemalto_get_string(modem, "NetworkControl");
	if (!device)
		goto other_devices;

	DBG("modem device: %s", device);
	fd = open(device, O_EXCL | O_NONBLOCK | O_RDWR);
	if (fd < 0)
		goto other_devices;

	ioctl(fd, TIOCGSERIAL, &old);
	new = old;
	new.closing_wait = ASYNC_CLOSING_WAIT_NONE;
	ioctl(fd, TIOCSSERIAL, &new);
	ioctl(fd, TIOCMBIS, &DTR_flag);

	DBG("device: %s opened successfully", device);
	md->mbimd = mbim_device_new(fd, md->max_segment);
	DBG("created new device %p", md->mbimd);

	mbim_device_set_close_on_unref(md->mbimd, true);
	mbim_device_set_max_outstanding(md->mbimd, md->max_outstanding);
	mbim_device_set_ready_handler(md->mbimd,
					mbim_device_ready, modem, NULL);
	mbim_device_set_disconnect_handler(md->mbimd,
				mbim_device_closed, modem, NULL);
	mbim_device_set_debug(md->mbimd, gemalto_mbim_debug, "MBIM:", NULL);

	return -EINPROGRESS;

other_devices:

	if (md->init_done) {
		return 0;
	}

	return gemalto_enable_app(modem);
}

static void qmi_enable_cb(void *user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *md = ofono_modem_get_data(modem);
	md->qmi = STATE_PRESENT;
	gemalto_enable_app(modem); /* qmi done, continue with app interface */
}

static int qmi_enable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *device;
	int fd;
	struct serial_struct old, new;
	int DTR_flag = TIOCM_DTR;

	DBG("modem struct: %p", modem);

	device = gemalto_get_string(modem, "NetworkControl");
	if (!device)
		goto other_devices;

	fd = open(device, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		goto other_devices;

	ioctl(fd, TIOCGSERIAL, &old);
	new = old;
	new.closing_wait = ASYNC_CLOSING_WAIT_NONE;
	ioctl(fd, TIOCSSERIAL, &new);
	ioctl(fd, TIOCMBIS, &DTR_flag);

	data->qmid = qmi_device_new(fd);
	if (!data->qmid) {
		close(fd);
		goto other_devices;
	}

	qmi_device_set_close_on_unref(data->qmid, true);
	qmi_device_set_debug(data->qmid, gemalto_qmi_debug, "QMI: ");
	qmi_device_discover(data->qmid, qmi_enable_cb, modem, NULL);
	return -EINPROGRESS;

other_devices:

	if (data->init_done) {
		return 0;
	}

	return gemalto_enable_app(modem);
}

static void set_from_model(struct gemalto_data *data) {
	guint m = data->model;

	data->has_lte = TRUE; /* default */

	/* pre-configure non-MBIM network interfaces */
	if (m != 0x62 && m != 0x5d && m != 0x65) {
		/*
		 * note: we probe for ECM/NCM even if the port is not present
		 * (for serial connection type or serial-like)
		 */
		if (m == 0x53 || m == 0x60 || m == 0x63)
			data->qmi = STATE_PROBE;
		/*these families have PPP only*/
		else if (m != 0x58 && m != 0x47 && m != 0x54)
			data->ecmncm = STATE_PROBE;
	}

	/* pre-configure SW features */
	if (m == 0xa0) {
		data->gprs_opt = USE_CTX3;
		data->ecmncm = STATE_ABSENT;
	}
	if (m == 0x63 || m == 0x65 || m == 0x5b || m == 0x5c || m == 0x5d)
		data->gina = STATE_PRESENT;

	data->init_waiting_time = 30;

	if (m == 0x55 || m == 0x47) {
		data->has_lte = FALSE;
		data->init_waiting_time = 5;
	}

	if (m == 0x58) {
		data->has_lte = FALSE;
		data->init_waiting_time = 15;
	}

	data->vts_with_quotes = TRUE;

	if (m == 0x5b || m == 0x5c || m == 0x5d || m == 0xa0) {
		data->vts_with_quotes = FALSE;
		data->auth_syntax = GEMALTO_AUTH_USE_SGAUTH |
						GEMALTO_AUTH_ALWAYS_ALL_PARAMS;
	}
}

static void store_cgmm(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	GAtResultIter iter;
	char const *model;
	char buf[16];

	/* if no model, fallback to a basic 2G one */
	data->model = 0x47;
	strncpy(data->modelstr, "", sizeof(data->modelstr));

	if (!ok)
		return;

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, NULL)) {
		if (!g_at_result_iter_next_unquoted_string(&iter, &model))
			continue;

		if (model && *model) {
			strncpy(data->modelstr, model, sizeof(data->modelstr));

			if (g_ascii_strncasecmp(model, "TC", 2) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "MC", 2) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "AC", 2) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "HC", 2) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "HM", 2) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "XT", 2) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "AGS", 3) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "BGS", 3) == 0)
				data->model = 0x47;
			else if (g_ascii_strncasecmp(model, "AH3", 3) == 0)
				data->model = 0x55;
			else if (g_ascii_strncasecmp(model, "AHS", 3) == 0)
				data->model = 0x55;
			else if (g_ascii_strncasecmp(model, "PHS", 3) == 0)
				data->model = 0x55;
			else if (g_ascii_strncasecmp(model, "PH8", 3) == 0)
				data->model = 0x55;
			else if (g_ascii_strncasecmp(model, "AHS", 3) == 0)
				data->model = 0x55;
			else if (g_ascii_strncasecmp(model, "EHS", 3) == 0)
				data->model = 0x58;
			else if (g_ascii_strncasecmp(model, "ELS31-", 6) == 0)
				data->model = 0xa0;
			else if (g_ascii_strncasecmp(model, "ELS61-", 6) == 0)
				data->model = 0x5b;
			else if (g_ascii_strncasecmp(model, "PLS62-", 6) == 0)
				data->model = 0x5b;
			else if (g_ascii_strncasecmp(model, "PLS8-", 5) == 0)
				data->model = 0x61;
			else if (g_ascii_strncasecmp(model, "ALS3-", 5) == 0)
				data->model = 0x61;
			else if (g_ascii_strncasecmp(model, "ALAS5-", 6) == 0)
				data->model = 0x65;
			return;
		}
	}

	sprintf(buf, "%04x", data->model);
	ofono_modem_set_string(modem, "Model", buf);
}

static void store_sqport(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	GAtResultIter iter;
	char const *sqport;

	/* in case of error, the port is of Modem type */
	strncpy(data->sqport, "Modem", sizeof(data->sqport));

	if (!ok)
		goto done;

	g_at_result_iter_init(&iter, result);

	/* answer format: "^SQPORT: Application" */
	if (!g_at_result_iter_next(&iter, "^SQPORT:"))
		goto done;

	if (!g_at_result_iter_next_unquoted_string(&iter, &sqport))
		goto done;

	if (!sqport || !*sqport)
		goto done;

	strncpy(data->sqport, sqport, sizeof(data->sqport));

done:
	/* select mdm, app or gina port type */
	data->ecmncm = STATE_PROBE;

	if (g_str_equal(sqport, "Modem")) {
		data->mdm = data->app;
		data->app = NULL;
		data->ecmncm = STATE_ABSENT;
	}

	if ((*sqport >= '0' && *sqport <= '9'))
		data->gina = STATE_PRESENT;

	set_from_model(data);
	gemalto_initialize(modem);
}

static void gemalto_detect_serial(gboolean success, struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (!success) {
		ofono_modem_set_powered(modem, FALSE);
		return;
	}

	data->app = data->tmp_chat;
	data->tmp_chat = NULL;

	g_at_chat_send(data->app, "AT+CGMM", none_prefix, store_cgmm,
								modem, NULL);
	g_at_chat_send(data->app, "AT^SQPORT", sqport_prefix, store_sqport,
								modem, NULL);
}

static void gemalto_detect_sysstart(GAtResult *result, gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->modem_ready_id) {
		g_at_chat_unregister(data->app, data->modem_ready_id);
		data->modem_ready_id = 0;
	}

	data->tmp_chat = data->app;
	gemalto_detect_serial(TRUE, modem);
}

static int gemalto_enable_serial(struct ofono_modem *modem)
{
	const char *device = ofono_modem_get_string(modem, "ATport");

	if (!device) {
		return -EINVAL;
	}

	gemalto_open_device(device, gemalto_detect_serial, modem);
	return -EINPROGRESS;
}

static int gemalto_enable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	const char *model = gemalto_get_string(modem, "Model");
	const char *conn_type = gemalto_get_string(modem, "ConnType");
	const char *ctl = gemalto_get_string(modem, "NetworkControl");
	const char *net = gemalto_get_string(modem, "NetworkInterface");
	guint m = 0; /* all default values */

	if (!modem || !data)
		return -EINVAL;

	data->conn = g_str_equal(conn_type,"Serial") ? GEMALTO_CONNECTION_SERIAL
						: GEMALTO_CONNECTION_USB;

	if (data->conn == GEMALTO_CONNECTION_SERIAL)
		return gemalto_enable_serial(modem);

	DBG("modem struct: %p, gemalto_data: %p", modem, data);

	if (data->init_done) {
		gemalto_set_cfun(data->app, 4, modem);

		if (data->mbim != STATE_ABSENT)
			mbim_enable(modem);

		return -EINPROGRESS;
	}

	if (model) {
		data->model = strtoul(model, NULL, 16);
		m = data->model;
	}

	/* single ACM interface 02: assign application to modem */
	if (m == 0xa0) {
		const char *app = gemalto_get_string(modem, "Application");
		ofono_modem_set_string(modem, "Modem", app);
	}

	if (m == 0x60) {
		const char *app = gemalto_get_string(modem, "Diag");
		ofono_modem_set_string(modem, "Modem", app);
	}

	/* if single ACM interface, remove possible extra devices */
	if (m == 0x58 || m == 0x47 || m == 0x54 || m == 0xa0 || m == 0x60) {
		ofono_modem_set_string(modem, "Application", NULL);
		ofono_modem_set_string(modem, "GNSS", NULL);
		ofono_modem_set_string(modem, "RSA", NULL);
		ofono_modem_set_string(modem, "Diag", NULL);
	}

	/* pre-configure MBIM network interface */
	if (m == 0x62 || m == 0x5d || m == 0x65) {
		data->mbim = STATE_PROBE;
	}

	set_from_model(data);

	if ((data->mbim == STATE_PROBE) && ctl && net) {
		data->init_waiting_time = 3;
		return mbim_enable(modem);
	}

	if ((data->qmi == STATE_PROBE) && ctl && net) {
		data->init_waiting_time = 10;
		return qmi_enable(modem);
	}

	return gemalto_enable_app(modem);
}

static void set_online_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_modem_online_cb_t cb = cbd->cb;
	struct ofono_error error;
	decode_at_error(&error, g_at_result_final_response(result));
	cb(&error, cbd->data);
}

static void gemalto_set_online_serial(struct ofono_modem *modem,
			ofono_bool_t online, ofono_modem_online_cb_t cb,
			void *user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char const *command;

	cbd->user = modem;

	DBG("modem %p %s", modem, online ? "online" : "offline");

	if (online)
		gemalto_exec_stored_cmd(modem, "set_online");
	else
		gemalto_exec_stored_cmd(modem, "set_offline");

	if (data->model == 0x47) {
		command = online ? "AT^SCFG=\"MEopMode/Airplane\",\"off\"" :
					"AT^SCFG=\"MEopMode/Airplane\",\"on\"";
	} else {
		command = online ? "AT+CFUN=1" : "AT+CFUN=4";
	}

	if (g_at_chat_send(data->app, command, NULL, set_online_cb, cbd,
									g_free))
		return;

	CALLBACK_WITH_FAILURE(cb, cbd->data);
	g_free(cbd);
}

static void gemalto_set_online(struct ofono_modem *modem, ofono_bool_t online,
				ofono_modem_online_cb_t cb, void *user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct cb_data *cbd = cb_data_new(cb, user_data);
	char const *cmd = online ? "AT+CFUN=1" : "AT+CFUN=4";

	cbd->user = modem;

	if (data->conn == GEMALTO_CONNECTION_SERIAL) {
		gemalto_set_online_serial(modem, online, cb, user_data);
		return;
	}

	DBG("modem %p %s", modem, online ? "online" : "offline");

	if (online)
		gemalto_exec_stored_cmd(modem, "set_online");
	else
		gemalto_exec_stored_cmd(modem, "set_offline");

	if (g_at_chat_send(data->app, cmd, NULL, set_online_cb, cbd, g_free))
		return;

	CALLBACK_WITH_FAILURE(cb, cbd->data);
	g_free(cbd);
}

static void gemalto_pre_sim(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	DBG("%p", modem);
	gemalto_exec_stored_cmd(modem, "pre_sim");
	ofono_location_reporting_create(modem, 0, "gemaltomodem", data->app);
	data->sim = ofono_sim_create(modem, OFONO_VENDOR_GEMALTO,
		"atmodem", data->app);

	if (data->sim && data->have_sim == TRUE)
		ofono_sim_inserted_notify(data->sim, TRUE);
}

static int mbim_sim_probe(void *device)
{
	struct mbim_message *message;
	/* SIM_GROUP is defined in mbimmodem.h that cannot be included */
	uint32_t SIM_GROUP = 1;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_SUBSCRIBER_READY_STATUS,
					MBIM_COMMAND_TYPE_QUERY);
	if (!message)
		return -ENOMEM;

	mbim_message_set_arguments(message, "");

	if (!mbim_device_send(device, SIM_GROUP, message,
				NULL, NULL, NULL)) {
		mbim_message_unref(message);
		return -EIO;
	}
	return 0;
}

static void gemalto_post_sim(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	gemalto_exec_stored_cmd(modem, "post_sim");

	if (data->mbim == STATE_PRESENT) {
		/* very important to set the interface ready */
		mbim_sim_probe(data->mbimd);
	}

	ofono_phonebook_create(modem, 0, "atmodem", data->app);
	ofono_modem_set_integer(modem, "GemaltoAuthType", data->auth_syntax);

	if (data->has_lte)
		ofono_lte_create(modem, 0, "gemaltomodem", data->app);
}

static void cgdcont17_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->gprs_opt = USE_CTX17;
}

static void swwan_probe(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct gemalto_data *data = ofono_modem_get_data(user_data);

	if (ok)
		data->gprs_opt = USE_SWWAN;
}

static void autoattach_probe_and_continue(gboolean ok, GAtResult *result,
							gpointer user_data)
{
	struct ofono_modem* modem = user_data;
	struct gemalto_data *data = ofono_modem_get_data(modem);
	GAtResultIter iter;
	struct ofono_message_waiting *mw;
	struct ofono_gprs *gprs = NULL;
	struct ofono_gprs_context *gc = NULL;

	data->autoattach = FALSE;
	ofono_modem_set_integer(modem, "GemaltoAutoAttach", 0);

	if (ok) {
		g_at_result_iter_init(&iter, result);
		while (g_at_result_iter_next(&iter, NULL)) {
			if (strstr(g_at_result_iter_raw_line(&iter),
					"\"enabled\"")) {
				data->autoattach = TRUE;
				ofono_modem_set_integer(modem,
					"GemaltoAutoAttach", 1);

			}
		}
	}

	if (data->mbim == STATE_PRESENT) {
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		ofono_gprs_set_cid_range(gprs, 0, data->max_sessions);
		if (data->model == 0x65) {
			struct gemalto_mbim_composite comp;
			comp.device = data->mbimd;
			comp.chat = data->app;
			comp.at_cid = 4;
			gc = ofono_gprs_context_create(modem, 0, "gemaltomodemmbim", &comp);
		} else /* model == 0x5d, 0x62 (standard mbim driver) */
			gc = ofono_gprs_context_create(modem, 0, "mbim", data->mbimd);
	} else if (data->qmi == STATE_PRESENT) {
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		ofono_gprs_set_cid_range(gprs, 1, 1);
		gc = ofono_gprs_context_create(modem, 0, "qmimodem",
								data->qmid);
	} else if (data->gprs_opt == USE_SWWAN || data->gprs_opt == USE_CTX17 ||
						data->gprs_opt == USE_CTX3) {
		ofono_modem_set_integer(modem, "GemaltoWwan",
						data->gprs_opt == USE_SWWAN);
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		if (data->gprs_opt == USE_CTX3)
			ofono_gprs_set_cid_range(gprs, 3, 3);
		else if (data->model == 0x5b)
			/* limitation: same APN as for attach */
			ofono_gprs_set_cid_range(gprs, 1, 11);
		else
			ofono_gprs_set_cid_range(gprs, 4, 16);
		// maybe rename the next to gemaltomodem-wwan
		if (data->gprs_opt != USE_CTX3)
			gc = ofono_gprs_context_create(modem, 0,
						"gemaltomodemswwan", data->app);
		else
			gc = ofono_gprs_context_create(modem, 0,
					"gemaltomodemswwanblocking", data->app);
	} else if (data->gprs_opt == USE_PPP) {
		/* plain PPP only works from mdm ports */
		gprs = ofono_gprs_create(modem, OFONO_VENDOR_GEMALTO, "atmodem",
								data->app);
		if (data->model == 0x47)
			ofono_gprs_set_cid_range(gprs, 1, 2);
		else if (data->has_lte)
			ofono_gprs_set_cid_range(gprs, 4, 16);
		else
			ofono_gprs_set_cid_range(gprs, 1, 16);

		gc = ofono_gprs_context_create(modem, 0, "atmodem", data->mdm);

	} /*
	   * in case of no match above, we have no gprs possibilities
	   * this is common when using the module through serial interfaces
	   * nevertheless other services (voice, gpio, gnss) could be available
	   */

	if (gc)
		ofono_gprs_context_set_type(gc,
					OFONO_GPRS_CONTEXT_TYPE_INTERNET);

	if (gprs && gc)
		ofono_gprs_add_context(gprs, gc);

	/* might have also without voicecall support  */
	ofono_ussd_create(modem, 0, "atmodem", data->app);

	/*
	 * Call support is technically possible only after sim insertion
	 * with the module online. However the EMERGENCY_SETUP procedure of
	 * the 3GPP TS_24.008 is triggered by the same AT command,
	 * and namely 'ATD112;', 'ATD911;', etc.
	 * On the other hand, in airplane-mode it is not possible to do it, nor
	 * to create all relevant URCs for the atom.
	 *
	 * Ofono does not make a distinction between no-sim and
	 * airplane-mode scenarios, so we create the voicecall in post-online.
	 * This is compatible with the European directives that require
	 * a SIM inserted and PIN validated also for emergency setup.
	 */

	if (data->voice_avail) {
		ofono_modem_set_integer(modem, "GemaltoVtsQuotes",
						data->vts_with_quotes);
		ofono_voicecall_create(modem, 0, "gemaltomodem", data->app);

		ofono_call_forwarding_create(modem, 0, "atmodem", data->app);
		ofono_call_settings_create(modem, 0, "atmodem", data->app);
		ofono_call_meter_create(modem, 0, "atmodem", data->app);
		ofono_call_barring_create(modem, 0, "atmodem", data->app);
	}

	/* modules require to be online to accept at+cnmi */
	ofono_sms_create(modem, OFONO_VENDOR_GEMALTO, "atmodem", data->app);
	mw = ofono_message_waiting_create(modem);

	if (mw)
		ofono_message_waiting_register(mw);

	data->netreg = ofono_netreg_create(modem, OFONO_VENDOR_GEMALTO, "atmodem", data->app);
}

static int gemalto_post_online_delayed(void *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	/*
	 * check module capabilities once online and SIM really ready.
	 *
	 * Note: the g_at_chat_send calls only insert the commands in a list:
	 * they are not executed synchronously
	 *
	 * Note: ofono executes each AT commands and the related callback before
	 * proceeding with the next. So continuing on the last AT command is all
	 * it takes
	 */

	gemalto_exec_stored_cmd(modem, "post_online");

	if (data->ecmncm == STATE_PROBE) {
		data->gprs_opt = USE_PPP; /* fallback */
		g_at_chat_send(data->app, "AT+CGDCONT=17", NULL,
						cgdcont17_probe, modem, NULL);
		g_at_chat_send(data->app, "AT^SWWAN?", NULL, swwan_probe, modem,
									NULL);
	}

	g_at_chat_send(data->app, "AT^SCFG=\"GPRS/AutoAttach\"", NULL,
				autoattach_probe_and_continue, modem, NULL);

	return FALSE; /* to kill the timer */
}

static void gemalto_post_online(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	/*
	 * in this version of ofono we must wait for SIM 'really-ready'
	 * can be avoided when capturing the right URCs
	 */
	data->online_timer = g_timeout_add_seconds(5, gemalto_post_online_delayed, modem);
}

static void mbim_radio_off_for_disable(struct mbim_message *message, void *user)
{
	struct ofono_modem *modem = user;
	struct gemalto_data *md = ofono_modem_get_data(modem);

	DBG("%p", modem);

	mbim_device_shutdown(md->mbimd);
}

static int gemalto_disable_serial(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);

	if (data->app != NULL) {
		if (data->model == 0x47) {
			g_at_chat_send(data->app,
				"AT^SCFG=\"MEopMode/Airplane\",\"on\"",
				NULL, NULL, NULL, NULL);
		} else {
			gemalto_set_cfun(data->app, 41, modem);
			return -EINPROGRESS;
		}
		g_at_chat_cancel_all(data->app);
	}

	ofono_modem_set_powered(modem, FALSE);
	return 0;
}

static int gemalto_disable(struct ofono_modem *modem)
{
	struct gemalto_data *data = ofono_modem_get_data(modem);
	struct mbim_message *message;

	DBG("%p", modem);

	if (data->conn == GEMALTO_CONNECTION_SERIAL)
		return gemalto_disable_serial(modem);

	// Remove gemalto interfaces
	gemalto_hardware_control_disable(modem);
	gemalto_gnss_disable(modem);
	gemalto_time_disable(modem);
	gemalto_hardware_monitor_disable(modem);
	gemalto_command_passthrough_disable(modem);

	if (data->mbim == STATE_PRESENT) {
		message = mbim_message_new(mbim_uuid_basic_connect,
						MBIM_CID_RADIO_STATE,
						MBIM_COMMAND_TYPE_SET);
		mbim_message_set_arguments(message, "u", 0);

		mbim_device_send(data->mbimd, 0, message,
			mbim_radio_off_for_disable, modem, NULL);
		mbim_device_shutdown(data->mbimd);
		mbim_device_unref(data->mbimd);
		data->mbimd = NULL;
		data->mbim = STATE_ABSENT;
	}

	if (data->app == NULL)
		return 0;

	// FIXME AT channel must be active for below to work
	gemalto_exec_stored_cmd(modem, "disable");
	gemalto_set_cfun(data->app, 41, modem);

	return -EINPROGRESS;
}

static const struct ofono_modem_driver gemalto_driver = {
	.name		= "gemalto",
	.probe		= gemalto_probe,
	.remove		= gemalto_remove,
	.enable		= gemalto_enable,
	.disable	= gemalto_disable,
	.set_online	= gemalto_set_online,
	.pre_sim	= gemalto_pre_sim,
	.post_sim	= gemalto_post_sim,
	.post_online	= gemalto_post_online,
};

static int gemalto_init(void)
{
	return ofono_modem_driver_register(&gemalto_driver);
}

static void gemalto_exit(void)
{
	ofono_modem_driver_unregister(&gemalto_driver);
}

OFONO_PLUGIN_DEFINE(gemalto, "Gemalto modem plugin", VERSION,
		OFONO_PLUGIN_PRIORITY_DEFAULT, gemalto_init, gemalto_exit)

