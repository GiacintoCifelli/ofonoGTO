#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include <glib.h>
#include <gdbus.h>

#include "ofono.h"
#include "sim-switch.h"

#include "common.h"
#include "util.h"

static GSList *g_drivers = NULL;


struct ofono_sim_switch {
	DBusMessage *pending;
	unsigned int card_slot_count;
	unsigned int active_card_slot;
	unsigned int pending_active_card_slot;
	void *driver_data;
	struct ofono_atom *atom;
	const struct ofono_sim_switch_driver *driver;
};

static void sim_switch_set_slot_callback(const struct ofono_error *error, void *data)
{
	struct ofono_sim_switch *ssw = data;
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path = __ofono_atom_get_path(ssw->atom);
	DBusMessage *reply;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		DBG("Error setting sim switch type");

		ssw->pending_active_card_slot = ssw->active_card_slot;

		reply = __ofono_error_from_error(error, ssw->pending);
		__ofono_dbus_pending_reply(&ssw->pending, reply);

		return;
	}

	ssw->active_card_slot = ssw->pending_active_card_slot;

	reply = dbus_message_new_method_return(ssw->pending);
	__ofono_dbus_pending_reply(&ssw->pending, reply);

	ofono_dbus_signal_property_changed(conn, path,
						OFONO_SIM_SWITCH_INTERFACE,
						ACTIA_PRO_ACTIVE_CARD_SLOT,
						DBUS_TYPE_UINT32,
						&ssw->active_card_slot);
}


static DBusMessage *sim_switch_get_properties(DBusConnection *conn,
                                              DBusMessage *msg, void *data)
{
	struct ofono_sim_switch *ssw = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
										OFONO_PROPERTIES_ARRAY_SIGNATURE,
										&dict);

	ofono_dbus_dict_append(&dict, ACTIA_PRO_CARD_SLOT_COUNT, DBUS_TYPE_UINT32,
							&ssw->card_slot_count);

	ofono_dbus_dict_append(&dict, ACTIA_PRO_ACTIVE_CARD_SLOT, DBUS_TYPE_UINT32,
							&ssw->active_card_slot);


	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *sim_switch_set_property(DBusConnection *conn,
                                            DBusMessage *msg,
                                            void *data)
{
	struct ofono_sim_switch *ssw = data;
	DBusMessageIter iter;
	DBusMessageIter var;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);

	if (g_strcmp0(property, ACTIA_PRO_ACTIVE_CARD_SLOT) == 0) {
		dbus_uint32_t value;

		dbus_message_iter_next(&iter);

		if (ssw->driver->set_active_card_slot == NULL)
			return __ofono_error_not_implemented(msg);

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_recurse(&iter, &var);

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_UINT32)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &value);

		if (value <= 0 || value > ssw->card_slot_count)
			return __ofono_error_invalid_args(msg);

		if (ssw->active_card_slot == value)
			return dbus_message_new_method_return(msg);

		ssw->pending = dbus_message_ref(msg);
		ssw->pending_active_card_slot = value;

		ssw->driver->set_active_card_slot(ssw, value - 1,
							sim_switch_set_slot_callback,
							ssw);
		return NULL;
	}

	return __ofono_error_invalid_args(msg);
}

static const GDBusMethodTable sim_switch_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			sim_switch_get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "property", "s" }, { "value", "v" }),
			NULL, sim_switch_set_property) },
	{ }
};

static const GDBusSignalTable sim_switch_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ }
};

int ofono_sim_switch_driver_register(const struct ofono_sim_switch_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	if (d == NULL || d->probe == NULL)
		return -EINVAL;

	g_drivers = g_slist_prepend(g_drivers, (void *) d);

	return 0;
}

void ofono_sim_switch_driver_unregister(const struct ofono_sim_switch_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	if (d == NULL)
		return;

	g_drivers = g_slist_remove(g_drivers, (void *) d);
}

static void sim_switch_settings_unregister(struct ofono_atom *atom)
{
	struct ofono_sim_switch *ssw = __ofono_atom_get_data(atom);
	const char *path = __ofono_atom_get_path(ssw->atom);
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(ssw->atom);

	ofono_modem_remove_interface(modem, OFONO_SIM_SWITCH_INTERFACE);
	g_dbus_unregister_interface(conn, path, OFONO_SIM_SWITCH_INTERFACE);
}

static void sim_switch_remove(struct ofono_atom *atom)
{
	struct ofono_sim_switch *ssw = __ofono_atom_get_data(atom);

	DBG("atom: %p", atom);

	if (ssw == NULL)
		return;

	if (ssw->driver && ssw->driver->remove)
		ssw->driver->remove(ssw);

	g_free(ssw);
}

struct ofono_sim_switch *ofono_sim_switch_create(struct ofono_modem *modem,
                                                 unsigned int vendor,
                                                 const char *driver,
                                                 void *data)
{
	struct ofono_sim_switch *ssw;
	GSList *l;

	if (driver == NULL)
		return NULL;

	ssw = g_try_new0(struct ofono_sim_switch, 1);
	if (ssw == NULL)
		return NULL;

	ssw->atom = __ofono_modem_add_atom(modem, OFONO_ATOM_TYPE_SIM_SWITCH,
										sim_switch_remove, ssw);

	ssw->active_card_slot = 1;
	ssw->card_slot_count = 1;

	for (l = g_drivers; l; l = l->next) {
		const struct ofono_sim_switch_driver *drv = l->data;

		if (g_strcmp0(drv->name, driver) != 0)
			continue;

		if (drv->probe(ssw, vendor, data) < 0)
			continue;

		ssw->driver = drv;
		break;
	}

	return ssw;
}

void ofono_sim_switch_register(struct ofono_sim_switch *ssw)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(ssw->atom);
	const char *path = __ofono_atom_get_path(ssw->atom);
	if (modem == NULL){
		ofono_error("Could not find modem");
		return;
	}
	DBG("");
	if (!g_dbus_register_interface(	conn, path,
									OFONO_SIM_SWITCH_INTERFACE,
									sim_switch_methods, sim_switch_signals,
									NULL, ssw, NULL))
	{
		ofono_error("Could not create %s interface",
				OFONO_SIM_SWITCH_INTERFACE);

		return;
	}
	ofono_modem_add_interface(modem, OFONO_SIM_SWITCH_INTERFACE);
	__ofono_atom_register(ssw->atom, sim_switch_settings_unregister);
}

void ofono_sim_switch_remove(struct ofono_sim_switch *ssw)
{
	__ofono_atom_free(ssw->atom);
}

void ofono_sim_switch_set_data(struct ofono_sim_switch *ssw,
					void *data)
{
	ssw->driver_data = data;
}

void *ofono_sim_switch_get_data(struct ofono_sim_switch *ssw)
{
	return ssw->driver_data;
}

void ofono_sim_switch_set_card_slot_count(struct ofono_sim_switch *ssw, unsigned int val)
{
	if (ssw)
		ssw->card_slot_count = val;
}

void ofono_sim_switch_set_active_card_slot(struct ofono_sim_switch *ssw, unsigned int val)
{
	if (ssw)
		ssw->active_card_slot = val;
}