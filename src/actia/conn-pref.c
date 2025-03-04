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
#include "conn-pref.h"

#include "common.h"
#include "util.h"

static GSList *g_drivers = NULL;

struct ofono_connpref {
	DBusMessage                  *pending;
	guint16                      default_cid;
	char                         **contextprofiles_list;
	char                         *bip_address_ip;
	void                         *driver_data;
	struct                       ofono_atom *atom;
	const struct                 ofono_connpref_driver *driver;
	int                          ims_autoconnect;
	int                          rpm;
};

static gboolean connpref_from_string_to_pdp_type(const char *str,
                                                 enum ofono_connpref_is_pdp_type *out)
{
	if (g_str_equal(str, OFONO_CONNPREF_PDP_TYPE_IP)) {
		*out = OFONO_CONNPREF_IS_PDP_TYPE_IP;
		return TRUE;
	} else if (g_str_equal(str, OFONO_CONNPREF_PDP_TYPE_IPV6)) {
		*out = OFONO_CONNPREF_IS_PDP_TYPE_IPV6;
		return TRUE;
	} else if (g_str_equal(str, OFONO_CONNPREF_PDP_TYPE_IPV4V6)) {
		*out = OFONO_CONNPREF_IS_PDP_TYPE_IPV4V6;
		return TRUE;
	} else if (g_str_equal(str, OFONO_CONNPREF_PDP_TYPE_NONE)) {
		*out = OFONO_CONNPREF_IS_PDP_TYPE_NONE;
		return TRUE;
	}

	return FALSE;
}

static gboolean connpref_verify_cid(guint16 cid)
{
	return ((cid > 0) && (cid <18));
}

static void connpref_set_bip_address_ip(struct ofono_connpref *connpref,
                                        char * bip_address_ip)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path;

	if (g_strcmp0(connpref->bip_address_ip,bip_address_ip) == 0)
		return;

	connpref->bip_address_ip = bip_address_ip;
	path = __ofono_atom_get_path(connpref->atom);

	ofono_dbus_signal_property_changed(conn, path,
	                                   OFONO_CONNPREF_INTERFACE,
	                                   ACTIA_PRO_BIP_SERVER_IP_ADDRESS,
	                                   DBUS_TYPE_STRING, &bip_address_ip);
}

static void connpref_set_context_profile_list(struct ofono_connpref *connpref,
                                              char * contextprofiles_list[],
                                              int contextprofile_size)
{
	int nelem = contextprofile_size;
	int i=0;
	char * elem;
	char **ret;

	DBG("");

	ret = g_new0(char *, nelem + 1);

	nelem = 0;
	for (i=0; i<contextprofile_size; i++) {
		elem = contextprofiles_list[i];
		ret[nelem++] = elem;
	}

	connpref->contextprofiles_list= ret;

}

static void connpref_set_ims_autoconnect(struct ofono_connpref *connpref, int ims_autoconnect)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path;
	dbus_bool_t value;

	if (connpref->ims_autoconnect == ims_autoconnect)
		return;

	connpref->ims_autoconnect = ims_autoconnect;
	value = ims_autoconnect;

	path = __ofono_atom_get_path(connpref->atom);

	ofono_dbus_signal_property_changed(conn, path,
	                                   OFONO_CONNPREF_INTERFACE,
	                                   ACTIA_PRO_IMSAUTOCONNECT,
	                                   DBUS_TYPE_BOOLEAN, &value);
}

static void connpref_set_rpm(struct ofono_connpref *connpref, int rpm)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	const char *path;
	dbus_bool_t value;

	if (connpref->rpm == rpm)
		return;

	connpref->rpm = rpm;
	value = rpm;

	path = __ofono_atom_get_path(connpref->atom);

	ofono_dbus_signal_property_changed(conn, path,
	                                   OFONO_CONNPREF_INTERFACE,
	                                   ACTIA_PRO_RPM,
	                                   DBUS_TYPE_BOOLEAN, &value);
}

static DBusMessage *connpref_get_properties_reply(DBusMessage *msg,
                                                  struct ofono_connpref *connpref)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;

	guint16 default_cid = connpref->default_cid ;
	char * bip_server_ip_address = connpref->bip_address_ip;
	dbus_bool_t value = connpref->ims_autoconnect;

	reply = dbus_message_new_method_return(msg);

	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
	                                 OFONO_PROPERTIES_ARRAY_SIGNATURE,
	                                 &dict);
	if (default_cid > 0)
		ofono_dbus_dict_append(&dict, ACTIA_PRO_DEFAULT_CONTEXT,
		                       DBUS_TYPE_UINT16, &default_cid);

	if (connpref->contextprofiles_list){
		char ** contextprofiles_list= connpref->contextprofiles_list;

		ofono_dbus_dict_append_array(&dict, ACTIA_PRO_CONTEXTROFILES, DBUS_TYPE_STRING,
		                             &contextprofiles_list);

		g_strfreev(contextprofiles_list);
	}

	if (bip_server_ip_address)
		ofono_dbus_dict_append(&dict, ACTIA_PRO_BIP_SERVER_IP_ADDRESS,
		                       DBUS_TYPE_STRING, &bip_server_ip_address);

	ofono_dbus_dict_append(&dict, ACTIA_PRO_IMSAUTOCONNECT,
		                       DBUS_TYPE_BOOLEAN, &value);

	value = connpref->rpm;
	ofono_dbus_dict_append(&dict, ACTIA_PRO_RPM,
		                       DBUS_TYPE_BOOLEAN, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void connpref_config_query_callback(const struct ofono_error *error,
                                           char * contextprofiles_list[],
                                           char *bip_address_ip_str,
                                           int contextprofile_size,
                                           int ims_autoconnect,
                                           int rpm,
                                           void *data)
{
	struct ofono_connpref *ofono_connpref = data;
	DBusMessage *reply;

	DBG("%p %s %d %d",contextprofiles_list, bip_address_ip_str, ims_autoconnect, rpm);

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		DBG("Error during config query");

		if(ofono_connpref->pending) {
			reply = __ofono_error_failed(ofono_connpref->pending);
			__ofono_dbus_pending_reply(&ofono_connpref->pending, reply);
		}

		return ;
	}

	connpref_set_bip_address_ip(ofono_connpref, bip_address_ip_str);
	connpref_set_context_profile_list(ofono_connpref, contextprofiles_list,contextprofile_size);
	connpref_set_ims_autoconnect(ofono_connpref,ims_autoconnect);
	connpref_set_rpm(ofono_connpref,rpm);

	if (ofono_connpref->pending) {
		reply = connpref_get_properties_reply(ofono_connpref->pending, ofono_connpref);
		__ofono_dbus_pending_reply(&ofono_connpref->pending, reply);
	}
}

static void connpref_cntxprofile_set_callback(const struct ofono_error *error,
                                              void *data)
{
	struct ofono_connpref *connpref = data;
	DBusMessage *reply;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		DBG("Error setting context profile");

		reply = __ofono_error_failed(connpref->pending);
		__ofono_dbus_pending_reply(&connpref->pending, reply);

		return;
	}

	reply = dbus_message_new_method_return(connpref->pending);
	__ofono_dbus_pending_reply(&connpref->pending, reply);

}

static void connpref_ims_set_callback(const struct ofono_error *error,
                                              void *data)
{
	struct ofono_connpref *connpref = data;
	DBusMessage *reply;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		DBG("Error setting IMSAutoconnect property");

		reply = __ofono_error_failed(connpref->pending);
		__ofono_dbus_pending_reply(&connpref->pending, reply);
		return;
	}

	reply = dbus_message_new_method_return(connpref->pending);
	__ofono_dbus_pending_reply(&connpref->pending, reply);

}

static void connpref_rpm_set_callback(const struct ofono_error *error,
                                              void *data)
{
	struct ofono_connpref *connpref = data;
	DBusMessage *reply;

	if (error->type != OFONO_ERROR_TYPE_NO_ERROR) {
		DBG("Error setting RPM property");

		reply = __ofono_error_failed(connpref->pending);
		__ofono_dbus_pending_reply(&connpref->pending, reply);

		return;
	}

	reply = dbus_message_new_method_return(connpref->pending);
	__ofono_dbus_pending_reply(&connpref->pending, reply);

}

static DBusMessage *connpref_get_properties(DBusConnection *conn,
                                            DBusMessage *msg, void *data)
{
	struct ofono_connpref *connpref = data;

	if (connpref->driver->query_connpref_config == NULL)
		return __ofono_error_not_implemented(msg);

	if(connpref->pending)
		return __ofono_error_busy(msg);

	connpref->pending = dbus_message_ref(msg);

	connpref->driver->query_connpref_config(connpref,
	                                        connpref_config_query_callback, connpref );

	return NULL;
}

static DBusMessage *connpref_set_context_profile(DBusConnection *conn, DBusMessage *msg,
                                                 void *data)
{
	struct ofono_connpref *connpref = data;
	guint16 cid;
	char * apn;
	const char *pdp_type_str;
	enum ofono_connpref_is_pdp_type pdp_type;


	if (connpref->pending)
		return __ofono_error_busy(msg);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT16, &cid,
	                           DBUS_TYPE_STRING, &apn, DBUS_TYPE_STRING, &pdp_type_str,DBUS_TYPE_INVALID))
		return __ofono_error_invalid_args(msg);

	if (connpref_from_string_to_pdp_type(pdp_type_str, &pdp_type) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (connpref_verify_cid(cid) == FALSE)
		return __ofono_error_invalid_args(msg);

	if (connpref->driver->set_connpref_context_profile == NULL)
		return __ofono_error_not_implemented(msg);

	connpref->pending = dbus_message_ref(msg);

	connpref->driver->set_connpref_context_profile(connpref, cid, apn, pdp_type,
	                                               connpref_cntxprofile_set_callback, connpref);

	return NULL;
}

static DBusMessage *connpref_set_property(DBusConnection *conn, DBusMessage *msg,
                                          void *data)
{
	struct ofono_connpref *connpref = data;
	DBusMessageIter iter;
	DBusMessageIter var;
	const char *property;
	const char *path = __ofono_atom_get_path(connpref->atom);

	if (connpref->pending)
		return __ofono_error_busy(msg);

	if (!dbus_message_iter_init(msg, &iter))
		return __ofono_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &var);

	if (g_strcmp0(property, ACTIA_PRO_DEFAULT_CONTEXT) == 0) {
		guint16 cid;

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_UINT16)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &cid);
		/* DefaultContext can be set to 0 to not force cid */
		if (cid != 0 && connpref_verify_cid (cid) == FALSE)
			return __ofono_error_invalid_args(msg);

		if (connpref->default_cid == cid)
			return dbus_message_new_method_return(msg);

		connpref->default_cid = cid;

		if (connpref->driver->set_connpref_default_context) {
			connpref->driver->set_connpref_default_context(connpref, cid);
		}

		ofono_dbus_signal_property_changed(conn, path,
		                                   OFONO_CONNPREF_INTERFACE,
		                                   ACTIA_PRO_DEFAULT_CONTEXT,
		                                   DBUS_TYPE_UINT16, &cid);

		return dbus_message_new_method_return(msg);
	}

	/* IMSAutoconnect */
	if (g_strcmp0(property, ACTIA_PRO_IMSAUTOCONNECT) == 0) {
		dbus_bool_t value;

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_BOOLEAN)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &value);

		if (connpref->driver->set_connpref_ims_autoconnect == NULL)
			return __ofono_error_not_implemented(msg);

		connpref->ims_autoconnect = value;

		connpref->pending = dbus_message_ref(msg);

		connpref->driver->set_connpref_ims_autoconnect(connpref, value, connpref_ims_set_callback, connpref);

		return NULL;
	}

	/* RPM */
	if (g_strcmp0(property, ACTIA_PRO_RPM) == 0) {
		dbus_bool_t rpm;

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_BOOLEAN)
			return __ofono_error_invalid_args(msg);

		dbus_message_iter_get_basic(&var, &rpm);

		if (connpref->driver->set_connpref_rpm == NULL)
			return __ofono_error_not_implemented(msg);

		connpref->rpm = rpm;

		connpref->pending = dbus_message_ref(msg);

		connpref->driver->set_connpref_rpm(connpref, rpm, connpref_rpm_set_callback, connpref);

		return NULL;
	}

	return __ofono_error_invalid_args(msg);
}

static const GDBusMethodTable connpref_methods[] = {
	{ GDBUS_ASYNC_METHOD("GetProperties",
	                     NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
	                     connpref_get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
	                     GDBUS_ARGS({ "property", "s" }, { "value", "v" }),
	                     NULL, connpref_set_property) },
	{ GDBUS_ASYNC_METHOD("SetContextProfile",
	                     GDBUS_ARGS({ "cid","q"}, {"apn", "s"}, {"pdp_type", "s"}),
	                     NULL, connpref_set_context_profile) },
	{ }
};

static const GDBusSignalTable connpref_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
	               GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ }
};

int ofono_connpref_driver_register(const struct ofono_connpref_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	if (d == NULL || d->probe == NULL)
		return -EINVAL;

	g_drivers = g_slist_prepend(g_drivers, (void *) d);

	return 0;
}

void ofono_connpref_driver_unregister(const struct ofono_connpref_driver *d)
{
	DBG("driver: %p, name: %s", d, d->name);

	if (d == NULL)
		return;

	g_drivers = g_slist_remove(g_drivers, (void *) d);
}

static void connpref_settings_unregister(struct ofono_atom *atom)
{
	struct ofono_connpref *connpref = __ofono_atom_get_data(atom);
	const char *path = __ofono_atom_get_path(connpref->atom);
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(connpref->atom);

	ofono_modem_remove_interface(modem, OFONO_CONNPREF_INTERFACE);
	g_dbus_unregister_interface(conn, path, OFONO_CONNPREF_INTERFACE);
}

static void connpref_remove(struct ofono_atom *atom)
{
	struct ofono_connpref *connpref = __ofono_atom_get_data(atom);

	DBG("atom: %p", atom);

	if (connpref == NULL)
		return;

	if (connpref->driver && connpref->driver->remove)
		connpref->driver->remove(connpref);

	g_free(connpref);
}

struct ofono_connpref *ofono_connpref_create(struct ofono_modem *modem,
                                             unsigned int vendor,
                                             const char *driver,
                                             void *data)
{
	struct ofono_connpref *connpref;
	GSList *l;

	if (driver == NULL)
		return NULL;

	connpref = g_try_new0(struct ofono_connpref, 1);
	if (connpref == NULL)
		return NULL;

	connpref->default_cid = 0; // DEFAULT: cid not forced
	connpref->contextprofiles_list = NULL;
	connpref->ims_autoconnect = -1;
	connpref->rpm = -1;

	connpref->atom = __ofono_modem_add_atom(modem, OFONO_ATOM_TYPE_CONNPREF,
	                                        connpref_remove, connpref);

	for (l = g_drivers; l; l = l->next) {
		const struct ofono_connpref_driver *drv = l->data;

		if (g_strcmp0(drv->name, driver) != 0)
			continue;

		if (drv->probe(connpref, vendor, data) < 0)
			continue;

		connpref->driver = drv;
		break;
	}

	return connpref;
}

void ofono_connpref_register(struct ofono_connpref *connpref)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	struct ofono_modem *modem = __ofono_atom_get_modem(connpref->atom);
	const char *path = __ofono_atom_get_path(connpref->atom);
	if (!g_dbus_register_interface(conn, path,
	                               OFONO_CONNPREF_INTERFACE,
	                               connpref_methods, connpref_signals,
	                               NULL, connpref, NULL))
	{
		ofono_error("Could not create %s interface",
		            OFONO_CONNPREF_INTERFACE);

		return;
	}
	ofono_modem_add_interface(modem, OFONO_CONNPREF_INTERFACE);
	__ofono_atom_register(connpref->atom, connpref_settings_unregister);
}

void ofono_connpref_remove(struct ofono_connpref *connpref)
{
	__ofono_atom_free(connpref->atom);
}

void ofono_connpref_set_data(struct ofono_connpref *connpref,
                           void *data)
{
	connpref->driver_data = data;
}

void *ofono_connpref_get_data(struct ofono_connpref *connpref)
{
	return connpref->driver_data;
}

guint16 ofono_connpref_get_default_context(struct ofono_connpref *connpref)
{
	return connpref->default_cid;
}

void ofono_connpref_set_default_context(struct ofono_connpref *connpref, guint16 cid)
{

	connpref->default_cid = cid;
}
