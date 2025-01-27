#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>
#include <gio/gio.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/dbus.h>
#include <actia/conn-pref.h>
#include <actia/default-properties.h>

#include "gatchat.h"
#include "gatresult.h"
#include "gemaltomodem.h"
#include "src/actia/vendor.h"

static const char *cgdcont_prefix[] = { "+CGDCONT:", NULL };
static const char *cgpaddr_prefix[] = { "+CGPADDR:", NULL };
static const char *scfg_prefix[] = { "^SCFG:", NULL };
static const char *sinfo_prefix[] = { "^SINFO:", NULL };

struct connpref_data {
	GAtChat *chat;
	unsigned int vendor;
	/*A max of 16 cid to be stored*/
	char *contextprofiles_list[16];
	char address[64];
	int contextprofile_size;
	int rpm;
};

static void gemalto_ims_cb(gboolean ok, GAtResult *result,
                               gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	struct ofono_connpref *connpref =  cbd->data;
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	ofono_connpref_contextprofiles_query_cb_t cb = cbd->cb;
	const char *value;
	int ims_autoconnect = -1;
	GAtResultIter iter;

	DBG("");

	decode_at_error(&error, g_at_result_final_response(result));

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "^SCFG: \"MEopMode/IMS\",")) {

		if (!g_at_result_iter_next_string(&iter, &value))
			goto error;

		if (g_str_equal(value, "1"))
			ims_autoconnect = 1 ;
		else
			ims_autoconnect = 0 ;

		CALLBACK_WITH_SUCCESS(cb, cp_data->contextprofiles_list, cp_data->address, cp_data->contextprofile_size, ims_autoconnect, cp_data->rpm, cbd->data);
		return;
	}

error:
	CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
}

static void gemalto_cgdcont_cb(gboolean ok, GAtResult *result,
                               gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	struct ofono_connpref *connpref =  cbd->data;
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	ofono_connpref_contextprofiles_query_cb_t cb = cbd->cb;
	int cid = -1;
	const char *pdp_type ;
	const char *apn ;
	GAtResultIter iter;
	int i=0;

	DBG("");

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok)
	{
		/*do not apply a strict check policy on fail*/
		if (g_at_chat_send(cp_data->chat, "AT^SCFG=\"MEopMode/IMS\"",scfg_prefix, gemalto_ims_cb, cbd, g_free) == 0) {
			CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
			g_free(cbd);
	}
		return ;
	}

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, "+CGDCONT:")) {

		/*handle empty reponse*/
		if (!g_at_result_iter_next_number(&iter, &cid)){
			if ( cid == -1)
				continue ;
			else
				goto error;
		}

		if (!g_at_result_iter_next_string(&iter, &pdp_type))
			goto error;
		if (!g_at_result_iter_next_string(&iter, &apn))
			goto error;

		DBG("element %d: cid:%d ,apn:%s, pdp_type:%s",i,cid,apn,pdp_type);

		char buf[50];

		snprintf(buf, sizeof(buf), "%d,%s,%s", cid, apn, pdp_type);

		cp_data->contextprofiles_list[i] = g_strndup(buf,sizeof(buf));
		i++;
	}

	cp_data->contextprofile_size = i;

	if (g_at_chat_send(cp_data->chat, "AT^SCFG=\"MEopMode/IMS\"",scfg_prefix, gemalto_ims_cb, cbd, g_free) == 0) {
		CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
		g_free(cbd);
	}
	return;

error:
	CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
}

/* For PLS62 */
static void gemalto_address_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	struct ofono_connpref *connpref =  cbd->data;
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	ofono_connpref_contextprofiles_query_cb_t cb = cbd->cb;
	int cid;
	const char *address;
	GAtResultIter iter;

	decode_at_error(&error, g_at_result_final_response(result));

	DBG("ok %d", ok);

	if (!ok) {
		goto error;
	}

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CGPADDR:"))
		goto error;

	if (!g_at_result_iter_next_number(&iter, &cid))
		goto error;

	if (!g_at_result_iter_next_string(&iter, &address))
		goto error;

	if (strlen(address) >= sizeof(cp_data->address)) {
		ofono_error("Retrieved address is too long");
		goto error;
	}

	strncpy(cp_data->address, address, sizeof(cp_data->address) - 1);
	cp_data->address[sizeof(cp_data->address) - 1] = '\0';

	DBG("BIP server address: %s", cp_data->address);

	if (g_at_chat_send(cp_data->chat, "AT+CGDCONT?", cgdcont_prefix, gemalto_cgdcont_cb, cbd, g_free) == 0) {
		CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
		g_free(cbd);
	}

	return;

error:
	CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
	g_free(cbd);

}

static void gemalto_query_connpref_config_step2(struct cb_data *cbd,
												struct connpref_data *cp_data)
{
	ofono_connpref_contextprofiles_query_cb_t cb = cbd->cb;
	DBG("");
	// TODO: change OFONO_VENDOR_GEMALTO_CINT_PLS62 to OFONO_VENDOR_GEMALTO_PLS62
	if (cp_data->vendor == OFONO_VENDOR_GEMALTO_CINT_PLS62) {
		if (g_at_chat_send(cp_data->chat, "AT+CGPADDR", cgpaddr_prefix, gemalto_address_cb, cbd, NULL) == 0){
			CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list,NULL, -1, -1, -1, cbd->data);
			g_free(cbd);
		}
	} else {
		if (g_at_chat_send(cp_data->chat, "AT+CGDCONT?", cgdcont_prefix, gemalto_cgdcont_cb, cbd, NULL) == 0) {
			CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list,NULL, -1, -1, -1, cbd->data);
			g_free(cbd);
		}
	}
}

static void gemalto_sinfo_cb(gboolean ok, GAtResult *result,
                               gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	struct ofono_connpref *connpref =  cbd->data;
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	ofono_connpref_contextprofiles_query_cb_t cb = cbd->cb;
	const char *str_value ;
	GAtResultIter iter;

	DBG("");

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok)
	{
		CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
		g_free(cbd);
		return ;
	}
	g_at_result_iter_init(&iter, result);
	if (!g_at_result_iter_next(&iter,"^SINFO:"))
		goto error;
	if (!g_at_result_iter_skip_next(&iter))
		goto error;
	if (!g_at_result_iter_next_string(&iter, &str_value))
		goto error;

	if (g_str_equal(str_value, "1"))
			cp_data->rpm= 1 ;
	else
			cp_data->rpm= 0 ;

	DBG("RPM enable : %d",cp_data->rpm);
	gemalto_query_connpref_config_step2(cbd,cp_data);
	return;

error:
	CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list, NULL, -1, -1, -1, cbd->data);
	g_free(cbd);
}

static void gemalto_query_connpref_config(struct ofono_connpref *connpref,
                                          ofono_connpref_contextprofiles_query_cb_t cb,
                                          void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);

	DBG("");
	// TODO: change OFONO_VENDOR_GEMALTO_CINT_PLS83 -> OFONO_VENDOR_GEMALTO_PLS63_PLS83
	if (cp_data->vendor == OFONO_VENDOR_GEMALTO_CINT_PLS83){
		if (g_at_chat_send(cp_data->chat, "AT^SINFO?", sinfo_prefix, gemalto_sinfo_cb, cbd, NULL) == 0) {
			CALLBACK_WITH_FAILURE(cb, cp_data->contextprofiles_list,NULL, -1, -1, -1, cbd->data);
			g_free(cbd);
		}
	} else {
		cp_data->rpm = FALSE;
		gemalto_query_connpref_config_step2(cbd,cp_data);
	}
}

static void gemalto_cgdcont_set_cb(gboolean ok, GAtResult *result,
                                   gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	ofono_connpref_techno_set_cb_t cb = cbd->cb;

	DBG("");

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok)
	{
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		return ;
	}

	CALLBACK_WITH_SUCCESS(cb, cbd->data);
}

static void gemalto_ims_set_cb(gboolean ok, GAtResult *result,
                                   gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	ofono_connpref_techno_set_cb_t cb = cbd->cb;

	DBG("");

	decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void gemalto_srpom_set_cb(gboolean ok, GAtResult *result,
                                   gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	ofono_connpref_techno_set_cb_t cb = cbd->cb;

	DBG("");

	decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void gemalto_rpm_set_cb(gboolean ok, GAtResult *result,
                                   gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_error error;
	ofono_connpref_techno_set_cb_t cb = cbd->cb;
	struct ofono_connpref *connpref =  cbd->data;
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	char buf[128];
	GAtResultIter iter;
	const char *value;

	DBG("");
	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);
	if (!g_at_result_iter_next(&iter, "^SCFG: \"MEopMode/RPM\","))
		goto error;

	if (!g_at_result_iter_next_string(&iter, &value))
		goto error;

	if (g_str_equal(value, "2")) {
		/*
		* SRPOM also need to be enable to activate RPM.
		* There is no need to disable SRPOM when desactive RPM since
		* it is already done by AT^SCFG="MEopMode/RPM","0"
		*/
		snprintf(buf, sizeof(buf),"AT^SCFG=\"MEopMode/SRPOM\",\"1\"");
		if (g_at_chat_send(cp_data->chat, buf, scfg_prefix,gemalto_srpom_set_cb, cbd, g_free) == 0){
			goto error;
		}
	} else {
		cb(&error, cbd->data);
		g_free(cbd);
	}
	return;
error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	g_free(cbd);
}

static char * gemalto_from_pdp_type_to_string(const enum ofono_connpref_is_pdp_type pdp_type)
{
	switch (pdp_type) {
		case OFONO_CONNPREF_IS_PDP_TYPE_IP:
			return OFONO_CONNPREF_PDP_TYPE_IP;
			break;
		case OFONO_CONNPREF_IS_PDP_TYPE_IPV6:
			return OFONO_CONNPREF_PDP_TYPE_IPV6;
			break;
		case OFONO_CONNPREF_IS_PDP_TYPE_IPV4V6:
			return OFONO_CONNPREF_PDP_TYPE_IPV4V6 ;
			break;
		case OFONO_CONNPREF_IS_PDP_TYPE_NONE:
			return OFONO_CONNPREF_PDP_TYPE_NONE ;
			break;
	}

	return "";
}

static void gemalto_set_connpref_context_profile(struct ofono_connpref *connpref,
                                                 guint16 cid,
                                                 char * apn,
                                                 enum ofono_connpref_is_pdp_type pdp_type,
                                                 ofono_connpref_techno_set_cb_t cb,
                                                 void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	char buf[128];

	DBG("cid:%d, apn:%s,pdp type:%d", cid, apn, pdp_type);

	char * pdp_type_is = gemalto_from_pdp_type_to_string(pdp_type);

	cbd->user = cp_data;

	/*to erase config, only cid should be defined*/
	if (g_str_equal (pdp_type_is,"") && g_str_equal (apn,""))
		snprintf(buf, sizeof(buf), "AT+CGDCONT=%u", cid);
	else
		snprintf(buf, sizeof(buf), "AT+CGDCONT=%u,\"%s\",\"%s\"", cid, pdp_type_is, apn);

	if (g_at_chat_send(cp_data->chat, buf, cgdcont_prefix, gemalto_cgdcont_set_cb, cbd, g_free) == 0){

		CALLBACK_WITH_FAILURE(cb, cbd->data);
		g_free(cbd);
	}
}

static void gemalto_set_ims_autoconnect(struct ofono_connpref *connpref,
                                        ofono_bool_t ims_autoconnect,
                                        ofono_connpref_techno_set_cb_t cb,
                                        void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	char buf[128];

	DBG("IMSAutoconnect : %d",ims_autoconnect);

	snprintf(buf, sizeof(buf),"AT^SCFG=\"MEopMode/IMS\",\"%i\"",ims_autoconnect ? 1:0);

	if (g_at_chat_send(cp_data->chat, buf, scfg_prefix,gemalto_ims_set_cb, cbd, g_free) == 0){
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		g_free(cbd);
	}
}

static void gemalto_set_rpm(struct ofono_connpref *connpref,
							ofono_bool_t rpm,
							ofono_connpref_techno_set_cb_t cb,
							void *data)
{
	struct cb_data *cbd = cb_data_new(cb, data);
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);
	char buf[128];

	// TODO: change OFONO_VENDOR_GEMALTO_CINT_PLS83 -> OFONO_VENDOR_GEMALTO_PLS63_PLS83
	if (cp_data->vendor == OFONO_VENDOR_GEMALTO_CINT_PLS83){
		DBG("Set RPM : %d",rpm);
		snprintf(buf, sizeof(buf),"AT^SCFG=\"MEopMode/RPM\",\"%i\"",rpm ? 2:0);
		if (g_at_chat_send(cp_data->chat, buf, scfg_prefix,gemalto_rpm_set_cb, cbd, NULL) == 0){
			CALLBACK_WITH_FAILURE(cb, cbd->data);
			g_free(cbd);
		}
	} else {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		g_free(cbd);
	}
}

static void gemalto_set_connpref_default_context(struct ofono_connpref *connpref,
                                                 guint16 cid)
{
	gchar* cid_str = g_strdup_printf("%u", cid);
	default_properties_set_value(OFONO_CONNPREF_INTERFACE,
	                             ACTIA_PRO_DEFAULT_CONTEXT,
	                             cid_str);
	g_free(cid_str);
}

static int gemalto_connpref_probe(struct ofono_connpref *connpref,
                                  unsigned int vendor,
                                  void *data)
{
	struct connpref_data *cp_data;
	GAtChat *chat = data;
	gchar* init_default_cid_str = NULL;
	guint64 init_default_cid = 0;

	DBG("");

	cp_data = g_try_new0(struct connpref_data, 1);
	if (cp_data == NULL)
		return -ENOMEM;

	cp_data->chat = g_at_chat_clone(chat);
	cp_data->vendor = vendor;

	/* Retrieve DefaultContext from file */
	init_default_cid_str = default_properties_get_value(OFONO_CONNPREF_INTERFACE,
	                                                    ACTIA_PRO_DEFAULT_CONTEXT,
	                                                    "0");

	init_default_cid = g_ascii_strtoull(init_default_cid_str, NULL, 10);
	if (init_default_cid <= G_MAXUINT16) {
		ofono_connpref_set_default_context(connpref, (guint16)init_default_cid);
	}

	ofono_connpref_set_data(connpref, cp_data);
	ofono_connpref_register(connpref);

	return 0;
}

static void gemalto_connpref_remove(struct ofono_connpref *connpref)
{
	struct connpref_data *cp_data = ofono_connpref_get_data(connpref);

	DBG("");

	ofono_connpref_set_data(connpref, NULL);
	g_at_chat_unref(cp_data->chat);
	g_free(cp_data);
}

static struct ofono_connpref_driver driver = {
	.name           = "gemaltomodem",
	.probe          = gemalto_connpref_probe,
	.remove         = gemalto_connpref_remove,
	.query_connpref_config = gemalto_query_connpref_config,
	.set_connpref_context_profile = gemalto_set_connpref_context_profile,
	.set_connpref_default_context = gemalto_set_connpref_default_context,
	.set_connpref_ims_autoconnect = gemalto_set_ims_autoconnect,
	.set_connpref_rpm             = gemalto_set_rpm,
};

void gemalto_connpref_init(void)
{
	ofono_connpref_driver_register(&driver);
}

void gemalto_connpref_exit(void)
{
	ofono_connpref_driver_unregister(&driver);
}
