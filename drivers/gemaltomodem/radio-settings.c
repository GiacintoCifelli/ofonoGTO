#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/radio-settings.h>

#include "gatchat.h"
#include "gatresult.h"

#include "gemaltomodem.h"
#include "drivers/atmodem/vendor.h"
#include "src/actia/vendor.h"

static const char *none_prefix[] = { NULL };
static const char *cops_prefix[] = { "+COPS:", NULL };

struct radio_settings_data {
	GAtChat *chat;
	unsigned int vendor;
};

struct radio_cb_data {
	struct radio_settings_data *rsd;
	struct cb_data *cbd;
};

static void cops_query_mode_cb(gboolean ok, GAtResult *result,
                               gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_query_cb_t cb = cbd->cb;
	enum ofono_radio_access_mode mode;
	struct ofono_error error;
	GAtResultIter iter;
	int modeCops, format, rat;
	const char *opName;

	DBG("");

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		cb(&error, -1, cbd->data);
		return;
	}

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+COPS:") == FALSE)
		goto error;

	if (g_at_result_iter_next_number(&iter, &modeCops) == FALSE)
		goto error;

	if (g_at_result_iter_next_number(&iter, &format) == FALSE)
		goto error;

	if (g_at_result_iter_next_string(&iter, &opName) == FALSE)
		goto error;

	if (g_at_result_iter_next_number(&iter, &rat) == FALSE)
		goto error;

	switch (rat) {
	case 0:
	case 3:
		mode = OFONO_RADIO_ACCESS_MODE_GSM;
		break;
	case 2:
	case 4:
	case 6:
		mode = OFONO_RADIO_ACCESS_MODE_UMTS;
		break;
	case 7:
		mode = OFONO_RADIO_ACCESS_MODE_LTE;
		break;
	default:
		CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
		return;
	}

	DBG("rat %d mode %d for %s", rat, mode, opName);

	cb(&error, mode, cbd->data);

	return;

error:
	CALLBACK_WITH_FAILURE(cb, -1, cbd->data);
}

static void gemalto_query_rat_mode(struct ofono_radio_settings *rs,
                                   ofono_radio_settings_rat_mode_query_cb_t cb,
                                   void *data)
{
	struct radio_settings_data *rsd = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd = cb_data_new(cb, data);
	DBG("");

	if (g_at_chat_send(rsd->chat, "AT+COPS?", cops_prefix,
						cops_query_mode_cb, cbd, g_free) == 0)
	{
		CALLBACK_WITH_FAILURE(cb, -1, data);
		g_free(cbd);
	}
}

static void rat_modify_mode_cb(gboolean ok, GAtResult *result,
                               gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_radio_settings_rat_mode_set_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));
	cb(&error, cbd->data);
}

//============================================================================//
// NAME : cops_get_and_set_mode_cb
//============================================================================//
// ROLE : First, check the result of AT+COPS?
//        Then, if the mode is 0 (automatic)
//         it will skip the command AT+COPS=0
//----------------------------------------------------------------------------//
static void cops_get_and_set_mode_cb(gboolean ok, GAtResult *result,
                                     gpointer user_data)
{
	struct radio_cb_data *rcbd = NULL; /* initialized only to avoid compiler warnings */
	ofono_radio_settings_rat_mode_set_cb_t cb = NULL; /* initialized only to avoid compiler warnings */
	struct ofono_error error;
	GAtResultIter iter;
	int modeCops;
	char buf[40];
	DBG("");
	if (user_data == NULL){
		DBG("error user_data==NULL");
		goto error;
	}
	rcbd = user_data;
	cb = rcbd->cbd->cb;
	decode_at_error(&error, g_at_result_final_response(result));
	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+COPS:") == FALSE)
		goto error;

	if (g_at_result_iter_next_number(&iter, &modeCops) == FALSE)
		goto error;

	DBG("modeCops %d ", modeCops);
	if (modeCops != 0){
		snprintf(buf, sizeof(buf), "AT+COPS=0");
		if (g_at_chat_send(rcbd->rsd->chat, buf, none_prefix,
							rat_modify_mode_cb, rcbd->cbd, g_free) <= 0)
		{
			goto error;
		}
	}
	return;
error:
	CALLBACK_WITH_FAILURE(cb, rcbd->cbd->data);
	g_free(rcbd);
}

static void gemalto_set_rat_mode_sxrat(struct radio_settings_data *rsd,
                                       enum ofono_radio_access_mode mode,
                                       struct cb_data *cbd)
{
	unsigned int value;
	char buf[1024];
	ofono_radio_settings_rat_mode_set_cb_t cb = cbd->cb;

	switch (mode) {
		case OFONO_RADIO_ACCESS_MODE_GSM:
			value = 0;
			break;
		case OFONO_RADIO_ACCESS_MODE_UMTS:
			value = 2;
			break;
		case OFONO_RADIO_ACCESS_MODE_LTE:
			value = 3;
			break;
		case OFONO_RADIO_ACCESS_MODE_ANY:
		default:
			value = 6;
	}
	snprintf(buf, sizeof(buf), "AT^SXRAT=%u", value);

	if (g_at_chat_send(rsd->chat, buf, none_prefix,
						rat_modify_mode_cb, cbd, g_free) > 0)
		return;

	CALLBACK_WITH_FAILURE(cb, cbd->data);
	g_free(cbd);
}

static void gemalto_set_rat_mode_cops(struct radio_settings_data *rsd,
                                      enum ofono_radio_access_mode mode,
                                      struct cb_data *cbd)
{
	int value = 2;
	char buf[40];
	ofono_radio_settings_rat_mode_set_cb_t cb = cbd->cb;
	struct radio_cb_data * rcbd=malloc(sizeof(struct radio_cb_data));
	if (rcbd == NULL){
		goto error;
	}
	rcbd->rsd = rsd;
	rcbd->cbd = cbd;
	DBG("");
	switch (mode) {
	case OFONO_RADIO_ACCESS_MODE_ANY:
		value = -1;
		break;
	case OFONO_RADIO_ACCESS_MODE_GSM:
		value = 0;
		break;
	case OFONO_RADIO_ACCESS_MODE_UMTS:
		value = 2;
		break;
	case OFONO_RADIO_ACCESS_MODE_LTE:
		if (rsd->vendor == OFONO_VENDOR_GEMALTO_CINT_PLS8_ALS3)
			value = 7;
		else
			goto error;
	}
	if (value == -1) {
		if (g_at_chat_send(rsd->chat, "AT+COPS?", cops_prefix,
							cops_get_and_set_mode_cb, rcbd, g_free) == 0)
		{
			goto error;
		}
	} else {
		snprintf(buf, sizeof(buf), "AT+COPS=0,0,,%u", value);
		if (g_at_chat_send(rsd->chat, buf, none_prefix,
							rat_modify_mode_cb, cbd, g_free) <= 0)
			goto error;
		g_free(rcbd);
	}
	return;

error:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	g_free(cbd);
}

static void gemalto_set_rat_mode(struct ofono_radio_settings *rs,
                                 enum ofono_radio_access_mode mode,
                                 ofono_radio_settings_rat_mode_set_cb_t cb,
                                 void *data)
{
	struct radio_settings_data *rsd = ofono_radio_settings_get_data(rs);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = GUINT_TO_POINTER(rsd->vendor);

	DBG("");

	if (rsd->vendor == OFONO_VENDOR_GEMALTO_CINT_PLS62) {
		gemalto_set_rat_mode_sxrat(rsd, mode, cbd);
	} else {
		gemalto_set_rat_mode_cops(rsd, mode, cbd);
	}
}

static gboolean gemalto_radio_settings_register(gpointer user)
{
	struct ofono_radio_settings *rs = user;

	ofono_radio_settings_register(rs);

	return FALSE;
}

static int gemalto_radio_settings_probe(struct ofono_radio_settings *rs,
					unsigned int vendor, void *data)
{
	GAtChat *chat = data;
	struct radio_settings_data *rsd;

	DBG("");

	rsd = g_try_new0(struct radio_settings_data, 1);
	if (rsd == NULL)
		return -ENOMEM;

	rsd->chat = g_at_chat_clone(chat);
	rsd->vendor = vendor;

	ofono_radio_settings_set_data(rs, rsd);

	/*don't check for AT+COPS? suppport ==> could return an error in some rare cases */
	g_idle_add(gemalto_radio_settings_register, rs);

	return 0;
}

static void gemalto_radio_settings_remove(struct ofono_radio_settings *rs)
{
	struct radio_settings_data *rsd = ofono_radio_settings_get_data(rs);

	ofono_radio_settings_set_data(rs, NULL);

	g_at_chat_unref(rsd->chat);
	g_free(rsd);
}

static struct ofono_radio_settings_driver driver = {
	.name           = "gemaltomodem",
	.probe          = gemalto_radio_settings_probe,
	.remove         = gemalto_radio_settings_remove,
	.query_rat_mode = gemalto_query_rat_mode,
	.set_rat_mode   = gemalto_set_rat_mode,
};

void gemalto_radio_settings_init(void)
{
	ofono_radio_settings_driver_register(&driver);
}

void gemalto_radio_settings_exit(void)
{
	ofono_radio_settings_driver_unregister(&driver);
}
