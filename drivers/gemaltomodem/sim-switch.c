#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <glib.h>
#include <stdint.h>
#include <ofono/log.h>
#include <ofono/dbus.h>
#include <gdbus.h>

#include "actia/sim-switch.h"

#include "gatchat.h"
#include "gatresult.h"
#include "gemaltomodem.h"
#include <drivers/atmodem/vendor.h>

static const char *scfg_prefix[] = { "^SCFG", NULL };

#define SIMCARD_INDEX 0
#define EXTSIM_INDEX  1

struct sim_switch_data {
	GAtChat *chat;
	gboolean dualmode_supported;
	gboolean use_sim_text_for_cs; /* if TRUE use text instead of SIM index */
};

/* CS value is different. For some modems it's SIM card index (0..3)
 * for others it is a text "SIM1".."SIM3"
 * if 'use_sim_text_for_cs' is TRUE, return text, otherwise SIM index
 */
static const char* gemalto_get_cs_value(unsigned int index, struct sim_switch_data *smd)
{
	if (index == SIMCARD_INDEX) {
		if (smd->use_sim_text_for_cs) {
			return "SIM1";
		} else {
			return "0";
		}
	} else {
		if (smd->use_sim_text_for_cs) {
			return "SIM3";
		} else {
			return "3";
		}
	}
}

static void gemalto_set_sim_selection_cb(gboolean success, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sim_switch_set_active_card_slot_cb_t cb = cbd->cb;

	if (success) {
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	} else {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	}
	g_free(cbd);
}

static void gemalto_set_active_card_slot(struct ofono_sim_switch *sm, unsigned int index,
			ofono_sim_switch_set_active_card_slot_cb_t cb, void *data)
{
	/* Type has been checked before */
	struct sim_switch_data *smd = ofono_sim_switch_get_data(data);
	if (smd == NULL) {
		ofono_error("Could not get sim switch data");
		return;
	}
	struct cb_data *cbd = NULL;
	gchar* cmd = NULL;

	if (!smd->dualmode_supported) {
		CALLBACK_WITH_FAILURE(cb, data);
	} else  {
		cbd = cb_data_new(cb, data);
		/* DualMode should be equal to 2 because it is set during probe */
		cmd = g_strdup_printf("AT^SCFG=\"SIM/Cs\",\"%s\"", gemalto_get_cs_value(index, smd));
		g_at_chat_send(smd->chat, cmd, scfg_prefix,
	                  gemalto_set_sim_selection_cb, cbd, NULL);
		g_free(cmd);
	}
}

static void gemalto_sim_cs_read_init_cb(gboolean success, GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *cs_val;
	struct ofono_sim_switch *sm = user_data;
	struct sim_switch_data *smd = ofono_sim_switch_get_data(sm);
	if (smd == NULL) {
		ofono_error("Could not get sim switch data");
		return;
	}
	const char* expected_prefix = (smd->use_sim_text_for_cs) ?
	                              "^SCFG: \"SIM/CS\"," : "^SCFG: \"SIM/Cs\",";

	if (success) {
		g_at_result_iter_init(&iter, result);
		if (!g_at_result_iter_next(&iter, expected_prefix)) {
			ofono_error("Invalid response when querying state of the sim cs");
			goto error;
		}

		if (!g_at_result_iter_next_string(&iter, &cs_val)) {
			ofono_error("Invalid response when querying state of the sim cs");
			goto error;
		}
		if (strcmp(cs_val, gemalto_get_cs_value(EXTSIM_INDEX, smd)) == 0) {
			DBG("Initial sim type is external");
			ofono_sim_switch_set_active_card_slot(sm, EXTSIM_INDEX + 1);
		} else if (strcmp(cs_val, gemalto_get_cs_value(SIMCARD_INDEX, smd)) == 0) {
			DBG("Initial sim type is simcard");
			ofono_sim_switch_set_active_card_slot(sm, SIMCARD_INDEX + 1);
		} else {
			ofono_error("Unknown response ['%s'] when querying state of the sim cs", cs_val);
			goto error;
		}
	} else {
		ofono_error("Error when retrieving SIM/Cs");
		goto error;
	}

	smd->dualmode_supported = TRUE;
	/* Set num slots */
	ofono_sim_switch_set_card_slot_count(sm, 2);

error:
	ofono_sim_switch_register(sm);
}

static void gemalto_set_sim_dualmode_init_cb(gboolean success, GAtResult *result, gpointer user_data)
{
	struct ofono_sim_switch *sm = user_data;
	struct sim_switch_data *smd = ofono_sim_switch_get_data(sm);

	if (success) {
		/* Check Cs value*/
		g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/Cs\"", scfg_prefix,
		               gemalto_sim_cs_read_init_cb, sm, NULL);
	} else {
		ofono_error("Error when setting DualMode to 2");
		ofono_sim_switch_register(sm);
	}
}

static void gemalto_dual_mode_read_init_cb(gboolean success, GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *dualmode_val;
	struct ofono_sim_switch *sm = user_data;
	struct sim_switch_data *smd = ofono_sim_switch_get_data(sm);
	if (smd == NULL) {
		ofono_error("Could not get sim switch data");
		return;
	}

	if (success) {
		g_at_result_iter_init(&iter, result);
		if (!g_at_result_iter_next(&iter, "^SCFG: \"SIM/DualMode\",")) {
			ofono_error("Invalid response when querying state of the sim dualmode");
			goto error;
		}

		if (!g_at_result_iter_next_string(&iter, &dualmode_val)) {
			ofono_error("Invalid response when querying state of the sim dualmode");
			goto error;
		}
		if (strcmp(dualmode_val, "2") == 0) {
			/* DualMode already equal to 2, check Cs value*/
			g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/Cs\"", scfg_prefix,
			               gemalto_sim_cs_read_init_cb, sm, NULL);
		} else {
			/* Set DualMode to 2 before checking Cs value */
			g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/DualMode\",\"2\"", scfg_prefix,
			               gemalto_set_sim_dualmode_init_cb, sm, NULL);
		}
		return;
	} else {
		DBG("Error when retrieving DualMode, it seems to not be supported");
	}

error:
	/* dualmode_supported is already set to FALSE at probe */
	ofono_sim_switch_register(sm);
}

static int gemalto_sim_switch_probe(struct ofono_sim_switch *sm, unsigned int vendor,
                                    void *data)
{
	struct sim_switch_data *smd;
	GAtChat *chat = data;

	DBG("");

	smd = g_try_new0(struct sim_switch_data, 1);
	if (smd == NULL)
		return -ENOMEM;
	smd->chat = g_at_chat_clone(chat);
	smd->dualmode_supported = FALSE;

	/* PLS83 has different SIM CS command, so let's check this out */
	if(vendor == OFONO_VENDOR_GEMALTO_PLS63_PLS83) {
		DBG("Enabling Gemalto PLS83 SIM CS workaround");
		smd->use_sim_text_for_cs = TRUE;
	}

	ofono_sim_switch_set_data(sm, smd);

	/* Read Initial Dual Mode */
	g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/DualMode\"", scfg_prefix,
	               gemalto_dual_mode_read_init_cb, sm, NULL);

	return 0;
}

static void gemalto_sim_switch_remove(struct ofono_sim_switch *sm)
{
	struct sim_switch_data *smd = ofono_sim_switch_get_data(sm);
	ofono_sim_switch_set_data(sm, NULL);
	g_free(smd);
}

static struct ofono_sim_switch_driver driver = {
	.name                 = "gemaltomodem",
	.probe                = gemalto_sim_switch_probe,
	.remove               = gemalto_sim_switch_remove,
	.set_active_card_slot = gemalto_set_active_card_slot
};

void gemalto_sim_switch_init(void)
{
	ofono_sim_switch_driver_register(&driver);
}

void gemalto_sim_switch_exit(void)
{
	ofono_sim_switch_driver_unregister(&driver);
}
