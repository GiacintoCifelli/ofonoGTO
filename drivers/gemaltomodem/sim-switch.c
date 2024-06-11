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
};

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


static void gemalto_set_sim_dualmode_cb(gboolean success, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_sim_switch_set_active_card_slot_cb_t cb = cbd->cb;
	unsigned int index = GPOINTER_TO_UINT(cbd->user);
	struct sim_switch_data *smd = ofono_sim_switch_get_data(cbd->data);
	if (smd == NULL) {
		ofono_error("Could not get sim switch data");
		return;
	}

	if (success) {
		if (index == SIMCARD_INDEX){
			/* consider OK for simcard */
			CALLBACK_WITH_SUCCESS(cb, cbd->data);
		} else {
			/* set SIM/Cs for ext sim */
			g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/Cs\",\"3\"", scfg_prefix,
							gemalto_set_sim_selection_cb, cbd, NULL);
			return;
		}

	} else {
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	}
	g_free(cbd);
}

static void gemalto_dual_mode_read_cb(gboolean success, GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	const char *dualmode_val;
	struct cb_data *cbd = user_data;
	ofono_sim_switch_set_active_card_slot_cb_t cb = cbd->cb;
	unsigned int index = GPOINTER_TO_UINT(cbd->user);
	struct sim_switch_data *smd = ofono_sim_switch_get_data(cbd->data);
	if (smd == NULL) {
		ofono_error("Could not get sim switch data");
		return;
	}

	if (success) {
		g_at_result_iter_init(&iter, result);
		if (!g_at_result_iter_next(&iter, "^SCFG: \"SIM/DualMode\",")) {
			ofono_error("Invalid response when querying state of the sim dualmode");
			goto sim_switch_err;
		}

		if (!g_at_result_iter_next_string(&iter, &dualmode_val)) {
			ofono_error("Invalid response when querying state of the sim dualmode");
			goto sim_switch_err;
		}

		if ((index == EXTSIM_INDEX) && (strcmp(dualmode_val, "2") != 0)) {
			g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/DualMode\",\"2\"", scfg_prefix,
							gemalto_set_sim_dualmode_cb, cbd, NULL);
		} else if ((index == SIMCARD_INDEX) && (strcmp(dualmode_val, "0") != 0)) {
			g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/DualMode\",\"0\"", scfg_prefix,
							gemalto_set_sim_dualmode_cb, cbd, NULL);
		} else {
			/* Update not needed: it should not be possible because DualMode is checked at the init */
			ofono_warn("No need to set dualmode to '%d' because modem is already in this state",
						index ? 2 : 0);
			CALLBACK_WITH_SUCCESS(cb, cbd->data);
			g_free(cbd);
		}
	} else {
		goto sim_switch_err;
	}
	return;

sim_switch_err:
	CALLBACK_WITH_FAILURE(cb, cbd->data);
	g_free(cbd);
}

static void gemalto_set_dual_mode(unsigned int index,
                                  ofono_sim_switch_set_active_card_slot_cb_t cb,
                                  void *data)
{
	struct sim_switch_data *smd = ofono_sim_switch_get_data(data);
	struct cb_data *cbd = cb_data_new(cb, data);
	cbd->user = GUINT_TO_POINTER(index);

	g_at_chat_send(smd->chat, "AT^SCFG=\"SIM/DualMode\"", scfg_prefix,
					gemalto_dual_mode_read_cb, cbd, NULL);
}

static void gemalto_set_active_card_slot(struct ofono_sim_switch *sm, unsigned int index,
			ofono_sim_switch_set_active_card_slot_cb_t cb, void *data)
{
	/* Type has been checked before */
	struct sim_switch_data *smd = ofono_sim_switch_get_data(data);

	if (!smd->dualmode_supported) {
		CALLBACK_WITH_FAILURE(cb, data);
	} else {
		gemalto_set_dual_mode(index, cb, data);
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
			DBG("Initial sim type is external");
			ofono_sim_switch_set_active_card_slot(sm, EXTSIM_INDEX + 1);
		} else if (strcmp(dualmode_val, "0") == 0) {
			DBG("Initial sim type is simcard");
			ofono_sim_switch_set_active_card_slot(sm, SIMCARD_INDEX + 1);
		} else {
			ofono_error("Unknown response ['%s'] when querying state of the sim dualmode", dualmode_val);
			goto error;
		}
	} else {
		DBG("Error when retrieving DualMode, it seems to not be supported");
		goto error;
	}
	smd->dualmode_supported = TRUE;
	/* Set num slots */
	ofono_sim_switch_set_card_slot_count(sm, 2);

	ofono_sim_switch_register(sm);
	return;

error:
	/* dualmode_supported is already set to FALSE at probe */
	ofono_sim_switch_register(sm);
}

static int gemalto_sim_switch_probe(struct ofono_sim_switch *sm, unsigned int vendor, void *data)
{
	struct sim_switch_data *smd;
	GAtChat *chat = data;

	DBG("");

	smd = g_try_new0(struct sim_switch_data, 1);
	if (smd == NULL)
		return -ENOMEM;
	smd->chat = g_at_chat_clone(chat);
	smd->dualmode_supported = FALSE;

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
