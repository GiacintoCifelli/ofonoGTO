/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010  ST-Ericsson AB.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <glib.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs.h>
#include <common.h>

#include "gatchat.h"
#include "gatresult.h"

#include "atmodem.h"
#include "vendor.h"

static const char *cgreg_prefix[] = { "+CGREG:", NULL };
static const char *cereg_prefix[] = { "+CEREG:", NULL };
static const char *c5greg_prefix[] = { "+C5GREG:", NULL };
static const char *cgdcont_prefix[] = { "+CGDCONT:", NULL };
static const char *none_prefix[] = { NULL };

struct gprs_data {
	GAtChat *chat;
	unsigned int vendor;
	unsigned int last_auto_context_id;
	gboolean telit_try_reattach;
	gboolean has_cgreg;
	gboolean has_cereg;
	gboolean has_c5greg;
	gboolean nb_inds;
	gboolean auto_attach; /* for LTE modems & co */
	int attached;
	int cgreg_status;
	int cereg_status;
	int c5greg_status;
};

struct netreg_info {
	struct ofono_gprs *gprs;
	struct gprs_data *gd;
	const char *ind;
	int status;
	int bearer;
};

static void at_cgatt_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_cb_t cb = cbd->cb;
	struct ofono_error error;

	decode_at_error(&error, g_at_result_final_response(result));

	cb(&error, cbd->data);
}

static void at_gprs_set_attached(struct ofono_gprs *gprs, int attached,
					ofono_gprs_cb_t cb, void *data)
{
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	struct cb_data *cbd;
	char buf[64];

	if (gd->auto_attach) {
		CALLBACK_WITH_SUCCESS(cb, data);
		return;
	}

	cbd = cb_data_new(cb, data);
	snprintf(buf, sizeof(buf), "AT+CGATT=%i", attached ? 1 : 0);

	if (g_at_chat_send(gd->chat, buf, none_prefix,
				at_cgatt_cb, cbd, g_free) > 0) {
		gd->attached = attached;
		return;
	}

	g_free(cbd);

	CALLBACK_WITH_FAILURE(cb, data);
}

static void at_cgreg_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_status_cb_t cb = cbd->cb;
	struct ofono_error error;
	int status;
	struct gprs_data *gd = cbd->user;
	gboolean last = !(gd->has_cereg || gd->has_c5greg);

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		status = -1;
		goto end;
	}

	if (at_util_parse_reg(result, "+CGREG:", NULL, &status,
				NULL, NULL, NULL, gd->vendor) == FALSE) {
		error.type = OFONO_ERROR_TYPE_FAILURE;
		error.error = 0;
		status = -1;
		goto end;
	}

end:
	gd->cgreg_status = status;

	if (last)
		cb(&error, status, cbd->data);
}

static void at_cereg_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_status_cb_t cb = cbd->cb;
	struct ofono_error error;
	int status;
	struct gprs_data *gd = cbd->user;
	gboolean last = !gd->has_c5greg;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		status = -1;
		goto end;
	}

	if (at_util_parse_reg(result, "+CEREG:", NULL, &status,
				NULL, NULL, NULL, gd->vendor) == FALSE) {
		error.type = OFONO_ERROR_TYPE_FAILURE;
		error.error = 0;
		status = -1;
		goto end;
	}

end:
	gd->cereg_status = status;

	if (last) {

		if (/*gd->cgreg_status == NETWORK_REGISTRATION_STATUS_DENIED ||*/
			gd->cgreg_status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
			gd->cgreg_status == NETWORK_REGISTRATION_STATUS_ROAMING)
			cb(&error, gd->cgreg_status, cbd->data);
		else
			cb(&error, status, cbd->data);
	}
}

static void at_c5greg_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_status_cb_t cb = cbd->cb;
	struct ofono_error error;
	int status;
	struct gprs_data *gd = cbd->user;

	decode_at_error(&error, g_at_result_final_response(result));

	if (!ok) {
		status = -1;
		goto end;
	}

	if (at_util_parse_reg(result, "+C5GREG:", NULL, &status,
				NULL, NULL, NULL, gd->vendor) == FALSE) {
		error.type = OFONO_ERROR_TYPE_FAILURE;
		error.error = 0;
		status = -1;
		goto end;
	}

end:
	gd->c5greg_status = status;

	if (/*gd->cgreg_status == NETWORK_REGISTRATION_STATUS_DENIED ||*/
			gd->cgreg_status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
			gd->cgreg_status == NETWORK_REGISTRATION_STATUS_ROAMING)
		cb(&error, gd->cgreg_status, cbd->data);
	else if (/*gd->cereg_status == NETWORK_REGISTRATION_STATUS_DENIED ||*/
			gd->cereg_status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
			gd->cereg_status == NETWORK_REGISTRATION_STATUS_ROAMING)
		cb(&error, gd->cereg_status, cbd->data);
	else
		cb(&error, status, cbd->data);
}

static void at_gprs_registration_status(struct ofono_gprs *gprs,
					ofono_gprs_status_cb_t cb,
					void *data)
{
	struct gprs_data *gd = ofono_gprs_get_data(gprs);

	switch (gd->vendor) {
	case OFONO_VENDOR_GOBI:
		/*
		 * Send *CNTI=0 to find out the current tech, it will be
		 * intercepted in gobi_cnti_notify in network registration
		 */
		g_at_chat_send(gd->chat, "AT*CNTI=0", none_prefix,
				NULL, NULL, NULL);
		break;
	case OFONO_VENDOR_NOVATEL:
		/*
		 * Send $CNTI=0 to find out the current tech, it will be
		 * intercepted in nw_cnti_notify in network registration
		 */
		g_at_chat_send(gd->chat, "AT$CNTI=0", none_prefix,
				NULL, NULL, NULL);
		break;
	}

	/*
	 * this is long: send all indicators, compare at the end if one reports
	 * attached and use it, otherwise report status for last indicator
	 * tested (higher technology).
	 * Note: AT+CGATT? is not good because doesn't tell us if we are roaming
	 */
	if (gd->has_cgreg) {
		struct cb_data *cbd = cb_data_new(cb, data);
		cbd->user = gd;
		gd->cgreg_status = -1; /* preset in case of fail of the at send */

		/* g_at_chat_send fails only if g_new_try fails, so we stop */
		if (g_at_chat_send(gd->chat, "AT+CGREG?", cgreg_prefix,
					at_cgreg_cb, cbd, g_free) == 0) {
			g_free(cbd);
			CALLBACK_WITH_FAILURE(cb, -1, data);
			return;
		}
	}

	if (gd->has_cereg) {
		struct cb_data *cbd = cb_data_new(cb, data);
		cbd->user = gd;
		gd->cereg_status = -1;

		if (g_at_chat_send(gd->chat, "AT+CEREG?", cereg_prefix,
					at_cereg_cb, cbd, g_free) == 0) {
			g_free(cbd);
			CALLBACK_WITH_FAILURE(cb, -1, data);
			return;
		}
	}

	if (gd->has_c5greg) {
		struct cb_data *cbd = cb_data_new(cb, data);
		cbd->user = gd;
		gd->c5greg_status = -1;

		if (g_at_chat_send(gd->chat, "AT+C5GREG?", c5greg_prefix,
					at_c5greg_cb, cbd, g_free) == 0) {
			g_free(cbd);
			CALLBACK_WITH_FAILURE(cb, -1, data);
			return;
		}
	}
}

static void at_cgdcont_read_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	int activated_cid = gd->last_auto_context_id;
	const char *apn = NULL;
	GAtResultIter iter;

	DBG("ok %d", ok);

	if (!ok) {
		ofono_warn("Can't read CGDCONT contexts.");
		return;
	}

	g_at_result_iter_init(&iter, result);

	while (g_at_result_iter_next(&iter, "+CGDCONT:")) {
		int read_cid;

		if (!g_at_result_iter_next_number(&iter, &read_cid))
			break;

		if (read_cid != activated_cid)
			continue;

		/* ignore protocol */
		g_at_result_iter_skip_next(&iter);

		g_at_result_iter_next_string(&iter, &apn);

		break;
	}

	if (apn)
		ofono_gprs_cid_activated(gprs, activated_cid, apn);
	else
		ofono_warn("cid %u: Received activated but no apn present",
				activated_cid);
}

static int cops_cb(gboolean ok, GAtResult *result)
{
	GAtResultIter iter;
	int format, tech = -1;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+COPS:"))
		goto error;

	g_at_result_iter_skip_next(&iter); /* mode: automatic, manual, ... */

	if (!g_at_result_iter_next_number(&iter, &format))
		goto error;

	g_at_result_iter_skip_next(&iter); /* operator name or code */

	if (!g_at_result_iter_next_number(&iter, &tech))
		tech = -1; /* make sure it has not been set to something */
error:
	return tech;
}


static void netreg_notify_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct netreg_info *nri = user_data;
	int cops_tech = cops_cb(ok, result);

	if (cops_tech == -1) { /* take the indicator status */
		ofono_gprs_status_notify(nri->gprs, nri->status);
		return;
	}

	/*
	 * values taken from the 3GPP 27.007 rel.15
	 * matching enum access_technology in common.h up to 7.
	 */
	if (g_str_equal(nri->ind,"CGREG") && (cops_tech < 7 || cops_tech == 8))
		ofono_gprs_status_notify(nri->gprs, nri->status);
	else if (g_str_equal(nri->ind,"CEREG") && (cops_tech == 7 ||
					cops_tech == 9 || cops_tech == 12))
		ofono_gprs_status_notify(nri->gprs, nri->status);
	else if (g_str_equal(nri->ind,"C5GREG") && (cops_tech == 10 ||
					cops_tech == 11 || cops_tech == 13))
		ofono_gprs_status_notify(nri->gprs, nri->status);
	/* all other cases ignored: indicator not for current AcT */
}

static void netreg_notify(struct ofono_gprs *gprs, const char* ind, int status,
								int bearer)
{
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	struct netreg_info *nri;

	if (status == NETWORK_REGISTRATION_STATUS_DENIED ||
			status == NETWORK_REGISTRATION_STATUS_REGISTERED ||
			status == NETWORK_REGISTRATION_STATUS_ROAMING ||
			gd->nb_inds == 1) {
		/* accept this status and process */
		ofono_gprs_status_notify(gprs, status);

		if (bearer != -1)
			ofono_gprs_bearer_notify(gprs, bearer);

		return;
	}

	/*
	 * in this case nb_inds>1 && status not listed above
	 * we check AT+COPS? for a second opinion.
	 */

	nri = g_new0(struct netreg_info, 1);
	nri->gprs = gprs;
	nri->gd = gd;
	nri->ind = ind;
	nri->status = status;
	nri->bearer = bearer;
	g_at_chat_send(gd->chat, "AT+COPS?", none_prefix, netreg_notify_cb,
		nri, g_free);
}

static void cgreg_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	int status, bearer;

	if (at_util_parse_reg_unsolicited(result, "+CGREG:", &status,
				NULL, NULL, &bearer, gd->vendor) == FALSE)
		return;

	/*
	 * Telit AT modem firmware (tested with UE910-EUR) generates
	 * +CGREG: 0\r\n\r\n+CGEV: NW DETACH
	 * after a context is de-activated and ppp connection closed.
	 * Then, after a random amount of time (observed from a few seconds
	 * to a few hours), an unsolicited +CGREG: 1 arrives.
	 * Attempt to fix the problem, by sending AT+CGATT=1 once.
	 * This does not re-activate the context, but if a network connection
	 * is still correct, will generate an immediate +CGREG: 1.
	 */
	if (gd->vendor == OFONO_VENDOR_TELIT) {
		if (gd->attached && !status && !gd->telit_try_reattach) {
			DBG("Trying to re-attach gprs network");
			gd->telit_try_reattach = TRUE;
			g_at_chat_send(gd->chat, "AT+CGATT=1", none_prefix,
					NULL, NULL, NULL);
			return;
		}

		gd->telit_try_reattach = FALSE;
	}

	netreg_notify(gprs, "CGREG", status, bearer);
}

static void cereg_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	int status, bearer;

	if (at_util_parse_reg_unsolicited(result, "+CEREG:", &status,
				NULL, NULL, &bearer, gd->vendor) == FALSE)
		return;

	netreg_notify(gprs, "CEREG", status, bearer);
}

static void c5greg_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	int status, bearer;

	if (at_util_parse_reg_unsolicited(result, "+C5GREG:", &status,
				NULL, NULL, &bearer, gd->vendor) == FALSE)
		return;

	netreg_notify(gprs, "C5GREG", status, bearer);
}

static void cgev_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	GAtResultIter iter;
	const char *event;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CGEV:"))
		return;

	if (!g_at_result_iter_next_unquoted_string(&iter, &event))
		return;

	if (g_str_equal(event, "NW DETACH") ||
			g_str_equal(event, "ME DETACH")) {
		if (gd->vendor == OFONO_VENDOR_TELIT &&
				gd->telit_try_reattach)
			return;

		gd->attached = FALSE;
		ofono_gprs_detached_notify(gprs);
		return;
	} else if (g_str_has_prefix(event, "ME PDN ACT")) {
		sscanf(event, "%*s %*s %*s %u", &gd->last_auto_context_id);

		g_at_chat_send(gd->chat, "AT+CGDCONT?", cgdcont_prefix,
				at_cgdcont_read_cb, gprs, NULL);
	}
}

static void xdatastat_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	int stat;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+XDATASTAT:"))
		return;

	if (!g_at_result_iter_next_number(&iter, &stat))

	DBG("stat %d", stat);

	switch (stat) {
	case 0:
		ofono_gprs_suspend_notify(gprs, GPRS_SUSPENDED_UNKNOWN_CAUSE);
		break;
	case 1:
		ofono_gprs_resume_notify(gprs);
		break;
	}
}

static void huawei_mode_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	int mode, submode;
	gint bearer;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "^MODE:"))
		return;

	if (!g_at_result_iter_next_number(&iter, &mode))
		return;

	if (!g_at_result_iter_next_number(&iter, &submode))
		return;

	switch (submode) {
	case 1:
	case 2:
		bearer = 1;	/* GPRS */
		break;
	case 3:
		bearer = 2;	/* EDGE */
		break;
	case 4:
		bearer = 3;	/* UMTS */
		break;
	case 5:
		bearer = 5;	/* HSDPA */
		break;
	case 6:
		bearer = 4;	/* HSUPA */
		break;
	case 7:
	case 9:
		bearer = 6;	/* HSUPA + HSDPA */
		break;
	default:
		bearer = 0;
		break;
	}

	ofono_gprs_bearer_notify(gprs, bearer);
}

static void huawei_hcsq_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	const char *mode;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "^HCSQ:"))
		return;

	if (!g_at_result_iter_next_string(&iter, &mode))
		return;

	if (!strcmp("LTE", mode))
		ofono_gprs_bearer_notify(gprs, 7); /* LTE */

	/* in other modes, notification ^MODE is used */
}

static void telit_mode_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	gint nt, bearer;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "#PSNT:"))
		return;

	if (!g_at_result_iter_next_number(&iter,&nt))
		return;

	switch (nt) {
	case 0:
		bearer = 1;    /* GPRS */
		break;
	case 1:
		bearer = 2;    /* EDGE */
		break;
	case 2:
		bearer = 3;    /* UMTS */
		break;
	case 3:
		bearer = 5;    /* HSDPA */
		break;
	case 4:
		bearer = 7;    /* LTE */
		break;
	default:
		bearer = 0;
		break;
	}

	ofono_gprs_bearer_notify(gprs, bearer);
}

static void ublox_ureg_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	gint state, bearer;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+UREG:"))
		return;

	if (!g_at_result_iter_next_number(&iter, &state))
		return;

	switch (state) {
	case 4:
		bearer = 5;
		break;
	case 5:
		bearer = 4;
		break;
	case 8:
		bearer = 1;
		break;
	case 9:
		bearer = 2;
		break;
	default:
		bearer = state;
	}

	ofono_gprs_bearer_notify(gprs, bearer);
}

static void gemalto_ciev_ceer_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	const char *report;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CIEV: ceer,"))
		return;
	/*
	 * No need to check release cause group
	 * as we only subscribe to no. 5
	 */
	if (!g_at_result_iter_skip_next(&iter))
		return;
	if (!g_at_result_iter_next_string(&iter, &report))
		return;

	/* TODO: Handle more of these? */

	if (g_str_equal(report, "Regular deactivation")) {
		ofono_gprs_detached_notify(gprs);
		return;
	}
}

static void gemalto_ciev_bearer_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	int bearer;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CIEV: psinfo,"))
		return;
	if (!g_at_result_iter_next_number(&iter, &bearer))
		return;

	/* Go from Gemalto representation to oFono representation */
	switch (bearer) {
	case 0: /* GPRS/EGPRS not available */
		/* Same as "no bearer"? */
		bearer = 0;
		break;
	case 1: /* GPRS available, ignore this one */
		return;
	case 2: /* GPRS attached */
		bearer = 1;
		break;
	case 3: /* EGPRS available, ignore this one */
		return;
	case 4: /* EGPRS attached */
		bearer = 2;
		break;
	case 5: /* UMTS available, ignore this one */
		return;
	case 6: /* UMTS attached */
		bearer = 3;
		break;
	case 7: /* HSDPA available, ignore this one */
		return;
	case 8: /* HSDPA attached */
		bearer = 5;
		break;
	case 9: /* HSDPA/HSUPA available, ignore this one */
		return;
	case 10: /* HSDPA/HSUPA attached */
		bearer = 6;
		break;
	/* TODO: Limit these cases to ALS3? */
	case 16: /* E-UTRA available, ignore this one */
		return;
	case 17: /* E-UTRA attached */
		bearer = 7;
		break;
	default: /* Assume that non-parsable values mean "no bearer" */
		bearer = 0;
		break;
	}

	ofono_gprs_bearer_notify(gprs, bearer);
}

static void cpsb_notify(GAtResult *result, gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	gint bearer;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+CPSB:"))
		return;

	if (!g_at_result_iter_next_number(&iter, NULL))
		return;

	if (!g_at_result_iter_next_number(&iter, &bearer))
		return;

	ofono_gprs_bearer_notify(gprs, bearer);
}

static void gprs_initialized(struct ofono_gprs *gprs)
{
	struct gprs_data *gd = ofono_gprs_get_data(gprs);

	switch (gd->vendor) {
	case OFONO_VENDOR_GEMALTO:
		break;
	default:
		g_at_chat_send(gd->chat, "AT+CGAUTO=0", none_prefix, NULL, NULL,
									NULL);
	}

	switch (gd->vendor) {
	case OFONO_VENDOR_MBM:
		/* Ericsson MBM and ST-E modems don't support AT+CGEREP=2,1 */
		g_at_chat_send(gd->chat, "AT+CGEREP=1,0", none_prefix,
			NULL, NULL, NULL);
		break;
	case OFONO_VENDOR_NOKIA:
		/* Nokia data cards don't support AT+CGEREP=1,0 either */
		g_at_chat_send(gd->chat, "AT+CGEREP=1", none_prefix,
			NULL, NULL, NULL);
		break;
	case OFONO_VENDOR_GEMALTO:
		g_at_chat_send(gd->chat, "AT+CGEREP=2", NULL,
					NULL, NULL, NULL);
		g_at_chat_send(gd->chat, "AT^SIND=\"psinfo\",1", none_prefix,
			NULL, NULL, NULL);
		break;
	default:
		g_at_chat_send(gd->chat, "AT+CGEREP=2,1", none_prefix,
			NULL, NULL, NULL);
		break;
	}

	g_at_chat_register(gd->chat, "+CGEV:", cgev_notify, FALSE, gprs, NULL);
	g_at_chat_register(gd->chat, "+CGREG:", cgreg_notify, FALSE, gprs,
									NULL);
	g_at_chat_register(gd->chat, "+CEREG:", cereg_notify, FALSE, gprs,
									NULL);
	g_at_chat_register(gd->chat, "+C5GREG:", c5greg_notify, FALSE, gprs,
									NULL);

	switch (gd->vendor) {
	case OFONO_VENDOR_HUAWEI:
		g_at_chat_register(gd->chat, "^MODE:", huawei_mode_notify,
						FALSE, gprs, NULL);
		g_at_chat_register(gd->chat, "^HCSQ:", huawei_hcsq_notify,
						FALSE, gprs, NULL);
		break;
	case OFONO_VENDOR_UBLOX:
	case OFONO_VENDOR_UBLOX_TOBY_L2:
		g_at_chat_register(gd->chat, "+UREG:", ublox_ureg_notify,
						FALSE, gprs, NULL);
		g_at_chat_send(gd->chat, "AT+UREG=1", none_prefix,
						NULL, NULL, NULL);
		break;
	case OFONO_VENDOR_TELIT:
		g_at_chat_register(gd->chat, "#PSNT:", telit_mode_notify,
						FALSE, gprs, NULL);
		g_at_chat_send(gd->chat, "AT#PSNT=1", none_prefix,
						NULL, NULL, NULL);
		break;
	case OFONO_VENDOR_GEMALTO:
		g_at_chat_register(gd->chat, "+CIEV: psinfo,",
			gemalto_ciev_bearer_notify, FALSE, gprs, NULL);
		g_at_chat_register(gd->chat, "+CIEV: ceer,",
			gemalto_ciev_ceer_notify, FALSE, gprs, NULL);
		break;
	default:
		g_at_chat_register(gd->chat, "+CPSB:", cpsb_notify,
						FALSE, gprs, NULL);
		g_at_chat_send(gd->chat, "AT+CPSB=1", none_prefix,
						NULL, NULL, NULL);
		break;
	}

	switch (gd->vendor) {
	case OFONO_VENDOR_IFX:
		/* Register for GPRS suspend notifications */
		g_at_chat_register(gd->chat, "+XDATASTAT:", xdatastat_notify,
						FALSE, gprs, NULL);
		g_at_chat_send(gd->chat, "AT+XDATASTAT=1", none_prefix,
						NULL, NULL, NULL);
		break;
	}

	ofono_gprs_register(gprs);
}

static void set_indreg(struct gprs_data *gd, const char *ind, gboolean present)
{
	if (g_str_equal(ind,"CGREG"))
		gd->has_cgreg = present;

	if (g_str_equal(ind,"CEREG"))
		gd->has_cereg = present;

	if (g_str_equal(ind,"C5GREG"))
		gd->has_c5greg = present;

}

static void at_indreg_test_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct cb_data *cbd = user_data;
	struct ofono_gprs *gprs = cbd->cb;
	const char *ind=cbd->data;
	const char *last=cbd->user;

	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	gint range[2];
	GAtResultIter iter;
	int cgreg1 = 0;
	int cgreg2 = 0;
	char buf[32];

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

retry:
	sprintf(buf,"+%s:",ind);
	if (!g_at_result_iter_next(&iter, buf))
		goto error;

	if (!g_at_result_iter_open_list(&iter))
		goto retry;

	while (g_at_result_iter_next_range(&iter, &range[0], &range[1])) {
		if (1 >= range[0] && 1 <= range[1])
			cgreg1 = 1;
		if (2 >= range[0] && 2 <= range[1])
			cgreg2 = 1;
	}

	g_at_result_iter_close_list(&iter);

	if (gd->vendor == OFONO_VENDOR_GEMALTO) {
		/*
		 * Gemalto prefers to print as much information as available
		 * for support purposes
		 */
		sprintf(buf, "AT+%s=%d",ind, range[1]);
	} else if (cgreg1) {
		sprintf(buf,"AT+%s=1", ind);
	} else if (cgreg2) {
		sprintf(buf,"AT+%s=2", ind);
	} else
		goto error;

	set_indreg(gd, ind,TRUE);
	g_at_chat_send(gd->chat, buf, none_prefix, NULL, NULL, NULL);

	if (last)
		goto endcheck;
	return;

error:
	set_indreg(gd, ind,FALSE);
	if (!last)
		return;

endcheck:
	if (gd->has_cgreg)
		gd->nb_inds++;
	if (gd->has_cereg)
		gd->nb_inds++;
	if (gd->has_c5greg)
		gd->nb_inds++;

	if (gd->nb_inds == 0) {
		ofono_info("GPRS not supported on this device");
		ofono_gprs_remove(gprs);
		return;
	}

	gprs_initialized(gprs);
}

static void test_and_set_regstatus(struct ofono_gprs *gprs) {
	struct gprs_data *gd = ofono_gprs_get_data(gprs);
	struct cb_data *cbd_cg  = cb_data_new(gprs, "CGREG");
	struct cb_data *cbd_ce  = cb_data_new(gprs, "CEREG");
	struct cb_data *cbd_c5g = cb_data_new(gprs, "C5GREG");

	cbd_c5g->user="last";

	/*
	 * modules can support one to all of the network registration indicators
	 *
	 * ofono will execute the next commands and related callbacks in order
	 * therefore it is possible to verify all result on the last one.
	 */

	g_at_chat_send(gd->chat, "AT+CGREG=?", cgreg_prefix,
					at_indreg_test_cb, cbd_cg, g_free);
	g_at_chat_send(gd->chat, "AT+CEREG=?", cereg_prefix,
					at_indreg_test_cb, cbd_ce, g_free);
	g_at_chat_send(gd->chat, "AT+C5GREG=?", c5greg_prefix,
					at_indreg_test_cb, cbd_c5g, g_free);
}

static void at_cgdcont_test_cb(gboolean ok, GAtResult *result,
				gpointer user_data)
{
	struct ofono_gprs *gprs = user_data;
	GAtResultIter iter;
	int min, max;
	const char *pdp_type;
	gboolean found = FALSE;

	if (!ok)
		goto error;

	g_at_result_iter_init(&iter, result);

	while (!found && g_at_result_iter_next(&iter, "+CGDCONT:")) {
		gboolean in_list = FALSE;

		if (!g_at_result_iter_open_list(&iter))
			continue;

		if (g_at_result_iter_next_range(&iter, &min, &max) == FALSE)
			continue;

		if (!g_at_result_iter_skip_next(&iter))
			continue;

		if (g_at_result_iter_open_list(&iter))
			in_list = TRUE;

		if (!g_at_result_iter_next_string(&iter, &pdp_type))
			continue;

		if (in_list && !g_at_result_iter_close_list(&iter))
			continue;

		/* We look for IP PDPs */
		if (g_str_equal(pdp_type, "IP"))
			found = TRUE;
	}

	if (found == FALSE)
		goto error;

	ofono_gprs_set_cid_range(gprs, min, max);
	test_and_set_regstatus(gprs);
	return;

error:
	ofono_info("GPRS not supported on this device");
	ofono_gprs_remove(gprs);
}

static int at_gprs_probe(struct ofono_gprs *gprs,
					unsigned int vendor, void *data)
{
	GAtChat *chat = data;
	struct gprs_data *gd;
	int autoattach;
	struct ofono_modem* modem=ofono_gprs_get_modem(gprs);

	gd = g_try_new0(struct gprs_data, 1);
	if (gd == NULL)
		return -ENOMEM;

	gd->chat = g_at_chat_clone(chat);
	gd->vendor = vendor;

	ofono_gprs_set_data(gprs, gd);

	if (gd->vendor == OFONO_VENDOR_GEMALTO) {
		autoattach=ofono_modem_get_integer(modem, "GemaltoAutoAttach");
		/* set autoattach */
		gd->auto_attach = (autoattach == 1);
		/* skip the cgdcont scanning: set manually */
		test_and_set_regstatus(gprs);
	} else {
		g_at_chat_send(gd->chat, "AT+CGDCONT=?", cgdcont_prefix,
						at_cgdcont_test_cb, gprs, NULL);
	}

	return 0;
}

static void at_gprs_remove(struct ofono_gprs *gprs)
{
	struct gprs_data *gd = ofono_gprs_get_data(gprs);

	ofono_gprs_set_data(gprs, NULL);

	g_at_chat_unref(gd->chat);
	g_free(gd);
}

static const struct ofono_gprs_driver driver = {
	.name			= "atmodem",
	.probe			= at_gprs_probe,
	.remove			= at_gprs_remove,
	.set_attached		= at_gprs_set_attached,
	.attached_status	= at_gprs_registration_status,
};

void at_gprs_init(void)
{
	ofono_gprs_driver_register(&driver);
}

void at_gprs_exit(void)
{
	ofono_gprs_driver_unregister(&driver);
}
