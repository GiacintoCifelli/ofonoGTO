/*
 *
 *  oFono - Open Source Telephony
 *
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

#include <glib.h>
#include <gatchat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <ofono/log.h>
#include <ofono/types.h>

#include "ofono.h"
#include "gemaltomodem.h"
#include <ofono/gemalto.h>

char *gemalto_get_auth_command(struct ofono_modem *modem, int cid,
				enum ofono_gprs_auth_method auth_method,
				const char *username, const char *password)
{
	int gemalto_auth = ofono_modem_get_integer(modem, "GemaltoAuthType");
	int len;
	size_t buflen = 32 + OFONO_GPRS_MAX_USERNAME_LENGTH +
					OFONO_GPRS_MAX_PASSWORD_LENGTH  + 1;
	char *buf = g_new(char, buflen);

	/* for now. Later to consider modules where the LTE attach CID=3 */
	if (cid==0)
		cid=1;

	if (gemalto_auth & GEMALTO_AUTH_USE_SGAUTH)
		len = snprintf(buf, buflen, "AT^SGAUTH");
	else
		len = snprintf(buf, buflen, "AT+CGAUTH");

	len += snprintf(buf+len, buflen-len, "=%d,%d", cid,
			at_util_gprs_auth_method_to_auth_prot(auth_method));

	switch(auth_method) {
	case OFONO_GPRS_AUTH_METHOD_NONE:

		if (gemalto_auth & GEMALTO_AUTH_ALWAYS_ALL_PARAMS)
			snprintf(buf+len, buflen-len, ",\"\",\"\"");

		break;
	case OFONO_GPRS_AUTH_METHOD_PAP:
	case OFONO_GPRS_AUTH_METHOD_CHAP:

		if (gemalto_auth & GEMALTO_AUTH_ORDER_PWD_USR)
			snprintf(buf+len, buflen-len, ",\"%s\",\"%s\"",
							password, username);
		else
			snprintf(buf+len, buflen-len, ",\"%s\",\"%s\"",
							username, password);

		break;
	}

	return buf;
}

char *gemalto_get_cgdcont_command(struct ofono_modem *modem, guint cid,
				enum ofono_gprs_proto proto, const char *apn)
{
	/*
	 * For future extension: verify if the module supports automatic
	 * context provisioning and if so, also if there is a manual override
	 * This is an ofono_modem_get_integer property
	 */

	/* for now. Later to consider modules where the LTE attach CID=3 */
	if (cid==0)
		cid=1;

	return at_util_get_cgdcont_command(cid, proto, apn);
}
