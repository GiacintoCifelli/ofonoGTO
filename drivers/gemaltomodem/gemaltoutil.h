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

struct ofono_modem;

char *gemalto_get_auth_command(struct ofono_modem *modem, int cid,
				enum ofono_gprs_auth_method auth_method,
				const char *username, const char *password);


char *gemalto_get_cgdcont_command(struct ofono_modem *modem, guint cid,
				enum ofono_gprs_proto proto, const char *apn);
