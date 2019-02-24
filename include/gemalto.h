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

#ifndef __OFONO_GEMALTO_H__
#define __OFONO_GEMALTO_H__

enum auth_option {
	GEMALTO_AUTH_DEFAULTS		= 0,
	GEMALTO_AUTH_USE_SGAUTH		= 1<<0,
	GEMALTO_AUTH_ORDER_PWD_USR	= 1<<1,
	GEMALTO_AUTH_ALWAYS_ALL_PARAMS	= 1<<2,
};

struct gemalto_mbim_composite {
	struct mbim_device *device;
	GAtChat *chat;
	unsigned int at_cid;
};

#endif /* __OFONO_GEMALTO_H__ */
