/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2010  Nokia Corporation and/or its subsidiary(-ies).
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

#ifndef __OFONO_CONNPREF_H
#define __OFONO_CONNPREF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ofono/types.h>

#define ACTIA_PRO_DEFAULT_CONTEXT "DefaultContext"
#define ACTIA_PRO_CONTEXTROFILES "ContextProfiles"
#define ACTIA_PRO_BIP_SERVER_IP_ADDRESS "BIPServerIPAddress"
#define ACTIA_PRO_IMSAUTOCONNECT "IMSAutoconnect"
#define ACTIA_PRO_RPM "RPM"

#define OFONO_CONNPREF_PDP_TYPE_IP "ip"
#define OFONO_CONNPREF_PDP_TYPE_IPV6 "ipv6"
#define OFONO_CONNPREF_PDP_TYPE_IPV4V6 "ipv4v6"
#define OFONO_CONNPREF_PDP_TYPE_NONE ""

enum ofono_connpref_is_pdp_type {
	OFONO_CONNPREF_IS_PDP_TYPE_IP = 0,
	OFONO_CONNPREF_IS_PDP_TYPE_IPV6,
	OFONO_CONNPREF_IS_PDP_TYPE_IPV4V6,
	OFONO_CONNPREF_IS_PDP_TYPE_NONE,
};

struct ofono_connpref;

typedef void (*ofono_connpref_techno_set_cb_t)(
                        const struct ofono_error *error,
                        void *data);

typedef void (*ofono_connpref_contextprofiles_query_cb_t)(
                        const struct ofono_error *error,
                        char * contextprofiles_list[],
                        char * bip_address_ip,
                        int contextprofile_size,
                        int ims_autoconnect,
                        int rpm,
                        void *data);


struct ofono_connpref_driver {
	const char *name;
	int (*probe)(struct ofono_connpref *cp, unsigned int vendor, void *data);
	void (*remove)(struct ofono_connpref *cp);
	void (*query_connpref_config)(struct ofono_connpref *cp,
	                              ofono_connpref_contextprofiles_query_cb_t cb,
	                              void *data);
	void (*set_connpref_context_profile)(struct ofono_connpref *cp,
	                                     guint16 cid,
	                                     char * apn,
	                                     enum ofono_connpref_is_pdp_type pdp_type,
	                                     ofono_connpref_techno_set_cb_t cb,
	                                     void *data);
	void (*set_connpref_default_context)(struct ofono_connpref *connpref,
	                                     guint16 cid);
	void (*set_connpref_ims_autoconnect)(struct ofono_connpref *connpref,
	                                     ofono_bool_t ims_autoconnect,
	                                     ofono_connpref_techno_set_cb_t cb,
	                                     void *data);
	void (*set_connpref_rpm)(struct ofono_connpref *connpref,
	                                     ofono_bool_t rpm,
	                                     ofono_connpref_techno_set_cb_t cb,
	                                     void *data);
};

int ofono_connpref_driver_register(
                const struct ofono_connpref_driver *d);
void ofono_connpref_driver_unregister(
                const struct ofono_connpref_driver *d);

struct ofono_connpref *ofono_connpref_create(struct ofono_modem *modem,
                                             unsigned int vendor,
                                             const char *driver,
                                             void *data);

void ofono_connpref_register(struct ofono_connpref *cp);
void ofono_connpref_remove(struct ofono_connpref *cp);

void ofono_connpref_set_data(struct ofono_connpref *cp, void *data);
void *ofono_connpref_get_data(struct ofono_connpref *cp);

guint16 ofono_connpref_get_default_context(struct ofono_connpref *connpref);
void ofono_connpref_set_default_context(struct ofono_connpref *connpref, guint16 cid);
#ifdef __cplusplus
}
#endif

#endif /* __OFONO_CONNPREF_H */
