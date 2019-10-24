/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include <glib.h>

#include "drivers/mbimmodem/mbim.h"
#include "drivers/mbimmodem/mbim-message.h"
#include "drivers/mbimmodem/mbimmodem.h"

#include "gatchat.h"
#include "gatresult.h"

#include "gemaltoutil.h"
#include <ofono/gemalto.h>

static const char *none_prefix[] = { NULL };

enum state {
	STATE_IDLE,
	STATE_ENABLING,
	STATE_DISABLING,
	STATE_ACTIVE,
};

struct gprs_context_data {
	struct mbim_device *device;
	unsigned int active_context;
	enum ofono_gprs_proto proto;
	enum state state;
	ofono_gprs_context_cb_t cb;
	void *cb_data;
	GAtChat *chat;
	unsigned int at_cid;
};

static uint32_t proto_to_context_ip_type(enum ofono_gprs_proto proto)
{
	switch (proto) {
	case OFONO_GPRS_PROTO_IP:
		return 1; /* MBIMContextIPTypeIPv4 */
	case OFONO_GPRS_PROTO_IPV6:
		return 2; /* MBIMContextIPTypeIPv6 */
	case OFONO_GPRS_PROTO_IPV4V6:
		return 3; /* MBIMContextIPTypeIPv4v6 */
	}

	return 0;
}

static void mbim_deactivate_cb(struct mbim_message *message, void *user)
{
	struct ofono_gprs_context *gc = user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	gcd->active_context = 0;
	gcd->state = STATE_IDLE;

	if (!gcd->cb)
		return;

	if (mbim_message_get_error(message) != 0)
		CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
	else
		CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
}

static void gemalto_gprs_deactivate_primary(struct ofono_gprs_context *gc,
					unsigned int cid,
					ofono_gprs_context_cb_t cb, void *data)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct mbim_message *message;

	DBG("cid %u", cid);

	gcd->state = STATE_DISABLING;
	gcd->cb = cb;
	gcd->cb_data = data;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "uusssuuu16y",
					cid, 0, NULL, NULL, NULL, 0, 0, 0,
					mbim_context_type_internet);

	if (mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				mbim_deactivate_cb, gc, NULL) > 0)
		return;

	mbim_message_unref(message);

	if (cb)
		CALLBACK_WITH_FAILURE(cb, data);
}

static void mbim_ip_configuration_cb(struct mbim_message *message, void *user)
{
	struct ofono_gprs_context *gc = user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);
	const char *interface;
	uint32_t session_id;
	uint32_t ipv4_config_available;
	uint32_t ipv6_config_available;
	uint32_t n_ipv4_addr;
	uint32_t ipv4_addr_offset;
	uint32_t n_ipv6_addr;
	uint32_t ipv6_addr_offset;
	uint32_t ipv4_gw_offset;
	uint32_t ipv6_gw_offset;
	uint32_t n_ipv4_dns;
	uint32_t ipv4_dns_offset;
	uint32_t n_ipv6_dns;
	uint32_t ipv6_dns_offset;
	uint32_t ipv4_mtu;
	uint32_t ipv6_mtu;

	struct in6_addr ipv6;
	struct in_addr ipv4;
	char buf[INET6_ADDRSTRLEN];

	DBG("%u", mbim_message_get_error(message));

	if (mbim_message_get_error(message) != 0)
		goto error;

	if (!mbim_message_get_arguments(message, "uuuuuuuuuuuuuuu",
				&session_id,
				&ipv4_config_available, &ipv6_config_available,
				&n_ipv4_addr, &ipv4_addr_offset,
				&n_ipv6_addr, &ipv6_addr_offset,
				&ipv4_gw_offset, &ipv6_gw_offset,
				&n_ipv4_dns, &ipv4_dns_offset,
				&n_ipv6_dns, &ipv6_dns_offset,
				&ipv4_mtu, &ipv6_mtu))
		goto error;

	if (gcd->proto == OFONO_GPRS_PROTO_IPV6)
		goto ipv6;

	if (ipv4_config_available & 0x1) { /* Address Info present */
		uint32_t prefix;

		if (!mbim_message_get_ipv4_element(message, ipv4_addr_offset,
							&prefix, &ipv4))
			goto error;

		inet_ntop(AF_INET, &ipv4, buf, sizeof(buf));
		ofono_gprs_context_set_ipv4_address(gc, buf, TRUE);
		ofono_gprs_context_set_ipv4_prefix_length(gc, prefix);
	} else
		ofono_gprs_context_set_ipv4_address(gc, NULL, FALSE);

	if (ipv4_config_available & 0x2) { /* IPv4 Gateway info */
		if (!mbim_message_get_ipv4_address(message,
							ipv4_gw_offset, &ipv4))
			goto error;

		inet_ntop(AF_INET, &ipv4, buf, sizeof(buf));

		ofono_gprs_context_set_ipv4_gateway(gc, buf);
	}

	if (ipv4_config_available & 0x3) { /* IPv4 DNS Info */
		const char *dns[3];
		char dns1[INET_ADDRSTRLEN];
		char dns2[INET_ADDRSTRLEN];

		memset(dns, 0, sizeof(dns));

		if (n_ipv4_dns > 1) { /* Grab second DNS */
			if (!mbim_message_get_ipv4_address(message,
							ipv4_dns_offset + 4,
							&ipv4))
				goto error;

			inet_ntop(AF_INET, &ipv4, dns2, sizeof(dns2));
			dns[1] = dns2;
		}

		if (n_ipv4_dns > 0) { /* Grab first DNS */
			if (!mbim_message_get_ipv4_address(message,
							ipv4_dns_offset,
							&ipv4))
				goto error;

			inet_ntop(AF_INET, &ipv4, dns1, sizeof(dns1));
			dns[0] = dns1;

			ofono_gprs_context_set_ipv4_dns_servers(gc, dns);
		}
	}

	if (ipv4_config_available & 0x8) { /* IPv4 mtu info */
	    ofono_gprs_context_set_ipv4_mtu(gc, ipv4_mtu);
	}

	if (gcd->proto == OFONO_GPRS_PROTO_IP)
		goto done;
ipv6:
	if (ipv6_config_available & 0x1) { /* Address Info present */
		uint32_t prefix;

		if (!mbim_message_get_ipv6_element(message, ipv6_addr_offset,
							&prefix, &ipv6))
			goto error;

		inet_ntop(AF_INET6, &ipv6, buf, sizeof(buf));
		ofono_gprs_context_set_ipv6_address(gc, buf);
		ofono_gprs_context_set_ipv6_prefix_length(gc, prefix);
	}

	if (ipv6_config_available & 0x2) { /* IPv6 Gateway info */
		if (!mbim_message_get_ipv6_address(message,
							ipv6_gw_offset, &ipv6))
			goto error;

		inet_ntop(AF_INET6, &ipv6, buf, sizeof(buf));

		ofono_gprs_context_set_ipv6_gateway(gc, buf);
	}

	if (ipv6_config_available & 0x3) { /* IPv6 DNS Info */
		const char *dns[3];
		char dns1[INET6_ADDRSTRLEN];
		char dns2[INET6_ADDRSTRLEN];

		memset(dns, 0, sizeof(dns));

		if (n_ipv6_dns > 1) { /* Grab second DNS */
			if (!mbim_message_get_ipv6_address(message,
							ipv6_dns_offset + 16,
							&ipv6))
				goto error;

			inet_ntop(AF_INET6, &ipv6, dns2, sizeof(dns2));
			dns[1] = dns2;
		}

		if (n_ipv6_dns > 0) { /* Grab first DNS */
			if (!mbim_message_get_ipv6_address(message,
							ipv6_dns_offset,
							&ipv6))
				goto error;

			inet_ntop(AF_INET6, &ipv6, dns1, sizeof(dns1));
			dns[0] = dns1;

			ofono_gprs_context_set_ipv6_dns_servers(gc, dns);
		}
	}

	if (ipv6_config_available & 0x8) { /* IPv6 mtu info */
		ofono_gprs_context_set_ipv6_mtu(gc, ipv6_mtu);
	}

done:

	gcd->state = STATE_ACTIVE;
	interface = ofono_modem_get_string(modem, "NetworkInterface");
	DBG();
	ofono_gprs_context_set_interface(gc, interface);
	DBG("%p - %p(%p)", gcd, gcd?gcd->cb:NULL, gcd?gcd->cb_data:NULL);

	CALLBACK_WITH_SUCCESS(gcd->cb, gcd->cb_data);
	DBG();
	gcd->cb = NULL;
	gcd->cb_data = NULL;
	return;

error:
	CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
	gcd->state = STATE_IDLE;
	gcd->cb = NULL;
	gcd->cb_data = NULL;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "uusssuuu16y",
					gcd->active_context, 0,
					NULL, NULL, NULL, 0, 0, 0,
					mbim_context_type_internet);

	if (!mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				NULL, NULL, NULL))
		mbim_message_unref(message);
}

static void mbim_activate_cb(struct mbim_message *message, void *user)
{
	struct ofono_gprs_context *gc = user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	if (mbim_message_get_error(message) != 0)
		goto error;

	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_IP_CONFIGURATION,
					MBIM_COMMAND_TYPE_QUERY);
	mbim_message_set_arguments(message, "uuuuuuuuuuuuuuu",
				gcd->active_context,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

	if (mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				mbim_ip_configuration_cb, gc, NULL) > 0)
		return;

	mbim_message_unref(message);
error:
	CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
	gcd->state = STATE_IDLE;
	gcd->cb = NULL;
	gcd->cb_data = NULL;
}

static void auth_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	struct mbim_message *message;
	char mbim_apn[101];

	if (!ok)
		goto error;

	snprintf(mbim_apn, sizeof(mbim_apn), "*99***%d#", gcd->at_cid);
	message = mbim_message_new(mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					MBIM_COMMAND_TYPE_SET);
	mbim_message_set_arguments(message, "uusssuuu16y",
				gcd->active_context,
				1, /* MBIMActivationCommandActivate */
				mbim_apn,
				NULL, /* username */
				NULL, /* password */
				0, /*MBIMCompressionNone */
				0, /* MBIMAUthProtocolNone */
				proto_to_context_ip_type(gcd->proto),
				mbim_context_type_internet);

	if (mbim_device_send(gcd->device, GPRS_CONTEXT_GROUP, message,
				mbim_activate_cb, gc, NULL) > 0)
		return;

	mbim_message_unref(message);
error:
	ofono_error("Unable activate context");
	CALLBACK_WITH_FAILURE(gcd->cb, gcd->cb_data);
}

static void gemalto_gprs_activate_primary(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *data)
{
	struct ofono_modem *modem = ofono_gprs_context_get_modem(gc);
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);
	char *buf_apn;
	char *buf_auth;

	DBG("cid %u", ctx->cid);

	gcd->active_context = ctx->cid;
	gcd->cb = cb;
	gcd->cb_data = data;
	gcd->proto = ctx->proto;
	gcd->state = STATE_ENABLING;

	buf_apn = gemalto_get_cgdcont_command(modem, gcd->at_cid, ctx->proto,
								ctx->apn);
	buf_auth = gemalto_get_auth_command(modem, gcd->at_cid,
				ctx->auth_method, ctx->username, ctx->password);

	/*
	 * note that if the cgdcont or auth commands are not ok we ignore them
	 * and continue but if the sending fails we do an error
	 */
	if (!g_at_chat_send(gcd->chat, buf_apn, none_prefix,
						NULL, NULL, NULL) ||
			!g_at_chat_send(gcd->chat, buf_auth, none_prefix,
						auth_cb, gc, NULL))
		CALLBACK_WITH_FAILURE(cb, data);

	g_free(buf_apn);
	g_free(buf_auth);
}

static void gemalto_gprs_detach_shutdown(struct ofono_gprs_context *gc,
						unsigned int cid)
{
	DBG("");
	gemalto_gprs_deactivate_primary(gc, cid, NULL, NULL);
}

static void mbim_connect_notify(struct mbim_message *message, void *user)
{
	uint32_t session_id;
	uint32_t activation_state;
	uint32_t voice_call_state;
	uint32_t ip_type;
	uint8_t context_type[16];
	uint32_t nw_error;
	char uuidstr[37];
	struct ofono_gprs_context *gc = user;
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	if (!mbim_message_get_arguments(message, "uuuu16yu",
					&session_id, &activation_state,
					&voice_call_state, &ip_type,
					context_type, &nw_error))
		return;

	DBG("session_id: %u, activation_state: %u, ip_type: %u",
			session_id, activation_state, ip_type);
	l_uuid_to_string(context_type, uuidstr, sizeof(uuidstr));
	DBG("context_type: %s, nw_error: %u", uuidstr, nw_error);

	if(activation_state!=3) // context deactivated
		return;
	ofono_gprs_context_deactivated(gc, gcd->active_context);
	gcd->active_context = 0;
	gcd->state = STATE_IDLE;
}

static int gemalto_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int vendor, void *data)
{
	struct gemalto_mbim_composite *composite = data;
	struct mbim_device *device = composite->device;
	struct gprs_context_data *gcd;

	DBG("gemaltombim");

	if (!mbim_device_register(device, GPRS_CONTEXT_GROUP,
					mbim_uuid_basic_connect,
					MBIM_CID_CONNECT,
					mbim_connect_notify, gc, NULL))
		return -EIO;

	gcd = l_new(struct gprs_context_data, 1);
	gcd->device = mbim_device_ref(device);
	gcd->chat = g_at_chat_clone(composite->chat);
	gcd->at_cid = composite->at_cid;

	ofono_gprs_context_set_data(gc, gcd);

	return 0;
}

static void gemalto_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *gcd = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	mbim_device_cancel_group(gcd->device, GPRS_CONTEXT_GROUP);
	mbim_device_unregister_group(gcd->device, GPRS_CONTEXT_GROUP);
	mbim_device_unref(gcd->device);
	gcd->device = NULL;
	g_at_chat_unref(gcd->chat);
	gcd->chat = NULL;
	l_free(gcd);
}

static const struct ofono_gprs_context_driver driver = {
	.name			= "gemaltomodemmbim",
	.probe			= gemalto_gprs_context_probe,
	.remove			= gemalto_gprs_context_remove,
	.activate_primary	= gemalto_gprs_activate_primary,
	.deactivate_primary	= gemalto_gprs_deactivate_primary,
	.detach_shutdown	= gemalto_gprs_detach_shutdown
};

extern void gemalto_gprs_context_mbim_init();
extern void gemalto_gprs_context_mbim_exit();

void gemalto_gprs_context_mbim_init(void)
{
	ofono_gprs_context_driver_register(&driver);
}

void gemalto_gprs_context_mbim_exit(void)
{
	ofono_gprs_context_driver_unregister(&driver);
}
