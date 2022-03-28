/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *  2021 Thales add dual IP support
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
#include <arpa/inet.h>

#include <ofono/log.h>
#include <ofono/modem.h>
#include <ofono/gprs-context.h>

#include "qmi.h"
#include "wda.h"
#include "wds.h"

#include "qmimodem.h"

struct gprs_context_data {
	struct qmi_service *ipv4_wds;
	struct qmi_service *ipv6_wds;
	struct qmi_service *wda;
	struct qmi_device *dev;

	unsigned int active_context;	/* PDP cid */
	uint32_t ipv4_pkt_handle;
	uint32_t ipv6_pkt_handle;
	enum ofono_gprs_proto proto;
	uint8_t ip_family;
	uint8_t qmi_auth;
	const char *apn;
	const char *username;
	const char *password;
};

static int qmi_start_net(struct gprs_context_data *data, struct cb_data *cbd);
static void create_wds_cb(struct qmi_service *service, void *user_data);
static int qmi_stop_net(struct gprs_context_data *data, struct cb_data *cbd);

static void pkt_status_notify(struct qmi_result *result, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	const struct qmi_wds_notify_conn_status *status;
	uint16_t len;
	uint8_t ip_family;

	DBG("");

	status = qmi_result_get(result, QMI_WDS_NOTIFY_CONN_STATUS, &len);
	if (!status)
		return;

	DBG("conn status %d", status->status);

	if (qmi_result_get_uint8(result, QMI_WDS_NOTIFY_IP_FAMILY, &ip_family))
		DBG("ip family %d", ip_family);

	switch (status->status) {
	case QMI_WDS_CONN_STATUS_DISCONNECTED:
		if (ip_family == QMI_WDS_IP_FAMILY_IPV4) {
			if (data->ipv4_pkt_handle) {
				data->ipv4_pkt_handle = 0;
			}
		} else {
			if (data->ipv6_pkt_handle) {
				data->ipv6_pkt_handle = 0;
			}
		}

		if ((data->ipv4_pkt_handle == 0) && (data->ipv6_pkt_handle == 0)) {
			/* The context has been disconnected by the network */
			ofono_gprs_context_deactivated(gc, data->active_context);
			data->active_context = 0;
		}
		break;
	}
}

static void get_settings_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct ofono_modem *modem;
	const char *interface;
	uint8_t pdp_type, ip_family;

	char* apn;
	uint32_t mtu;


	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto done;

	apn = qmi_result_get_string(result, QMI_WDS_RESULT_APN);
	if (apn) {
		DBG("APN: %s", apn);
		g_free(apn);
	}

	if (qmi_result_get_uint8(result, QMI_WDS_RESULT_PDP_TYPE, &pdp_type))
		DBG("PDP type %d", pdp_type);

	if (qmi_result_get_uint8(result, QMI_WDS_RESULT_IP_FAMILY, &ip_family))
		DBG("IP family %d", ip_family);

	if (ip_family == QMI_WDS_IP_FAMILY_IPV4) {
		uint32_t ip_addr;
		struct in_addr addr;
		char* straddr;
		const char *dns[3];
		char dns_buf[2][INET_ADDRSTRLEN];

		memset(dns, 0, sizeof(dns));

		if (qmi_result_get_uint32(result,QMI_WDS_RESULT_IPV4_ADDRESS, &ip_addr)) {
			addr.s_addr = htonl(ip_addr);
			straddr = inet_ntoa(addr);
			DBG("IP addr: %s", straddr);
			ofono_gprs_context_set_ipv4_address(gc, straddr, 1);
		}

		if (qmi_result_get_uint32(result,QMI_WDS_RESULT_IPV4_GATEWAY, &ip_addr)) {
			addr.s_addr = htonl(ip_addr);
			straddr = inet_ntoa(addr);
			DBG("Gateway: %s", straddr);
			ofono_gprs_context_set_ipv4_gateway(gc, straddr);
		}

		if (qmi_result_get_uint32(result,
					QMI_WDS_RESULT_IPV4_GATEWAY_NETMASK, &ip_addr)) {
			addr.s_addr = htonl(ip_addr);
			straddr = inet_ntoa(addr);
			DBG("Gateway netmask: %s", straddr);
			ofono_gprs_context_set_ipv4_netmask(gc, straddr);
		}

		if (qmi_result_get_uint32(result,
					QMI_WDS_RESULT_IPV4_PRIMARY_DNS, &ip_addr)) {
			addr.s_addr = htonl(ip_addr);
			dns[0] = inet_ntop(AF_INET, &addr, dns_buf[0], sizeof(dns_buf[0]));
			DBG("Primary DNS: %s", dns[0]);
		}

		if (qmi_result_get_uint32(result,
					QMI_WDS_RESULT_IPV4_SECONDARY_DNS, &ip_addr)) {
			addr.s_addr = htonl(ip_addr);
			dns[1] = inet_ntop(AF_INET, &addr, dns_buf[1], sizeof(dns_buf[1]));
			DBG("Secondary DNS: %s", dns[1]);
		}

		if (dns[0])
			ofono_gprs_context_set_ipv4_dns_servers(gc, dns);

		if (qmi_result_get_uint32(result,
					QMI_WDS_RESULT_MTU, &mtu)) {
			DBG("MTU: %d", mtu);
			ofono_gprs_context_set_ipv4_mtu(gc, mtu);
		}
	} else if (ip_family == QMI_WDS_IP_FAMILY_IPV6) {
		struct in6_addr ipv6;
		uint8_t prefix;
		char buff[INET6_ADDRSTRLEN];
		const char *dns[3];
		char dns1[INET6_ADDRSTRLEN];
		char dns2[INET6_ADDRSTRLEN];

		memset(dns, 0, sizeof(dns));

		if (qmi_result_get_ipv6_element(result, QMI_WDS_RESULT_IPV6_ADDRESS, &prefix, &ipv6)) {
			inet_ntop(AF_INET6, &ipv6, buff, sizeof(buff));
			DBG("IPV6 addr: %s", buff);
			DBG("IPV6 prefix length: %d", prefix);
			ofono_gprs_context_set_ipv6_address(gc, buff);
			ofono_gprs_context_set_ipv6_prefix_length(gc, prefix);
		}

		if (qmi_result_get_ipv6_element(result, QMI_WDS_RESULT_IPV6_GATEWAY, &prefix, &ipv6)) {
			inet_ntop(AF_INET6, &ipv6, buff, sizeof(buff));
			DBG("IPV6 gateway: %s", buff);
			DBG("IPV6 gateway prefix length: %d", prefix);
			ofono_gprs_context_set_ipv6_gateway(gc, buff);
		}

		if (qmi_result_get_ipv6_address(result, QMI_WDS_RESULT_IPV6_PRIMARY_DNS, &ipv6)) {
			inet_ntop(AF_INET6, &ipv6, dns1, sizeof(dns1));
			DBG("IPV6 dns1: %s", dns1);
			dns[0] = dns1;
		}

		if (qmi_result_get_ipv6_address(result, QMI_WDS_RESULT_IPV6_SECONDARY_DNS, &ipv6)) {
			inet_ntop(AF_INET6, &ipv6, dns2, sizeof(dns2));
			DBG("IPV6 dns2: %s", dns2);
			dns[1] = dns2;
		}

		if (dns[0]) {
			ofono_gprs_context_set_ipv6_dns_servers(gc, dns);
		}

		if (qmi_result_get_uint32(result,
					QMI_WDS_RESULT_MTU, &mtu)) {
			DBG("MTU: %d", mtu);
			ofono_gprs_context_set_ipv6_mtu(gc, mtu);
		}
	}

done:
	if ((data->proto == OFONO_GPRS_PROTO_IPV4V6) && (data->ip_family == QMI_WDS_IP_FAMILY_IPV4)) {
		/* dual, next IP family is IPV6 (dual) */
		data->ip_family = QMI_WDS_IP_FAMILY_IPV6;
		/* Duplicate cbd, the old one will be freed when this method returns */
		cbd = cb_data_new(cb, cbd->data);
		cbd->user = gc;
		if (qmi_start_net(data, cbd) > 0)
			return;
		else {
			/* failed to start IPv6 */
			modem = ofono_gprs_context_get_modem(gc);
			interface = ofono_modem_get_string(modem, "NetworkInterface");

			ofono_gprs_context_set_interface(gc, interface);
			CALLBACK_WITH_SUCCESS(cb, cbd->data);
			g_free(cbd);   /* free duplicated cbd */
		}
	} else {
		modem = ofono_gprs_context_get_modem(gc);
		interface = ofono_modem_get_string(modem, "NetworkInterface");

		ofono_gprs_context_set_interface(gc, interface);
		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	}
}

static void start_net_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;

	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct qmi_service *wds = NULL;
	uint8_t ipfamily = data->ip_family;

	struct ofono_modem *modem;
	const char *interface;
	uint32_t handle;
	/* get settings */
	struct qmi_param *param;

	uint32_t requested = 	QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_PDP_TYPE		|
				QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_DNS_ADDRESS	|
             			QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_APN_NAME		|
             			QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_IP_ADDRESS	|
             			QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_GATEWAY_INFO	|
             			QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_MTU 		|
             			QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_DOMAIN_NAME_LIST	|
             			QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_IP_FAMILY;

	if (qmi_result_set_error(result, NULL))
		goto error;

	if (!qmi_result_get_uint32(result, QMI_WDS_RESULT_PKT_HANDLE, &handle))
		goto error;

	DBG("packet handle: 0x%08x", handle);

	if (ipfamily == QMI_WDS_IP_FAMILY_IPV4) {
		wds = data->ipv4_wds;
		data->ipv4_pkt_handle = handle;
	} else {
		wds = data->ipv6_wds;
		data->ipv6_pkt_handle = handle;
	}

	/* Duplicate cbd, the old one will be freed when this method returns */
	cbd = cb_data_new(cb, cbd->data);
	cbd->user = gc;
	param = qmi_param_new_uint32(QMI_WDS_PARAM_GET_CURRENT_SETTINGS, requested);

	if (qmi_service_send(wds, QMI_WDS_GET_SETTINGS, param,
					get_settings_cb, cbd, g_free) > 0)
		return;

	qmi_param_free(param);

	modem = ofono_gprs_context_get_modem(gc);
	interface = ofono_modem_get_string(modem, "NetworkInterface");
	ofono_gprs_context_set_interface(gc, interface);
	CALLBACK_WITH_SUCCESS(cb, cbd->data);
	g_free(cbd);		/* failed to send, then free the duplicated cbd */

	return;

error:
	if (data->proto == OFONO_GPRS_PROTO_IPV4V6 && ipfamily == QMI_WDS_IP_FAMILY_IPV4)
	{
		/* failed to start IPv4, start IPv6 */
		data->ip_family = QMI_WDS_IP_FAMILY_IPV6;
		/* Duplicate cbd, the old one will be freed when this method returns */
		cbd = cb_data_new(cb, cbd->data);
		cbd->user = gc;
		if (qmi_start_net(data, cbd) > 0)
			return;
		else {
			/* IPv6 failed */
			data->active_context = 0;
			CALLBACK_WITH_FAILURE(cb, cbd->data);
			g_free(cbd);	/* free the duplicated cbd */
		}
	} else if ((data->proto == OFONO_GPRS_PROTO_IPV4V6) && (ipfamily == QMI_WDS_IP_FAMILY_IPV6) && (data->ipv4_pkt_handle != 0)) {
		/* failed to start IPv6, but IPv4 successfully */
		modem = ofono_gprs_context_get_modem(gc);
		interface = ofono_modem_get_string(modem, "NetworkInterface");

		ofono_gprs_context_set_interface(gc, interface);

		CALLBACK_WITH_SUCCESS(cb, cbd->data);
	} else {
		/* IPv4 and IPv6 failed */
		data->active_context = 0;
		CALLBACK_WITH_FAILURE(cb, cbd->data);
	}
}

static int qmi_start_net(struct gprs_context_data *data, struct cb_data *cbd)
{
	uint8_t ipfamily = data->ip_family;
	struct qmi_param *param = NULL;
	struct qmi_service *wds = NULL;
	int ret;

	if (ipfamily == QMI_WDS_IP_FAMILY_IPV4) {
		wds = data->ipv4_wds;
	} else {
		wds = data->ipv6_wds;
	}

	if (wds == NULL)
		return -1;

	param = qmi_param_new();
	if (!param)
		return  -1;

	if (strlen(data->apn) > 0) {
		qmi_param_append(param, QMI_WDS_PARAM_APN, strlen(data->apn), data->apn);
	}

	qmi_param_append_uint8(param, QMI_WDS_PARAM_IP_FAMILY, ipfamily);

	qmi_param_append_uint8(param, QMI_WDS_PARAM_AUTHENTICATION_PREFERENCE,
					data->qmi_auth);

	if (data->qmi_auth != QMI_WDS_AUTHENTICATION_NONE && data->username[0] != '\0')
		qmi_param_append(param, QMI_WDS_PARAM_USERNAME,
					strlen(data->username), data->username);

	if (data->qmi_auth != QMI_WDS_AUTHENTICATION_NONE &&  data->password[0] != '\0')
		qmi_param_append(param, QMI_WDS_PARAM_PASSWORD,
					strlen(data->password), data->password);

	if ((ret = qmi_service_send(wds, QMI_WDS_START_NET, param,
					start_net_cb, cbd, g_free)) > 0)
		return ret;

	qmi_param_free(param);

	return -1;
}

#if 0 // not supported in current ofono baseline 1.26
/*
 * This function gets called for "automatic" contexts, those which are
 * not activated via activate_primary.  For these, we will still need
 * to call start_net in order to get the packet handle for the context.
 * The process for automatic contexts is essentially identical to that
 * for others.
 */
static void qmi_gprs_read_settings(struct ofono_gprs_context* gc,
					unsigned int cid, const char *apn,
					enum ofono_gprs_proto proto,
					ofono_gprs_context_cb_t cb,
					void *user_data)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("cid: %u, apn: %s, proto: %d", cid, apn, proto);

	data->active_context = cid;

	cbd->user = gc;
	data->proto = proto;

	/* IP family */
	switch (proto) {
	case OFONO_GPRS_PROTO_IP:
		data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	case OFONO_GPRS_PROTO_IPV6:
		data->ip_family = QMI_WDS_IP_FAMILY_IPV6;
		break;
	case OFONO_GPRS_PROTO_IPV4V6:
		/* dual, start IPv4 first */
		data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	default:
		data->proto = OFONO_GPRS_PROTO_IPV4V6;
		data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	}

	/* APN */
	data->apn = apn;

	/* quth */
	data->qmi_auth = QMI_WDS_AUTHENTICATION_NONE;

	if (qmi_start_net(data, cbd) > 0) {
		return;
	} else {
		if ((proto == OFONO_GPRS_PROTO_IPV4V6) && (data->ip_family == QMI_WDS_IP_FAMILY_IPV4)) {
			/* failed to start IPv4, start IPv6 */
			data->ip_family = QMI_WDS_IP_FAMILY_IPV6;
			if (qmi_start_net(data, cbd) > 0) {
				return;
			}
		}

		/* failed to start IPv4 and IPv6 */
		data->active_context = 0;
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		g_free(cbd);
	}
}
#endif // not supported in ofono 1.26

static uint8_t auth_method_to_qmi_auth(enum ofono_gprs_auth_method method)
{
	switch (method) {
	case OFONO_GPRS_AUTH_METHOD_CHAP:
		return QMI_WDS_AUTHENTICATION_CHAP;
	case OFONO_GPRS_AUTH_METHOD_PAP:
		return QMI_WDS_AUTHENTICATION_PAP;
	case OFONO_GPRS_AUTH_METHOD_NONE:
		return QMI_WDS_AUTHENTICATION_NONE;
	}

	return QMI_WDS_AUTHENTICATION_NONE;
}

static void qmi_activate_primary(struct ofono_gprs_context *gc,
				const struct ofono_gprs_primary_context *ctx,
				ofono_gprs_context_cb_t cb, void *user_data)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	uint8_t auth;

	DBG("cid: %u, apn: %s, proto: %d", ctx->cid, ctx->apn, ctx->proto);

	cbd->user = gc;

	data->active_context = ctx->cid;
	data->proto = ctx->proto;

	switch (ctx->proto) {
	case OFONO_GPRS_PROTO_IP:
		data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	case OFONO_GPRS_PROTO_IPV6:
		data->ip_family = QMI_WDS_IP_FAMILY_IPV6;
		break;
	case OFONO_GPRS_PROTO_IPV4V6:
		/* dual, start IPv4 first */
		data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	default:
		data->proto = OFONO_GPRS_PROTO_IPV4V6;
		data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
		break;
	}

	/* APN */
	data->apn = ctx->apn;

	/* auth */
	auth = auth_method_to_qmi_auth(ctx->auth_method);
	data->qmi_auth = auth;
	data->username = ctx->username;
	data->password = ctx->password;

	if (qmi_start_net(data, cbd) > 0) {
		return;
	} else {
		if ((ctx->proto == OFONO_GPRS_PROTO_IPV4V6) && (data->ip_family == QMI_WDS_IP_FAMILY_IPV4)) {
			/* failed to start IPv4, start IPv6 */
			data->ip_family = QMI_WDS_IP_FAMILY_IPV6;
			if (qmi_start_net(data, cbd) > 0) {
				return;
			}
		}

		/* failed to start IPv4 and IPv6 */
		data->active_context = 0;
		CALLBACK_WITH_FAILURE(cb, cbd->data);
		g_free(cbd);
	}
}

static void stop_net_cb(struct qmi_result *result, void *user_data)
{
	struct cb_data *cbd = user_data;
	ofono_gprs_context_cb_t cb = cbd->cb;
	struct ofono_gprs_context *gc = cbd->user;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	if (data->ipv4_pkt_handle != 0 && data->ipv6_pkt_handle != 0) {
		/* dual, IPv4 has been stopped, then stop IPv6 */
		data->ipv4_pkt_handle = 0;

		/* Duplicate cbd, the old one will be freed when this method returns */
		cbd = cb_data_new(cb, cbd->data);
		cbd->user = gc;

		if (qmi_stop_net(data, cbd) > 0)
			return;

		if (cb)
			CALLBACK_WITH_FAILURE(cb, user_data);

		g_free(cbd);
	} else {
		/* IPv4 or IPv6 has been stoped */
		if (qmi_result_set_error(result, NULL)) {
			if (cb)
				CALLBACK_WITH_FAILURE(cb, cbd->data);
			return;
		}

		if (data->ipv6_pkt_handle != 0) {
			data->ipv6_pkt_handle = 0;
		}

		if (data->ipv4_pkt_handle != 0) {
			data->ipv4_pkt_handle = 0;
		}

		if (cb)
			CALLBACK_WITH_SUCCESS(cb, cbd->data);
		else
			ofono_gprs_context_deactivated(gc, data->active_context);

		data->active_context = 0;
	}
}

static int qmi_stop_net(struct gprs_context_data *data, struct cb_data *cbd)
{
	int ret;
	struct qmi_param *param;
	guint32 pkt_handle = 0;
	struct qmi_service *wds = NULL;

	if (data->ipv4_pkt_handle != 0 && data->ipv6_pkt_handle != 0) {
		/* dual, first stop IPv4 */
		pkt_handle = data->ipv4_pkt_handle;
		wds = data->ipv4_wds;
	} else {
		/* IPv4 or IPv6 */
		if (data->ipv4_pkt_handle != 0) {
			/* stop IPv4 */
			wds = data->ipv4_wds;
			pkt_handle = data->ipv4_pkt_handle;
			DBG("stop IPv4, pkt handle: 0x%08x", pkt_handle);
		} else if (data->ipv6_pkt_handle != 0) {
			/* stop IPv6 */
			wds = data->ipv6_wds;
			pkt_handle = data->ipv6_pkt_handle;
			DBG("stop IPv6, pkt handle: 0x%08x", pkt_handle);
		}
	}

	if ((wds == NULL) || (pkt_handle == 0)) {
		return -1;
	}

	param = qmi_param_new_uint32(QMI_WDS_PARAM_PKT_HANDLE,
						pkt_handle);

	if (!param)
		return -1;

	if ((ret = qmi_service_send(wds, QMI_WDS_STOP_NET, param,
					stop_net_cb, cbd, g_free)) > 0)
		return ret;

	qmi_param_free(param);

	return -1;
}

static void qmi_deactivate_primary(struct ofono_gprs_context *gc,
				unsigned int cid,
				ofono_gprs_context_cb_t cb, void *user_data)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	struct cb_data *cbd = cb_data_new(cb, user_data);

	DBG("cid %u", cid);

	cbd->user = gc;

	if (qmi_stop_net(data, cbd) > 0)
		return;

	if (cb)
		CALLBACK_WITH_FAILURE(cb, user_data);

	g_free(cbd);
}

static void qmi_gprs_context_detach_shutdown(struct ofono_gprs_context *gc,
						unsigned int cid)
{
	DBG("");

	qmi_deactivate_primary(gc, cid, NULL, NULL);
}

static void wds_set_ip_family_pref_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint8_t ipfamily = data->ip_family;

	if (ipfamily == QMI_WDS_IP_FAMILY_IPV4) {
		DBG("");
		qmi_service_register(data->ipv4_wds, QMI_WDS_PKT_STATUS_IND,
					pkt_status_notify, gc, NULL);

		/* create IPv6 wds */
		data->ip_family = QMI_WDS_IP_FAMILY_IPV6;
		qmi_service_create_shared(data->dev, QMI_SERVICE_WDS, create_wds_cb, gc,
									NULL);
	} else {
		qmi_service_register(data->ipv6_wds, QMI_WDS_PKT_STATUS_IND,
					pkt_status_notify, gc, NULL);
	}
}

static void wds_set_ip_family_pref(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint8_t ipfamily = data->ip_family;
	struct qmi_param *param;

	DBG("ip family: %d", ipfamily);

	param = qmi_param_new_uint8(QMI_WDS_CLIENT_IP_FAMILY_PREF, ipfamily);
	if (!param) {
		return;
	}

	if (ipfamily == QMI_WDS_IP_FAMILY_IPV4) {
		/* IPv4 */
		if (qmi_service_send(data->ipv4_wds, QMI_WDS_SET_CLIENT_IP_FAMILY_PREF, param,
					wds_set_ip_family_pref_cb, gc, NULL) > 0)
			return;
	} else {
		/* IPv6 */
		if (qmi_service_send(data->ipv6_wds, QMI_WDS_SET_CLIENT_IP_FAMILY_PREF, param,
					wds_set_ip_family_pref_cb, gc, NULL) > 0)
			return;
	}

	qmi_param_free(param);
}

static void create_wds_cb(struct qmi_service *service, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint8_t ipfamily = data->ip_family;

	DBG("IP Family: %d", ipfamily);

	if (!service) {
		ofono_error("Failed to request WDS service");
		ofono_gprs_context_remove(gc);
		return;
	}

	if (ipfamily == QMI_WDS_IP_FAMILY_IPV4) {
		data->ipv4_wds = qmi_service_ref(service);
	} else {
		data->ipv6_wds = qmi_service_ref(service);
	}

	wds_set_ip_family_pref(gc);
}

static void get_data_format_cb(struct qmi_result *result, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);
	uint32_t llproto;
	enum qmi_device_expected_data_format expected_llproto;

	DBG("");

	if (qmi_result_set_error(result, NULL))
		goto done;

	if (!qmi_result_get_uint32(result, QMI_WDA_LL_PROTOCOL, &llproto))
		goto done;

	expected_llproto = qmi_device_get_expected_data_format(data->dev);

	if ((llproto == QMI_WDA_DATA_LINK_PROTOCOL_802_3) &&
			(expected_llproto ==
				QMI_DEVICE_EXPECTED_DATA_FORMAT_RAW_IP)) {
		if (!qmi_device_set_expected_data_format(data->dev,
					QMI_DEVICE_EXPECTED_DATA_FORMAT_802_3))
			DBG("Fail to set expected data to 802.3");
		else
			DBG("expected data set to 802.3");
	} else if ((llproto == QMI_WDA_DATA_LINK_PROTOCOL_RAW_IP) &&
			(expected_llproto ==
				QMI_DEVICE_EXPECTED_DATA_FORMAT_802_3)) {
		if (!qmi_device_set_expected_data_format(data->dev,
					QMI_DEVICE_EXPECTED_DATA_FORMAT_RAW_IP))
			DBG("Fail to set expected data to raw-ip");
		else
			DBG("expected data set to raw-ip");
	}

done:
	data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
	qmi_service_create_shared(data->dev, QMI_SERVICE_WDS, create_wds_cb, gc,
									NULL);
}

static void create_wda_cb(struct qmi_service *service, void *user_data)
{
	struct ofono_gprs_context *gc = user_data;
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	if (!service) {
		DBG("Failed to request WDA service, continue initialization");
		goto error;
	}

	data->wda = qmi_service_ref(service);

	if (qmi_service_send(data->wda, QMI_WDA_GET_DATA_FORMAT, NULL,
					get_data_format_cb, gc, NULL) > 0)
		return;

error:
	data->ip_family = QMI_WDS_IP_FAMILY_IPV4;
	qmi_service_create_shared(data->dev, QMI_SERVICE_WDS, create_wds_cb, gc,
									NULL);
}

static int qmi_gprs_context_probe(struct ofono_gprs_context *gc,
					unsigned int vendor, void *user_data)
{
	struct qmi_device *device = user_data;
	struct gprs_context_data *data;

	DBG("");

	data = g_new0(struct gprs_context_data, 1);

	ofono_gprs_context_set_data(gc, data);
	data->dev = device;

	qmi_service_create(device, QMI_SERVICE_WDA, create_wda_cb, gc, NULL);

	return 0;
}

static void qmi_gprs_context_remove(struct ofono_gprs_context *gc)
{
	struct gprs_context_data *data = ofono_gprs_context_get_data(gc);

	DBG("");

	ofono_gprs_context_set_data(gc, NULL);

	if (data->ipv4_wds) {
		qmi_service_unregister_all(data->ipv4_wds);
		qmi_service_unref(data->ipv4_wds);
	}

	if (data->ipv6_wds) {
		qmi_service_unregister_all(data->ipv6_wds);
		qmi_service_unref(data->ipv6_wds);
	}

	if (data->wda) {
		qmi_service_unregister_all(data->wda);
		qmi_service_unref(data->wda);
	}

	g_free(data);
}

static const struct ofono_gprs_context_driver driver = {
	.name			= "qmimodem",
	.probe			= qmi_gprs_context_probe,
	.remove			= qmi_gprs_context_remove,
	.activate_primary	= qmi_activate_primary,
	.deactivate_primary	= qmi_deactivate_primary,
//	.read_settings		= qmi_gprs_read_settings,
	.detach_shutdown	= qmi_gprs_context_detach_shutdown,
};

void qmi_gprs_context_init(void)
{
	ofono_gprs_context_driver_register(&driver);
}

void qmi_gprs_context_exit(void)
{
	ofono_gprs_context_driver_unregister(&driver);
}
