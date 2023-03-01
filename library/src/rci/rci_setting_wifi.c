/*
 * Copyright (c) 2017-2022 Digi International Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Digi International Inc., 9350 Excelsior Blvd., Suite 700, Hopkins, MN 55343
 * ===========================================================================
 */

#include <libdigiapix/wifi.h>
#include <stdio.h>

#include "rci_setting_wifi.h"
#include "cc_logging.h"
#include "network_utils.h"

#define INTERFACE_NAME		"wlan0"

typedef struct {
	wifi_state_t info;
	char ipaddr_buff[IP_STRING_LENGTH];
	char submask_buff[IP_STRING_LENGTH];
	char dns1_buff[IP_STRING_LENGTH];
	char dns2_buff[IP_STRING_LENGTH];
	char gw_buff[IP_STRING_LENGTH];
	char mac_addr_buff[MAC_STRING_LENGTH];
} rci_iface_info_t;

static rci_iface_info_t *wifi_iface_info;

ccapi_setting_wifi_error_id_t rci_setting_wifi_start(ccapi_rci_info_t * const info)
{
	ccapi_setting_wifi_error_id_t ret = CCAPI_SETTING_WIFI_ERROR_NONE;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	wifi_iface_info = (rci_iface_info_t *) malloc(sizeof(rci_iface_info_t));
	if (wifi_iface_info == NULL) {
		log_error("%s: Cannot allocate memory", __func__);
		ret = CCAPI_SETTING_WIFI_ERROR_MEMORY_FAIL;
		goto done;
	}

	if (ldx_wifi_get_iface_state(INTERFACE_NAME, &(wifi_iface_info->info)) != 0)
		log_error("%s: get_iface_info failed", __func__);

done:
	return ret;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_end(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	free(wifi_iface_info);
	wifi_iface_info = NULL;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_iface_name_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = INTERFACE_NAME;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_enabled_get(ccapi_rci_info_t * const info, ccapi_on_off_t * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = wifi_iface_info->info.net_state.status == NET_STATUS_CONNECTED ? CCAPI_ON : CCAPI_OFF;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_ssid_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = wifi_iface_info->info.ssid;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_wpa_status_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = "UNKNOWN";

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

#if (defined RCI_ENUMS_AS_STRINGS)
ccapi_setting_wifi_error_id_t rci_setting_wifi_conn_type_get(ccapi_rci_info_t * const info, char const * * const value)
#else
ccapi_setting_wifi_error_id_t rci_setting_wifi_conn_type_get(ccapi_rci_info_t * const info, ccapi_setting_wifi_conn_type_id_t * const value)
#endif /* RCI_ENUMS_AS_STRINGS */
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

#if (defined RCI_ENUMS_AS_STRINGS)
	*value = (wifi_iface_info->info.net_state.is_dhcp == NET_ENABLED ? "DHCP" : "static");
#else
	*value = (wifi_iface_info->info.net_state.is_dhcp == NET_ENABLED ? CCAPI_SETTING_WIFI_CONN_TYPE_DHCP : CCAPI_SETTING_WIFI_CONN_TYPE_STATIC);
#endif /* RCI_ENUMS_AS_STRINGS */

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_ipaddr_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const ip = wifi_iface_info->info.net_state.ipv4;

	snprintf(wifi_iface_info->ipaddr_buff, IP_STRING_LENGTH, IP_FORMAT,
			ip[0], ip[1], ip[2], ip[3]);
	*value = wifi_iface_info->ipaddr_buff;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_netmask_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const netmask = wifi_iface_info->info.net_state.netmask;

	snprintf(wifi_iface_info->submask_buff, IP_STRING_LENGTH, IP_FORMAT,
			netmask[0], netmask[1], netmask[2], netmask[3]);
	*value = wifi_iface_info->submask_buff;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_dns1_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const dns1 = wifi_iface_info->info.net_state.dns1;

	snprintf(wifi_iface_info->dns1_buff, IP_STRING_LENGTH, IP_FORMAT,
			dns1[0], dns1[1], dns1[2], dns1[3]);
	*value = wifi_iface_info->dns1_buff;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_dns2_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const dns2 = wifi_iface_info->info.net_state.dns2;

	snprintf(wifi_iface_info->dns2_buff, IP_STRING_LENGTH, IP_FORMAT,
			dns2[0], dns2[1], dns2[2], dns2[3]);
	*value = wifi_iface_info->dns2_buff;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_gateway_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const gateway = wifi_iface_info->info.net_state.gateway;

	snprintf(wifi_iface_info->gw_buff, IP_STRING_LENGTH, IP_FORMAT,
			gateway[0], gateway[1], gateway[2], gateway[3]);
	*value = wifi_iface_info->gw_buff;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}

ccapi_setting_wifi_error_id_t rci_setting_wifi_mac_addr_get(ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const mac = wifi_iface_info->info.net_state.mac;

	snprintf(wifi_iface_info->mac_addr_buff, MAC_STRING_LENGTH, MAC_FORMAT,
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	*value = wifi_iface_info->mac_addr_buff;

	return CCAPI_SETTING_WIFI_ERROR_NONE;
}
