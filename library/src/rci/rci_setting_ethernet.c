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

#include <libdigiapix/network.h>
#include <stdio.h>

#include "rci_setting_ethernet.h"
#include "cc_logging.h"
#include "network_utils.h"

static const char * eth_iface_name[] = { "eth0", "eth1" };

typedef struct {
	net_state_t info;
	char ipaddr_buff[IP_STRING_LENGTH];
	char submask_buff[IP_STRING_LENGTH];
	char dns1_buff[IP_STRING_LENGTH];
	char dns2_buff[IP_STRING_LENGTH];
	char gw_buff[IP_STRING_LENGTH];
	char mac_addr_buff[MAC_STRING_LENGTH];
} rci_iface_info_t;

static rci_iface_info_t *eth_iface_info;

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_start(
		ccapi_rci_info_t * const info)
{
	ccapi_setting_ethernet_error_id_t ret = CCAPI_SETTING_ETHERNET_ERROR_NONE;
	unsigned int iface_index = info->group.item.index - 1;
	log_debug("    Called '%s'\n", __func__);

	if (iface_index >= ARRAY_SIZE(eth_iface_name)) {
		log_error("%s: Interface index %u beyond maximum index %u", __func__,
				iface_index,
				(unsigned int)ARRAY_SIZE(eth_iface_name));
		ret = CCAPI_SETTING_ETHERNET_ERROR_LOAD_FAIL;
		goto done;
	}

	eth_iface_info = (rci_iface_info_t *) malloc(sizeof(rci_iface_info_t));
	if (eth_iface_info == NULL) {
		log_error("%s: Cannot allocate memory", __func__);
		ret = CCAPI_SETTING_ETHERNET_ERROR_MEMORY_FAIL;
		goto done;
	}

	if (ldx_net_get_iface_state(eth_iface_name[iface_index], &(eth_iface_info->info)) != 0)
		log_error("%s: get_iface_info failed", __func__);

done:
	return ret;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	free(eth_iface_info);
	eth_iface_info = NULL;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_iface_name_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = eth_iface_info->info.name;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_enabled_get(
		ccapi_rci_info_t * const info, ccapi_on_off_t * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = eth_iface_info->info.status == NET_STATUS_CONNECTED ? CCAPI_ON : CCAPI_OFF;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

#if (defined RCI_ENUMS_AS_STRINGS)
ccapi_setting_ethernet_error_id_t rci_setting_ethernet_conn_type_get(
		ccapi_rci_info_t * const info, char const * * const value)
#else
ccapi_setting_ethernet_error_id_t rci_setting_ethernet_conn_type_get(
		ccapi_rci_info_t * const info, ccapi_setting_ethernet_conn_type_id_t * const value)
#endif /* RCI_ENUMS_AS_STRINGS */
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
#if (defined RCI_ENUMS_AS_STRINGS)
	*value = (eth_iface_info->info.is_dhcp == NET_ENABLED ? "DHCP" : "static");
#else
	*value = (eth_iface_info->info.is_dhcp == NET_ENABLED ? CCAPI_SETTING_ETHERNET_CONN_TYPE_DHCP : CCAPI_SETTING_ETHERNET_CONN_TYPE_STATIC);
#endif /* RCI_ENUMS_AS_STRINGS */
	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_ipaddr_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const ip = eth_iface_info->info.ipv4;

	snprintf(eth_iface_info->ipaddr_buff, IP_STRING_LENGTH, IP_FORMAT,
			ip[0], ip[1], ip[2], ip[3]);
	*value = eth_iface_info->ipaddr_buff;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_netmask_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const netmask = eth_iface_info->info.netmask;

	snprintf(eth_iface_info->submask_buff, IP_STRING_LENGTH, IP_FORMAT,
			netmask[0], netmask[1], netmask[2], netmask[3]);
	*value = eth_iface_info->submask_buff;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_dns1_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const dns1 = eth_iface_info->info.dns1;

	snprintf(eth_iface_info->dns1_buff, IP_STRING_LENGTH, IP_FORMAT,
			dns1[0], dns1[1], dns1[2], dns1[3]);
	*value = eth_iface_info->dns1_buff;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_dns2_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const dns2 = eth_iface_info->info.dns2;

	snprintf(eth_iface_info->dns2_buff, IP_STRING_LENGTH, IP_FORMAT,
			dns2[0], dns2[1], dns2[2], dns2[3]);
	*value = eth_iface_info->dns2_buff;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_gateway_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const gateway = eth_iface_info->info.gateway;

	snprintf(eth_iface_info->gw_buff, IP_STRING_LENGTH, IP_FORMAT,
			gateway[0], gateway[1], gateway[2], gateway[3]);
	*value = eth_iface_info->gw_buff;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}

ccapi_setting_ethernet_error_id_t rci_setting_ethernet_mac_addr_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);
	uint8_t const * const mac = eth_iface_info->info.mac;

	snprintf(eth_iface_info->mac_addr_buff, MAC_STRING_LENGTH, MAC_FORMAT,
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	*value = eth_iface_info->mac_addr_buff;

	return CCAPI_SETTING_ETHERNET_ERROR_NONE;
}
