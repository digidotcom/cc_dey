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

#include <stdio.h>

#include "rci_state_primary_interface.h"
#include "cc_config.h"
#include "cc_logging.h"
#include "network_utils.h"

static char *iface_ip;
static char *iface_name;

extern cc_cfg_t *cc_cfg;

ccapi_state_primary_interface_error_id_t rci_state_primary_interface_start(
		ccapi_rci_info_t * const info)
{
	ccapi_state_primary_interface_error_id_t ret = CCAPI_STATE_PRIMARY_INTERFACE_ERROR_NONE;
	net_state_t net_state;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (get_main_iface_info(cc_cfg->url, &net_state) != 0) {
		ret = CCAPI_STATE_PRIMARY_INTERFACE_ERROR_LOAD_FAIL;
	} else {
		iface_name = strdup(net_state.name);
		iface_ip = malloc(IP_STRING_LENGTH * sizeof(char));
		snprintf(iface_ip, IP_STRING_LENGTH, "%d.%d.%d.%d",
				net_state.ipv4[0], net_state.ipv4[1],
				net_state.ipv4[2], net_state.ipv4[3]);
	}

	return ret;
}

ccapi_state_primary_interface_error_id_t rci_state_primary_interface_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	free(iface_ip);
	iface_ip = NULL;
	free(iface_name);
	iface_name = NULL;

	return CCAPI_STATE_PRIMARY_INTERFACE_ERROR_NONE;
}

ccapi_state_primary_interface_error_id_t rci_state_primary_interface_connection_type_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = iface_name;

	return CCAPI_STATE_PRIMARY_INTERFACE_ERROR_NONE;
}

ccapi_state_primary_interface_error_id_t rci_state_primary_interface_ip_addr_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = iface_ip;

	return CCAPI_STATE_PRIMARY_INTERFACE_ERROR_NONE;
}
