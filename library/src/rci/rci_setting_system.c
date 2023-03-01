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
#include "ccapi/ccapi.h"
#include "rci_setting_system.h"
#include "cc_logging.h"
#include "cc_config.h"

extern cc_cfg_t *cc_cfg;

ccapi_setting_system_error_id_t rci_setting_system_start(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}

ccapi_setting_system_error_id_t rci_setting_system_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}

ccapi_setting_system_error_id_t rci_setting_system_description_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = cc_cfg->description ? cc_cfg->description : "";

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}

ccapi_setting_system_error_id_t rci_setting_system_description_set(
		ccapi_rci_info_t * const info, char const * const value)
{
	UNUSED_PARAMETER(info);
	printf("    Called '%s'", __func__);

	free(cc_cfg->description);
	cc_cfg->description = strdup(value);

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}

ccapi_setting_system_error_id_t rci_setting_system_contact_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = cc_cfg->contact ? cc_cfg->contact : "";

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}

ccapi_setting_system_error_id_t rci_setting_system_contact_set(
		ccapi_rci_info_t * const info, char const * const value)
{
	UNUSED_PARAMETER(info);
	printf("    Called '%s'", __func__);

	free(cc_cfg->contact);
	cc_cfg->contact = strdup(value);

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}

ccapi_setting_system_error_id_t rci_setting_system_location_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = cc_cfg->location ? cc_cfg->location : "";

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}

ccapi_setting_system_error_id_t rci_setting_system_location_set(
		ccapi_rci_info_t * const info, char const * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	free(cc_cfg->location);
	cc_cfg->location = strdup(value);

	return CCAPI_SETTING_SYSTEM_ERROR_NONE;
}
