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

#include <math.h>
#include <stdio.h>
#include "rci_setting_static_location.h"
#include "cc_logging.h"
#include "cc_config.h"

extern cc_cfg_t *cc_cfg;

ccapi_setting_static_location_error_id_t rci_setting_static_location_start(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_use_static_location_get(
		ccapi_rci_info_t * const info, ccapi_on_off_t * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = (cc_cfg->use_static_location == CCAPI_TRUE ? CCAPI_ON : CCAPI_OFF);

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_use_static_location_set(
		ccapi_rci_info_t * const info, ccapi_on_off_t const * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	cc_cfg->use_static_location =
			(*value == CCAPI_ON ? CCAPI_TRUE : CCAPI_FALSE);

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_latitude_get(
		ccapi_rci_info_t * const info, float * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = cc_cfg->latitude;

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_latitude_set(
		ccapi_rci_info_t * const info, float const * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (isnan(*value))
		return CCAPI_SETTING_STATIC_LOCATION_ERROR_BAD_VALUE;

	cc_cfg->latitude = *value;

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_longitude_get(
		ccapi_rci_info_t * const info, float * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = cc_cfg->longitude;

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_longitude_set(
		ccapi_rci_info_t * const info, float const * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (isnan(*value))
		return CCAPI_SETTING_STATIC_LOCATION_ERROR_BAD_VALUE;

	cc_cfg->longitude = *value;

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_altitude_get(
		ccapi_rci_info_t * const info, float * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	*value = cc_cfg->altitude;

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}

ccapi_setting_static_location_error_id_t rci_setting_static_location_altitude_set(
		ccapi_rci_info_t * const info, float const * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (isnan(*value))
		return CCAPI_SETTING_STATIC_LOCATION_ERROR_BAD_VALUE;

	cc_cfg->altitude = *value;

	return CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE;
}
