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
#include "rci_state_gps_stats.h"
#include "cc_logging.h"
#include "cc_config.h"

extern cc_cfg_t *cc_cfg;

#define FLOAT_MAX_LENGTH		(14)
static char *latitude_state;
static char *longitude_state;

ccapi_state_gps_stats_error_id_t rci_state_gps_stats_start(
		ccapi_rci_info_t * const info)
{
	ccapi_state_gps_stats_error_id_t ret = CCAPI_STATE_GPS_STATS_ERROR_NONE;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	latitude_state = malloc(FLOAT_MAX_LENGTH * sizeof(char));
	if (latitude_state == NULL) {
		ret = CCAPI_STATE_GPS_STATS_ERROR_MEMORY_FAIL;
		goto out;
	}

	longitude_state = malloc(FLOAT_MAX_LENGTH * sizeof(char));
	if (latitude_state == NULL) {
		ret = CCAPI_STATE_GPS_STATS_ERROR_MEMORY_FAIL;
		goto out;
	}

	out: return ret;
}

ccapi_state_gps_stats_error_id_t rci_state_gps_stats_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	free(latitude_state);
	latitude_state = NULL;
	free(longitude_state);
	longitude_state = NULL;

	return CCAPI_STATE_GPS_STATS_ERROR_NONE;
}

ccapi_state_gps_stats_error_id_t rci_state_gps_stats_latitude_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	ccapi_state_gps_stats_error_id_t ret = CCAPI_STATE_GPS_STATS_ERROR_NONE;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (cc_cfg->use_static_location == CCAPI_TRUE) {
		snprintf(latitude_state, FLOAT_MAX_LENGTH, "%f", cc_cfg->latitude);
		*value = latitude_state;
	} else {
		*value = "0.0";
	}

	return ret;
}

ccapi_state_gps_stats_error_id_t rci_state_gps_stats_longitude_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	ccapi_state_gps_stats_error_id_t ret = CCAPI_STATE_GPS_STATS_ERROR_NONE;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (cc_cfg->use_static_location == CCAPI_TRUE) {
		snprintf(longitude_state, FLOAT_MAX_LENGTH, "%f", cc_cfg->longitude);
		*value = longitude_state;
	} else {
		*value = "0.0";
	}

	return ret;
}
