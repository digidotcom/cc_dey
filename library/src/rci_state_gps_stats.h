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

#ifndef rci_state_gps_stats_h
#define rci_state_gps_stats_h

#include "connector_api.h"
#include "ccapi_rci_functions.h"

typedef enum {
	CCAPI_STATE_GPS_STATS_ERROR_NONE,
	CCAPI_STATE_GPS_STATS_ERROR_BAD_COMMAND = 1, /* PROTOCOL DEFINED */
	CCAPI_STATE_GPS_STATS_ERROR_BAD_DESCRIPTOR,
	CCAPI_STATE_GPS_STATS_ERROR_BAD_VALUE,
	CCAPI_STATE_GPS_STATS_ERROR_LOAD_FAIL, /* USER DEFINED (GLOBAL ERRORS) */
	CCAPI_STATE_GPS_STATS_ERROR_SAVE_FAIL,
	CCAPI_STATE_GPS_STATS_ERROR_MEMORY_FAIL,
	CCAPI_STATE_GPS_STATS_ERROR_NOT_IMPLEMENTED,
	CCAPI_STATE_GPS_STATS_ERROR_COUNT
} ccapi_state_gps_stats_error_id_t;

ccapi_state_gps_stats_error_id_t rci_state_gps_stats_start(
		ccapi_rci_info_t * const info);
ccapi_state_gps_stats_error_id_t rci_state_gps_stats_end(
		ccapi_rci_info_t * const info);

ccapi_state_gps_stats_error_id_t rci_state_gps_stats_latitude_get(
		ccapi_rci_info_t * const info, char const * * const value);
#define rci_state_gps_stats_latitude_set    NULL

ccapi_state_gps_stats_error_id_t rci_state_gps_stats_longitude_get(
		ccapi_rci_info_t * const info, char const * * const value);
#define rci_state_gps_stats_longitude_set    NULL

#endif
