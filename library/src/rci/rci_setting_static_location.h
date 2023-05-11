/*
 * Copyright (c) 2017-2023 Digi International Inc.
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

#ifndef rci_setting_static_location_h
#define rci_setting_static_location_h

#ifdef ENABLE_RCI

#include "connector_api.h"
#include "ccapi_rci_functions.h"

typedef enum {
	CCAPI_SETTING_STATIC_LOCATION_ERROR_NONE,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_BAD_COMMAND, /* PROTOCOL DEFINED */
	CCAPI_SETTING_STATIC_LOCATION_ERROR_BAD_DESCRIPTOR,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_BAD_VALUE,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_INVALID_INDEX,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_INVALID_NAME,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_MISSING_NAME,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_LOAD_FAIL, /* USER DEFINED (GLOBAL ERRORS) */
	CCAPI_SETTING_STATIC_LOCATION_ERROR_SAVE_FAIL,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_MEMORY_FAIL,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_NOT_IMPLEMENTED,
	CCAPI_SETTING_STATIC_LOCATION_ERROR_COUNT
} ccapi_setting_static_location_error_id_t;

ccapi_setting_static_location_error_id_t rci_setting_static_location_start(
		ccapi_rci_info_t * const info);
ccapi_setting_static_location_error_id_t rci_setting_static_location_end(
		ccapi_rci_info_t * const info);

ccapi_setting_static_location_error_id_t rci_setting_static_location_use_static_location_get(
		ccapi_rci_info_t * const info, ccapi_on_off_t * const value);
ccapi_setting_static_location_error_id_t rci_setting_static_location_use_static_location_set(
		ccapi_rci_info_t * const info, ccapi_on_off_t const * const value);

ccapi_setting_static_location_error_id_t rci_setting_static_location_latitude_get(
		ccapi_rci_info_t * const info, float * const value);
ccapi_setting_static_location_error_id_t rci_setting_static_location_latitude_set(
		ccapi_rci_info_t * const info, float const * const value);

ccapi_setting_static_location_error_id_t rci_setting_static_location_longitude_get(
		ccapi_rci_info_t * const info, float * const value);
ccapi_setting_static_location_error_id_t rci_setting_static_location_longitude_set(
		ccapi_rci_info_t * const info, float const * const value);

ccapi_setting_static_location_error_id_t rci_setting_static_location_altitude_get(
		ccapi_rci_info_t * const info, float * const value);
ccapi_setting_static_location_error_id_t rci_setting_static_location_altitude_set(
		ccapi_rci_info_t * const info, float const * const value);

#endif /* ENABLE_RCI */

#endif
