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

#ifndef _CCAPI_DATAPOINTS_H_
#define _CCAPI_DATAPOINTS_H_

#include <stddef.h>
#include <stdint.h>

#define CCAPI_DP_WAIT_FOREVER		0UL

#define CCAPI_DP_KEY_DATA_INT32		"int32"
#define CCAPI_DP_KEY_DATA_INT64		"int64"
#define CCAPI_DP_KEY_DATA_FLOAT		"float"
#define CCAPI_DP_KEY_DATA_DOUBLE	"double"
#define CCAPI_DP_KEY_DATA_STRING	"string"
#define CCAPI_DP_KEY_DATA_JSON		"json"
#define CCAPI_DP_KEY_DATA_GEOJSON	"geojson"

#define CCAPI_DP_KEY_TS_EPOCH		"ts_epoch"
#define CCAPI_DP_KEY_TS_EPOCH_MS	"ts_epoch_ms"
#define CCAPI_DP_KEY_TS_ISO8601		"ts_iso"

#define CCAPI_DP_KEY_LOCATION		"loc"
#define CCAPI_DP_KEY_QUALITY		"qual"

typedef enum {
	CCAPI_DP_ERROR_NONE,
	CCAPI_DP_ERROR_INVALID_ARGUMENT,
	CCAPI_DP_ERROR_INVALID_STREAM_ID,
	CCAPI_DP_ERROR_INVALID_FORMAT,
	CCAPI_DP_ERROR_INVALID_UNITS,
	CCAPI_DP_ERROR_INVALID_FORWARD_TO,
	CCAPI_DP_ERROR_INSUFFICIENT_MEMORY,
	CCAPI_DP_ERROR_LOCK_FAILED,
	CCAPI_DP_ERROR_CCAPI_NOT_RUNNING,
	CCAPI_DP_ERROR_TRANSPORT_NOT_STARTED,
	CCAPI_DP_ERROR_INITIATE_ACTION_FAILED,
	CCAPI_DP_ERROR_RESPONSE_BAD_REQUEST,
	CCAPI_DP_ERROR_RESPONSE_UNAVAILABLE,
	CCAPI_DP_ERROR_RESPONSE_CLOUD_ERROR,
	CCAPI_DP_ERROR_STATUS_CANCEL,
	CCAPI_DP_ERROR_STATUS_TIMEOUT,
	CCAPI_DP_ERROR_STATUS_INVALID_DATA,
	CCAPI_DP_ERROR_STATUS_SESSION_ERROR
} ccapi_dp_error_t;

typedef struct {
	float latitude;
	float longitude;
	float elevation;
} ccapi_location_t;

typedef union {
	struct {
		uint32_t seconds;
		uint32_t milliseconds;
	} epoch;
	uint64_t epoch_msec;
	char const * iso8601;
} ccapi_timestamp_t;

typedef struct ccapi_dp_collection * ccapi_dp_collection_handle_t;
typedef struct ccapi_dp_data_stream * ccapi_dp_data_stream_handle_t;

ccapi_dp_error_t ccapi_dp_create_collection(ccapi_dp_collection_handle_t *const dp_collection);
ccapi_dp_error_t ccapi_dp_clear_collection(ccapi_dp_collection_handle_t const dp_collection);
ccapi_dp_error_t ccapi_dp_destroy_collection(ccapi_dp_collection_handle_t const dp_collection);

ccapi_dp_error_t ccapi_dp_add_data_stream_to_collection(ccapi_dp_collection_handle_t const dp_collection, char const * const stream_id, char const * const format_string);
ccapi_dp_error_t ccapi_dp_add_data_stream_to_collection_extra(ccapi_dp_collection_handle_t const dp_collection, char const * const stream_id, char const * const format_string, char const * const units, char const * const forward_to);
ccapi_dp_error_t ccapi_dp_remove_data_stream_from_collection(ccapi_dp_collection_handle_t const dp_collection, char const * const stream_id);
ccapi_dp_error_t ccapi_dp_get_collection_points_count(ccapi_dp_collection_handle_t const collection, uint32_t * const count);

ccapi_dp_error_t ccapi_dp_add(ccapi_dp_collection_handle_t const collection, char const * const stream_id, ...);
ccapi_dp_error_t ccapi_dp_remove_older_data_point_from_streams(ccapi_dp_collection_handle_t const collection);

#endif
