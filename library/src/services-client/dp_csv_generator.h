/*
 * Copyright (c) 2023 Digi International Inc.
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

#ifndef _DP_CSV_GENERATOR_H_
#define _DP_CSV_GENERATOR_H_

#include <stddef.h>

#include "connector_api.h"
#include "ccimp/ccimp_types.h"
#include "stringify_tools.h"

/************************************************************************
** WARNING: Don't change the order of the state unless default		 **
**		  CSV format described in the Cloud documentation changes.   **
************************************************************************/
typedef enum {
	csv_data,
	csv_time,
	csv_quality,
	csv_description,
	csv_location,
	csv_type,
	csv_unit,
	csv_forward_to,
	csv_stream_id,
	csv_finished
} csv_field_t;

typedef enum {
	LOCATION_STATE_PUT_LEADING_QUOTE,
	LOCATION_STATE_INIT_LATITUDE,
	LOCATION_STATE_PUT_LATITUDE,
	LOCATION_STATE_PUT_1ST_COMMA,
	LOCATION_STATE_INIT_LONGITUDE,
	LOCATION_STATE_PUT_LONGITUDE,
	LOCATION_STATE_PUT_2ND_COMMA,
	LOCATION_STATE_INIT_ELEVATION,
	LOCATION_STATE_PUT_ELEVATION,
	LOCATION_STATE_PUT_TRAILING_QUOTE,
	LOCATION_STATE_FINISH
} location_state_t;

typedef enum {
	TIME_EPOCH_FRAC_STATE_SECONDS,
	TIME_EPOCH_FRAC_STATE_MILLISECONDS,
	TIME_EPOCH_FRAC_STATE_FINISH
} time_epoch_frac_state_t;

typedef struct {
	connector_data_stream_t const * current_data_stream;
	connector_data_point_t const * current_data_point;
	csv_field_t current_csv_field;

	struct {
		bool init;
		union {
			int_info_t intg;
			double_info_t dbl;
			string_info_t str;
		} info;
		union {
			location_state_t location;
			time_epoch_frac_state_t time;
		} internal_state;
	} data;
} csv_process_data_t;

size_t generate_dp_csv(csv_process_data_t * const csv_process_data, buffer_info_t * const buffer_info);

#endif /* _DP_CSV_GENERATOR_H_ */