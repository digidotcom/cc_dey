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

#include "dp_csv_generator.h"

static bool terminate_csv_field(csv_process_data_t * const csv_process_data, buffer_info_t * const buffer_info, csv_field_t const next_field)
{
	csv_process_data->data.init = false;
	if (put_character(',', buffer_info)) {
		csv_process_data->current_csv_field = next_field;
		return true;
	}

	return false;
}

static bool process_csv_data(csv_process_data_t * const csv_process_data, buffer_info_t * const buffer_info)
{
	connector_data_point_t const * const current_data_point = csv_process_data->current_data_point;
	connector_data_stream_t const * const current_data_stream = csv_process_data->current_data_stream;
	bool done_processing = false;

	if (!csv_process_data->data.init) {
		csv_process_data->data.init = true;

		switch (current_data_point->data.type) {
			case connector_data_type_text:
			{
				init_string_info(&csv_process_data->data.info.str, current_data_point->data.element.text);
				break;
			}
			case connector_data_type_native:
			{
				switch (current_data_stream->type) {
					case connector_data_point_type_string:
					case connector_data_point_type_geojson:
					case connector_data_point_type_json:
					case connector_data_point_type_binary:
					{
						init_string_info(&csv_process_data->data.info.str, current_data_point->data.element.native.string_value);
						break;
					}
					case connector_data_point_type_double:
					{
						init_double_info(&csv_process_data->data.info.dbl, current_data_point->data.element.native.double_value);
						break;
					}
					case connector_data_point_type_float:
					{
						init_double_info(&csv_process_data->data.info.dbl, current_data_point->data.element.native.float_value);
						break;
					}
					case connector_data_point_type_integer:
					{
						init_int_info(&csv_process_data->data.info.intg, current_data_point->data.element.native.int_value, 10);
						break;
					}
					case connector_data_point_type_long:
					{
						init_int_info(&csv_process_data->data.info.intg, current_data_point->data.element.native.long_value, 10);
						break;
					}

				}
				break;
			}
		}
	}

	switch (current_data_point->data.type) {
		case connector_data_type_text:
			done_processing = process_string(&csv_process_data->data.info.str, buffer_info);
			break;
		case connector_data_type_native:
			switch (current_data_stream->type) {
				case connector_data_point_type_string:
				case connector_data_point_type_geojson:
				case connector_data_point_type_json:
				case connector_data_point_type_binary:
					done_processing = process_string(&csv_process_data->data.info.str, buffer_info);
					break;
				case connector_data_point_type_double:
				case connector_data_point_type_float:
					done_processing = process_double(&csv_process_data->data.info.dbl, buffer_info);
					break;
				case connector_data_point_type_long:
					/* Intentional fall through */
				case connector_data_point_type_integer:
					done_processing = process_integer(&csv_process_data->data.info.intg, buffer_info);
					break;
			}
			break;
	}

	return done_processing;
}

/* 0- not done
1 - done
2 - error */
static int process_csv_location(csv_process_data_t * const csv_process_data, buffer_info_t * const buffer_info)
{
	connector_data_point_t const * const current_data_point = csv_process_data->current_data_point;
	bool done_processing = 0;

	switch (current_data_point->location.type) {
		case connector_location_type_ignore:
		{
			done_processing = 1;
			break;
		}
		case connector_location_type_text:
		case connector_location_type_native:
		{
			if (!csv_process_data->data.init) {
				csv_process_data->data.init = true;
				csv_process_data->data.internal_state.location = LOCATION_STATE_PUT_LEADING_QUOTE;
			}
			switch (csv_process_data->data.internal_state.location) {
				case LOCATION_STATE_PUT_LEADING_QUOTE:
				case LOCATION_STATE_PUT_TRAILING_QUOTE:
				{
					if (put_character('\"', buffer_info))
						csv_process_data->data.internal_state.location++;
					else
						done_processing = 2;
					break;
				}
				case LOCATION_STATE_INIT_LATITUDE:
				{
					if (current_data_point->location.type == connector_location_type_native) {
						init_double_info(&csv_process_data->data.info.dbl, current_data_point->location.value.native.latitude);
					} else {
						init_string_info(&csv_process_data->data.info.str, current_data_point->location.value.text.latitude);
						ClearQuotesNeeded(csv_process_data->data.info.str.quotes_info);
					}
					csv_process_data->data.internal_state.location++;
					break;
				}
				case LOCATION_STATE_INIT_LONGITUDE:
				{
					if (current_data_point->location.type == connector_location_type_native) {
						init_double_info(&csv_process_data->data.info.dbl, current_data_point->location.value.native.longitude);
					} else {
						init_string_info(&csv_process_data->data.info.str, current_data_point->location.value.text.longitude);
						ClearQuotesNeeded(csv_process_data->data.info.str.quotes_info);
					}
					csv_process_data->data.internal_state.location++;
					break;
				}
				case LOCATION_STATE_INIT_ELEVATION:
				{
					if (current_data_point->location.type == connector_location_type_native) {
						init_double_info(&csv_process_data->data.info.dbl, current_data_point->location.value.native.elevation);
					} else {
						init_string_info(&csv_process_data->data.info.str, current_data_point->location.value.text.elevation);
						ClearQuotesNeeded(csv_process_data->data.info.str.quotes_info);
					}
					csv_process_data->data.internal_state.location++;
					break;
				}
				case LOCATION_STATE_PUT_LATITUDE:
				case LOCATION_STATE_PUT_LONGITUDE:
				case LOCATION_STATE_PUT_ELEVATION:
				{
					bool field_done;

					if (current_data_point->location.type == connector_location_type_native)
						field_done = process_double(&csv_process_data->data.info.dbl, buffer_info);
					else
						field_done = process_string(&csv_process_data->data.info.str, buffer_info);

					if (field_done)
						csv_process_data->data.internal_state.location++;
					break;
				}
				case LOCATION_STATE_PUT_1ST_COMMA:
				case LOCATION_STATE_PUT_2ND_COMMA:
				{
					if (put_character(',', buffer_info))
						csv_process_data->data.internal_state.location++;
					else
						done_processing = 2;
					break;
				}
				case LOCATION_STATE_FINISH:
					done_processing = 1;
					break;
			}
			break;
		}
	}

	return done_processing;
}

static bool process_csv_time(csv_process_data_t * const csv_process_data, buffer_info_t * const buffer_info)
{
	connector_data_point_t const * const current_data_point = csv_process_data->current_data_point;
	bool done_processing = false;

	switch (current_data_point->time.source) {
		case connector_time_cloud:
			done_processing = true;
			break;
		case connector_time_local_epoch_fractional:
		{
			if (!csv_process_data->data.init) {
				csv_process_data->data.init = true;
				init_int_info(&csv_process_data->data.info.intg, current_data_point->time.value.since_epoch_fractional.seconds, 10);
				csv_process_data->data.internal_state.time = TIME_EPOCH_FRAC_STATE_SECONDS;
			}

			switch (csv_process_data->data.internal_state.time) {
				case TIME_EPOCH_FRAC_STATE_SECONDS:
				case TIME_EPOCH_FRAC_STATE_MILLISECONDS:
				{
					bool const field_done = process_integer(&csv_process_data->data.info.intg, buffer_info);

					if (field_done) {
						init_int_info(&csv_process_data->data.info.intg, current_data_point->time.value.since_epoch_fractional.milliseconds, 10);
						csv_process_data->data.info.intg.figures = 3; /* Always add leading zeroes, i.e. 1 millisecond must be "001" */
						csv_process_data->data.internal_state.time++;
					}
					break;
				}
				case TIME_EPOCH_FRAC_STATE_FINISH:
					done_processing = true;
					break;
			}
			break;
		}
		case connector_time_local_epoch_whole:
		{
			if (!csv_process_data->data.init) {
				csv_process_data->data.init = true;
				init_int_info(&csv_process_data->data.info.intg, current_data_point->time.value.since_epoch_whole.milliseconds, 10);
			}

			done_processing = process_integer(&csv_process_data->data.info.intg, buffer_info);
			break;
		}
		case connector_time_local_iso8601:
		{
			if (!csv_process_data->data.init) {
				csv_process_data->data.init = true;
				init_string_info(&csv_process_data->data.info.str, current_data_point->time.value.iso8601_string);
			}
			done_processing = process_string(&csv_process_data->data.info.str, buffer_info);
			break;
		}
	}

	return done_processing;
}

size_t generate_dp_csv(csv_process_data_t * const csv_process_data, buffer_info_t * const buffer_info)
{
	while (csv_process_data->current_data_point != NULL) {
		connector_data_point_t const * const current_data_point = csv_process_data->current_data_point;
		connector_data_stream_t const * const current_data_stream = csv_process_data->current_data_stream;

		switch (csv_process_data->current_csv_field) {
			case csv_data:
			{
				bool const done_processing = process_csv_data(csv_process_data, buffer_info);

				if (done_processing
					&& !terminate_csv_field(csv_process_data, buffer_info, csv_time))
					goto error;
				break;
			}
			case csv_time:
			{
				bool const done_processing = process_csv_time(csv_process_data, buffer_info);

				if (done_processing &&
					!terminate_csv_field(csv_process_data, buffer_info, csv_quality))
					goto error;
				break;
			}
			case csv_quality:
			{
				bool done_processing = false;

				switch (current_data_point->quality.type) {
					case connector_quality_type_ignore:
					{
						done_processing = true;
						break;
					}
					case connector_quality_type_native:
					{
						if (!csv_process_data->data.init) {
							csv_process_data->data.init = true;
							init_int_info(&csv_process_data->data.info.intg, current_data_point->quality.value, 10);
						}

						done_processing = process_integer(&csv_process_data->data.info.intg, buffer_info);
						break;
					}
				}

				if (done_processing
					&& !terminate_csv_field(csv_process_data, buffer_info, csv_description))
					goto error;
				break;
			}

			case csv_location:
			{
				int const done_processing = process_csv_location(csv_process_data, buffer_info);

				switch(done_processing) {
					case 0:
						break;
					case 1:
						if (!terminate_csv_field(csv_process_data, buffer_info, csv_type))
							goto error;
						break;
					case 2:
						goto error;
				}

				break;
			}

			case csv_type:
			case csv_description:
			case csv_unit:
			case csv_forward_to:
			case csv_stream_id:
			{
				bool done_processing;

				if (!csv_process_data->data.init) {
					char const * string = NULL;

					switch (csv_process_data->current_csv_field) {
						case csv_description:
							string = current_data_point->description;
							break;
						case csv_type:
						{
							static char const * const type_list[] = {"INTEGER", "LONG", "FLOAT", "DOUBLE", "STRING", "BINARY", "JSON", "GEOJSON"};
							string = type_list[csv_process_data->current_data_stream->type];
							break;
						}
						case csv_unit:
							string = current_data_stream->unit;
							break;
						case csv_forward_to:
							string = current_data_stream->forward_to;
							break;
						case csv_stream_id:
							string = current_data_stream->stream_id;
							break;
						default:
							assert(0);
							break;
					}

					csv_process_data->data.init = true;
					init_string_info(&csv_process_data->data.info.str, string);
				}

				done_processing = process_string(&csv_process_data->data.info.str, buffer_info);

				if (done_processing) {
					csv_process_data->data.init = false;
					csv_process_data->current_csv_field++;

					assert(csv_process_data->current_csv_field <= csv_finished);

					if (csv_process_data->current_csv_field != csv_finished)
						if (!put_character(',', buffer_info))
							goto error;
				}
				break;
			}

			case csv_finished:
			{
				if (!put_character('\n', buffer_info))
					goto error;
				
				csv_process_data->current_data_point = current_data_point->next;

				if (csv_process_data->current_data_point == NULL) {
					csv_process_data->current_data_stream = csv_process_data->current_data_stream->next;

					if (csv_process_data->current_data_stream != NULL)
						csv_process_data->current_data_point = csv_process_data->current_data_stream->point;
				}

				csv_process_data->current_csv_field = csv_data;
				csv_process_data->data.init = false;
				break;
			}
		}
	}

	return buffer_info->bytes_written;

error:
	free(buffer_info->buffer);
	buffer_info->buffer = NULL;
	buffer_info->bytes_available = 0;
	buffer_info->bytes_written = -1;

	return buffer_info->bytes_written;
}