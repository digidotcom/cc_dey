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

#ifndef __CC_DATAPOINTS_H_
#define __CC_DATAPOINTS_H_

#include "services-client/dp_csv_generator.h"

typedef enum {
	CCCS_DP_ARG_DATA_INT32,
	CCCS_DP_ARG_DATA_INT64,
	CCCS_DP_ARG_DATA_FLOAT,
	CCCS_DP_ARG_DATA_DOUBLE,
	CCCS_DP_ARG_DATA_STRING,
	CCCS_DP_ARG_DATA_JSON,
	CCCS_DP_ARG_DATA_GEOJSON,
	CCCS_DP_ARG_TS_EPOCH,
	CCCS_DP_ARG_TS_EPOCH_MS,
	CCCS_DP_ARG_TS_ISO8601,
	CCCS_DP_ARG_LOCATION,
	CCCS_DP_ARG_QUALITY,
	CCCS_DP_ARG_INVALID
} cccs_dp_argument_t;

typedef struct cccs_dp_data_stream {
	connector_data_stream_t *ccfsm_data_stream;
	struct {
		cccs_dp_argument_t *list;
		unsigned int count;
	} arguments;
	struct cccs_dp_data_stream *next;
} cccs_dp_data_stream_t;

typedef struct ccapi_dp_collection {
	cccs_dp_data_stream_t *cccs_data_stream_list;
	uint32_t dp_count;
	void * lock;
} cccs_dp_collection_t;

/*
 * dp_generate_csv_from_collection() - Generate the CSV contents in memory to send to the daemon
 *
 * @collection:	Data point collection to send.
 * @buf_info:	The buffer with the generated CSV.
 * @max_dp:	Maximum number of data points to include in the CSV buffer.
 * @n_dp:	Number of data points included in the CSV buffer.
 *
 * Buffer contains the result of the operation. It must be freed.
 *
 * Return: The size of the CSV buffer, -1 if error.
 */
size_t dp_generate_csv_from_collection(cccs_dp_collection_t * const collection,
	buffer_info_t *buf_info, unsigned int max_dp, unsigned int *n_dp);

/*
 * dp_remove_from_collection() - Remove a number of data points from collection
 *
 * @collection:		Data point collection.
 * @n_to_remove:	Number of data points to remove. 0 to remove all.
 *
 * Return: The number of removed data points.
 */
unsigned int dp_remove_from_collection(cccs_dp_collection_t * const collection, unsigned int n_to_remove);

/*
 * dp_process_send_dp_error() - Handle data point send error
 *
 * @type:		Format of the data points information.
 * @error:		Error to process.
 * @buff:		Buffer with data points or absolute path of the file with them.
 * @size:		Size of the buffer (not used for file path).
 * @stream_id:		Stream data id to send data to for binary data points, otherwise not used.
 * @backlog_dir_path:	Absolute path of the directory to store samples if required.
 * @backlog_kb:		Maximum size (kb) of the data backlog.
 *
 * Depending on the 'error', data is stored inside 'backlog_dir_path' as a file.
 *
 * Return: 0 if success, 1 otherwise.
 */
int dp_process_send_dp_error(uint32_t type, unsigned int error,
	char const * const buff, size_t size, char const stream_id[],
	const char * const backlog_dir_path, uint32_t backlog_kb);

/*
 * dp_send_stored_data() - Send data stored in the provided backlog directory
 *
 * @backlog_dir_path:	Absolute path of the directory to look for data to send.
 *
 * Return: 0 if success, any other value otherwise.
 */
int dp_send_stored_data(char const * const backlog_dir_path);

#endif /* __CC_DATAPOINTS_H_ */