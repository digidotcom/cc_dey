/*
 * Copyright (c) 2022, 2023 Digi International Inc.
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

#include <errno.h>
#include <stdio.h>

#include "ccapi/ccapi.h"
#include "_cc_datapoints.h"
#include "cc_logging.h"
#include "cc_error_msg.h"
#include "service_dp_upload.h"
#include "services_util.h"
#include "services-client/cccs_definitions.h"
#include "_utils.h"

static ccapi_send_error_t upload_datapoint_file(uint32_t type,
	char const * const buff, size_t size,
	char const cloud_path[],
	ccapi_string_info_t * const hint_string_info,
	ccapi_optional_uint8_t *err_from_server)
{
#define TIMEOUT 5
	ccapi_send_error_t send_error = CCAPI_SEND_ERROR_NONE;
	char const file_type[] = "text/plain";

	switch (type) {
		case upload_datapoint_file_events:
		case upload_datapoint_file_metrics:
			send_error = ccapi_send_data_with_reply_and_errorcode(CCAPI_TRANSPORT_TCP,
				cloud_path, file_type, buff, size,
				CCAPI_SEND_BEHAVIOR_OVERWRITE, TIMEOUT, hint_string_info, err_from_server);
			break;
		case upload_datapoint_file_path_metrics:
			send_error = ccapi_send_file_with_reply_and_errorcode(CCAPI_TRANSPORT_TCP,
				buff /* Local path */, cloud_path, file_type,
				CCAPI_SEND_BEHAVIOR_OVERWRITE, TIMEOUT, hint_string_info, err_from_server);
			break;
		default:
			/* Should not occur */
			break;
	}

	if (send_error != CCAPI_SEND_ERROR_NONE)
		log_error("Send error: %d Hint: %s", send_error, hint_string_info->string);

	return send_error;
#undef TIMEOUT
}

static ccapi_dp_b_error_t upload_binary_datapoint(uint32_t type,
	char const * const buff, size_t size,
	char const stream_id[],
	ccapi_string_info_t * const hint_string_info,
	ccapi_optional_uint8_t *err_from_server)
{
#define TIMEOUT 5
	ccapi_dp_b_error_t send_error = CCAPI_DP_B_ERROR_NONE;

	switch (type) {
		case upload_datapoint_file_metrics_binary:
			send_error = ccapi_dp_binary_send_data_with_reply_and_errorcode(CCAPI_TRANSPORT_TCP,
				stream_id, buff, size,
				TIMEOUT, hint_string_info, err_from_server);
			break;
		case upload_datapoint_file_path_binary:
			send_error = ccapi_dp_binary_send_file_with_reply_and_errorcode(CCAPI_TRANSPORT_TCP,
				buff, stream_id,
				TIMEOUT, hint_string_info, err_from_server);
			break;
		default:
			/* Should not occur */
			break;
	}

	if (send_error != CCAPI_DP_B_ERROR_NONE)
		log_error("Send binary error: %d Hint: %s", send_error, hint_string_info->string);

	return send_error;
#undef TIMEOUT
}

int handle_datapoint_file_upload(int fd, const cc_cfg_t *const cc_cfg)
{
	while (1) {
		int ret, cccs_err = 0;
		uint32_t type;
		size_t size;
		void *blob = NULL;
		char *file_path = NULL, *stream_id = NULL, *cloud_path = NULL;
		char const * err_msg = NULL;
		struct timeval timeout = {
			.tv_sec = SOCKET_READ_TIMEOUT_SEC,
			.tv_usec = 0
		};
		char hint[256];
		ccapi_string_info_t hint_string_info;
		ccapi_optional_uint8_t err_from_server = {
			.known = false,
			.value = 0
		};

		hint[0] = '\0';
		hint_string_info.length = sizeof hint;
		hint_string_info.string = hint;

		/* Read the record type from the client message */
		ret = read_uint32(fd, &type, &timeout);
		if (ret == -ETIMEDOUT)
			send_error_codes(fd, "Timeout reading data type",
				0, 0, CCCS_SEND_ERROR_READ_TIMEOUT);
		else if (ret)
			send_error_codes(fd, "Failed to read data type",
				0, 0, CCCS_SEND_ERROR_READ_ERROR);

		if (ret)
			return 1;

		if (type == upload_datapoint_file_terminate)
			break;

		if (type != upload_datapoint_file_metrics
			&& type != upload_datapoint_file_events
			&& type != upload_datapoint_file_path_metrics
			&& type != upload_datapoint_file_path_binary
			&& type != upload_datapoint_file_metrics_binary) {
			send_error_codes(fd, "Invalid data type",
				0, 0, CCCS_SEND_ERROR_BAD_RESPONSE);

			return 1;
		}

		/* Read data point(s) blob/file path */
		switch (type) {
			case upload_datapoint_file_path_metrics:
			case upload_datapoint_file_path_binary:
				/* Read data point(s) file path */
				ret = read_string(fd, &file_path, NULL, &timeout);
				if (ret == -ETIMEDOUT)
					send_error_codes(fd, "Timeout reading data point file path",
						0, 0, CCCS_SEND_ERROR_READ_TIMEOUT);
				else if (ret == -ENOMEM)
					send_error_codes(fd, "Failed to read data point file path: Out of memory",
						0, 0, CCCS_SEND_ERROR_OUT_OF_MEMORY);
				else if (ret == -EPIPE)
					/* Do not send anything */
					;
				else if (ret)
					send_error_codes(fd, "Failed to read data point file path",
						0, 0, CCCS_SEND_ERROR_READ_ERROR);

				if (ret)
					return 1;

				break;
			case upload_datapoint_file_events:
			case upload_datapoint_file_metrics:
			case upload_datapoint_file_metrics_binary:
			default:
				/* Read the data point(s) blob of data from the client process */
				ret = read_blob(fd, &blob, &size, &timeout);
				if (ret == -ETIMEDOUT)
					send_error_codes(fd, "Timeout reading data point data",
						0, 0, CCCS_SEND_ERROR_READ_TIMEOUT);
				else if (ret == -ENOMEM)
					send_error_codes(fd, "Failed to read data point data: Out of memory",
						0, 0, CCCS_SEND_ERROR_OUT_OF_MEMORY);
				else if (ret == -EPIPE)
					/* Do not send anything */
					;
				else if (ret)
					send_error_codes(fd, "Failed to read data point data",
						0, 0, CCCS_SEND_ERROR_READ_ERROR);

				if (ret)
					return 1;

				break;
		}

		/* Determine cloud_path/stream_id*/
		switch (type) {
			case upload_datapoint_file_events:
				cloud_path = "DeviceLog/EventLog.json";
				break;
			case upload_datapoint_file_metrics_binary:
			case upload_datapoint_file_path_binary:
				/* Read the data stream name */
				ret = read_string(fd, &stream_id, NULL, &timeout);
				if (ret == -ETIMEDOUT)
					send_error_codes(fd, "Timeout reading data point stream id",
						0, 0, CCCS_SEND_ERROR_READ_TIMEOUT);
				else if (ret == -ENOMEM)
					send_error_codes(fd, "Failed to read data point stream id: Out of memory",
						0, 0, CCCS_SEND_ERROR_OUT_OF_MEMORY);
				else if (ret == -EPIPE)
					/* Do not send anything */
					;
				else if (ret)
					send_error_codes(fd, "Failed to read data point stream id",
						0, 0, CCCS_SEND_ERROR_READ_ERROR);

				if (ret) {
					free(blob);
					free(file_path);
					return 1;
				}
				break;
			case upload_datapoint_file_metrics:
			case upload_datapoint_file_path_metrics:
			default:
				cloud_path = "DataPoint/.csv";
				break;
		}

		/* Upload data to cloud */
		switch (type) {
			case upload_datapoint_file_path_metrics:
				/* Upload the file to the cloud */
				ret = upload_datapoint_file(type, file_path, 0,
					cloud_path, &hint_string_info, &err_from_server);
				cccs_err = dp_process_send_dp_error(type, ret, file_path, 0, NULL,
					cc_cfg->data_backlog_path, cc_cfg->data_backlog_kb);
				err_msg = to_send_error_msg(ret);
				break;
			case upload_datapoint_file_metrics_binary:
				/* Upload the binary blob to the cloud */
				ret = upload_binary_datapoint(type, blob, size,
					stream_id, &hint_string_info, &err_from_server);
				cccs_err = dp_process_send_dp_error(type, ret, blob, size, stream_id,
					cc_cfg->data_backlog_path, cc_cfg->data_backlog_kb);
				err_msg = dp_b_to_send_error_msg(ret);
				break;
			case upload_datapoint_file_path_binary:
				/* Upload the binary file to the cloud */
				ret = upload_binary_datapoint(type, file_path, 0,
					stream_id, &hint_string_info, &err_from_server);
				cccs_err = dp_process_send_dp_error(type, ret, file_path, 0, stream_id,
					cc_cfg->data_backlog_path, cc_cfg->data_backlog_kb);
				err_msg = dp_b_to_send_error_msg(ret);
				break;
			case upload_datapoint_file_events:
			case upload_datapoint_file_metrics:
			default:
				/* Upload the blob to the cloud */
				ret = upload_datapoint_file(type, blob, size,
					cloud_path, &hint_string_info, &err_from_server);
				cccs_err = dp_process_send_dp_error(type, ret, blob, size, NULL,
					cc_cfg->data_backlog_path, cc_cfg->data_backlog_kb);
				err_msg = to_send_error_msg(ret);
				break;
		}

		free(blob);
		free(file_path);
		free(stream_id);

		if (ret || cccs_err) {
			char *err_msg_with_hint = NULL;

			if (!err_from_server.known) {
				/* Use a sentinel value of 255 to indicate something went wrong */
				err_from_server.value = 255;
			}

			if (cccs_err)
				cccs_err = CCCS_SEND_ERROR_UNABLE_TO_STORE_DP;

			if ((hint[0] != '\0') && (asprintf(&err_msg_with_hint, "%s, %s", err_msg, hint) > 0)) {
				send_error_codes(fd, err_msg_with_hint, err_from_server.value, ret, cccs_err);
				free(err_msg_with_hint);
			} else {
				send_error_codes(fd, err_msg, err_from_server.value, ret, cccs_err);
			}
		} else {
			send_ok(fd);
		}

		if (ret != 0 || cccs_err != 0)
			return 1;
	}

	return 0;
}