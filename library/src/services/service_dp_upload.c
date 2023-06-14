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

#include <stdio.h>

#include "ccapi/ccapi.h"
#include "cc_logging.h"
#include "cc_error_msg.h"
#include "service_dp_upload.h"
#include "services_util.h"

static ccapi_send_error_t upload_datapoint_file(char const * const buff, ccapi_string_info_t * const hint_string_info, size_t size, char const cloud_path[])
{
#define TIMEOUT 5
	ccapi_send_error_t send_error;
	char const file_type[] = "text/plain";
	send_error = ccapi_send_data_with_reply(CCAPI_TRANSPORT_TCP,
											cloud_path, file_type,
											buff, size,
											CCAPI_SEND_BEHAVIOR_OVERWRITE,
											TIMEOUT,
											hint_string_info);
	if (send_error != CCAPI_SEND_ERROR_NONE)
		log_error("Send error: %d Hint: %s", send_error, hint_string_info->string);

	return send_error;
#undef TIMEOUT
}

int handle_datapoint_file_upload(int fd)
{
	while(1) {
		ccapi_send_error_t ret;
		uint32_t type;
		size_t size;
		void * blob;
		struct timeval timeout = {
			.tv_sec = SOCKET_READ_TIMEOUT_SEC,
			.tv_usec = 0
		};
		char hint[256];
		ccapi_string_info_t hint_string_info;

		hint[0] = '\0';
		hint_string_info.length = sizeof hint;
		hint_string_info.string = hint;

		/* Read the record type from the client message */
		if (read_uint32(fd, &type, &timeout)) {
			send_error(fd, "Failed to read data type");
			return 1;
		}

		if (type == upload_datapoint_file_terminate)
			break;

		if (type != upload_datapoint_file_metrics && type != upload_datapoint_file_events) {
			send_error(fd, "Invalid datapoint type");
			return 1;
		}

		/* Read the datapoint(s) blob of data from the client process */
		if (read_blob(fd, &blob, &size, &timeout)) {
			send_error(fd, "Failed to read datapoint data");
			return 1;
		}

		char* cloud_path;
		switch(type) {
			case upload_datapoint_file_events:
				cloud_path = "DeviceLog/EventLog.json";
				break;
			case upload_datapoint_file_metrics:
			default:
				cloud_path = "DataPoint/.csv";
				break;
		}

		/* Upload the blob to the cloud */
		ret = upload_datapoint_file(blob, &hint_string_info, size, cloud_path);

		free(blob);

		if (ret) {
			char const * const err_msg = to_send_error_msg(ret);
			char * err_msg_with_hint = NULL;

			if ((hint[0] != '\0') && (asprintf(&err_msg_with_hint, "%s, %s", err_msg, hint) > 0)) {
				send_error(fd, err_msg_with_hint);
				free(err_msg_with_hint);
			} else {
				send_error(fd, err_msg);
			}
		} else {
			send_ok(fd);
		}

		if (ret != CCAPI_SEND_ERROR_NONE) {
			return 1;
		}
	}

	return 0;
}
