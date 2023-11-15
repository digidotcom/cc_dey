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

#ifndef SERVICE_COMMON_H
#define SERVICE_COMMON_H

#define CONNECTOR_REQUEST_PORT		977

#define REQ_TAG_DP_FILE_REQUEST		"upload_1_dp"
#define REQ_TAG_MNT_REQUEST		"mnt_request"
#define REQ_TAG_REGISTER_DR		"register_devicerequest"
#define REQ_TAG_UNREGISTER_DR		"unregister_devicerequest"
#define REQ_TAG_REGISTER_DR_IPV4	"register_devicerequest_ipv4"
#define REQ_TAG_UNREGISTER_DR_IPV4	"unregister_devicerequest_ipv4"

#define REQ_TYPE_REQUEST_CB		"request"
#define REQ_TYPE_STATUS_CB		"status"

typedef enum {
	upload_datapoint_file_terminate,
	upload_datapoint_file_metrics,
	upload_datapoint_file_events,
	upload_datapoint_file_path_metrics,
	upload_datapoint_file_path_binary,
	upload_datapoint_file_metrics_binary,
	upload_datapoint_file_count
} upload_datapoint_file_t;

#endif /* SERVICE_COMMON_H */
