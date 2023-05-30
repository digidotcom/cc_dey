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

#include "cc_error_msg.h"
#include "cc_logging.h"

const char *to_send_error_msg(ccapi_send_error_t error) {
	switch (error) {
		case CCAPI_SEND_ERROR_NONE:
			return "Success";
		case CCAPI_SEND_ERROR_CCAPI_NOT_RUNNING:
			return "CCAPI not running";
		case CCAPI_SEND_ERROR_TRANSPORT_NOT_STARTED:
			return "Transport not started";
		case CCAPI_SEND_ERROR_FILESYSTEM_NOT_SUPPORTED:
			return "Filesystem not supported";
		case CCAPI_SEND_ERROR_INVALID_CLOUD_PATH:
			return "Invalid cloud path";
		case CCAPI_SEND_ERROR_INVALID_CONTENT_TYPE:
			return "Invalid content type";
		case CCAPI_SEND_ERROR_INVALID_DATA:
			return "Invalid data";
		case CCAPI_SEND_ERROR_INVALID_LOCAL_PATH:
			return "Invalid local path";
		case CCAPI_SEND_ERROR_NOT_A_FILE:
			return "Not a file";
		case CCAPI_SEND_ERROR_ACCESSING_FILE:
			return "Error accessing file";
		case CCAPI_SEND_ERROR_INVALID_HINT_POINTER:
			return "Invalid hint pointer";
		case CCAPI_SEND_ERROR_INSUFFICIENT_MEMORY:
			return "Out of memory";
		case CCAPI_SEND_ERROR_LOCK_FAILED:
			return "Lock failed";
		case CCAPI_SEND_ERROR_INITIATE_ACTION_FAILED:
			return "Initiate action failed";
		case CCAPI_SEND_ERROR_STATUS_CANCEL:
			return "Cancelled";
		case CCAPI_SEND_ERROR_STATUS_TIMEOUT:
			return "Timeout";
		case CCAPI_SEND_ERROR_STATUS_SESSION_ERROR:
			return "Session error";
		case CCAPI_SEND_ERROR_RESPONSE_BAD_REQUEST:
			return "Bad request";
		case CCAPI_SEND_ERROR_RESPONSE_UNAVAILABLE:
			return "Response unavailable";
		case CCAPI_SEND_ERROR_RESPONSE_CLOUD_ERROR:
			return "Cloud error";
		default:
			log_error("unknown internal connection error: ccapi_send_error_t[%d]", error);
			return "Internal connector error";
	}
}

