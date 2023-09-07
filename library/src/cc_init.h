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

#ifndef CC_INIT_H_
#define CC_INIT_H_

typedef enum {
	CC_INIT_ERROR_NONE,
	CC_INIT_CCAPI_START_ERROR_NULL_PARAMETER,
	CC_INIT_CCAPI_START_ERROR_INVALID_VENDORID,
	CC_INIT_CCAPI_START_ERROR_INVALID_DEVICEID,
	CC_INIT_CCAPI_START_ERROR_INVALID_URL,
	CC_INIT_CCAPI_START_ERROR_INVALID_DEVICETYPE,
	CC_INIT_CCAPI_START_ERROR_INVALID_CLI_REQUEST_CALLBACK,
	CC_INIT_CCAPI_START_ERROR_INVALID_RCI_REQUEST_CALLBACK,
	CC_INIT_CCAPI_START_ERROR_INVALID_FIRMWARE_INFO,
	CC_INIT_CCAPI_START_ERROR_INVALID_FIRMWARE_DATA_CALLBACK,
	CC_INIT_CCAPI_START_ERROR_INVALID_SM_ENCRYPTION_CALLBACK,
	CC_INIT_CCAPI_START_ERROR_INSUFFICIENT_MEMORY,
	CC_INIT_CCAPI_START_ERROR_THREAD_FAILED,
	CC_INIT_CCAPI_START_ERROR_LOCK_FAILED,
	CC_INIT_CCAPI_START_ERROR_ALREADY_STARTED,
	CC_INIT_ERROR_REG_BUILTIN_REQUESTS,
	CC_INIT_ERROR_INSUFFICIENT_MEMORY,
	CC_INIT_ERROR_PARSE_CONFIGURATION,
	CC_INIT_ERROR_ADD_VIRTUAL_DIRECTORY,
	CC_INIT_ERROR_UNKOWN
} cc_init_error_t;

typedef enum {
	CC_START_ERROR_NONE,
	CC_START_CCAPI_TCP_START_ERROR_ALREADY_STARTED,
	CC_START_CCAPI_TCP_START_ERROR_CCAPI_STOPPED,
	CC_START_CCAPI_TCP_START_ERROR_NULL_POINTER,
	CC_START_CCAPI_TCP_START_ERROR_INSUFFICIENT_MEMORY,
	CC_START_CCAPI_TCP_START_ERROR_KEEPALIVES,
	CC_START_CCAPI_TCP_START_ERROR_IP,
	CC_START_CCAPI_TCP_START_ERROR_INVALID_MAC,
	CC_START_CCAPI_TCP_START_ERROR_PHONE,
	CC_START_CCAPI_TCP_START_ERROR_INIT,
	CC_START_CCAPI_TCP_START_ERROR_TIMEOUT,
	CC_START_ERROR_NOT_INITIALIZE,
	CC_START_ERROR_SYSTEM_MONITOR
} cc_start_error_t;

typedef enum {
	CC_STOP_ERROR_NONE,
	CC_STOP_CCAPI_STOP_ERROR_NOT_STARTED
} cc_stop_error_t;

typedef enum {
	CC_STATUS_DISCONNECTED,
	CC_STATUS_CONNECTING,
	CC_STATUS_CONNECTED
} cc_status_t;

/*
 * init_cloud_connection() - Initialize Cloud connection
 *
 * @config_file: Absolute path of the configuration file to use. NULL to
 * 		 use the default one (/etc/cccs.conf).
 *
 * Return: 0 if Cloud connection is successfully initialized, error code
 *	   otherwise.
 */
cc_init_error_t init_cloud_connection(const char *config_file);

/*
 * start_cloud_connection() - Start Cloud connection
 *
 * Return: 0 if Cloud connection is successfully started, error code otherwise.
 */
cc_start_error_t start_cloud_connection(void);

/*
 * stop_cloud_connection() - Stop Cloud connection
 *
 * Return: 0 if Cloud connection is successfully stopped, error code otherwise.
 */
cc_stop_error_t stop_cloud_connection(void);

/*
 * get_cloud_connection_status() - Return the status of the connection
 *
 * Return: The connection status.
 */
cc_status_t get_cloud_connection_status(void);

#endif /* CC_INIT_H_ */
