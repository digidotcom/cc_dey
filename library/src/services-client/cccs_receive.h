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
* Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
* =======================================================================
*/

#ifndef _CCCS_RECEIVE_H_
#define _CCCS_RECEIVE_H_

#include <stddef.h>

#include "cccs_definitions.h"

#define CCCS_RECEIVE_NO_LIMIT	((size_t) - 1)

typedef enum {
	CCCS_RECEIVE_ERROR_NONE,
	CCCS_RECEIVE_ERROR_CCAPI_NOT_RUNNING,
	CCCS_RECEIVE_ERROR_NO_RECEIVE_SUPPORT,
	CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY,
	CCCS_RECEIVE_ERROR_INVALID_TARGET,
	CCCS_RECEIVE_ERROR_TARGET_NOT_ADDED,
	CCCS_RECEIVE_ERROR_TARGET_ALREADY_ADDED,
	CCCS_RECEIVE_ERROR_INVALID_DATA_CB,
	CCCS_RECEIVE_ERROR_LOCK_FAILED,
	CCCS_RECEIVE_ERROR_USER_REFUSED_TARGET,
	CCCS_RECEIVE_ERROR_REQUEST_TOO_BIG,
	CCCS_RECEIVE_ERROR_STATUS_CANCEL,
	CCCS_RECEIVE_ERROR_STATUS_TIMEOUT,
	CCCS_RECEIVE_ERROR_STATUS_SESSION_ERROR,
	CCCS_RECEIVE_ERROR_CUSTOM
} cccs_receive_error_t;

typedef struct {
	void * buffer;
	size_t length;
} cccs_buffer_info_t;

typedef cccs_receive_error_t (*cccs_request_data_cb_t)(char const * const target,
	cccs_buffer_info_t const * const request_buffer_info,
	cccs_buffer_info_t * const response_buffer_info);
typedef void (*cccs_request_status_cb_t)(char const * const target,
	cccs_buffer_info_t * const response_buffer_info,
	int receive_error, const char * const receive_error_hint);

/*
 * cccs_add_request_target() - Register a request target
 *
 * @target:	Target name to register.
 * @data_cb:	Callback function executed when a request for the provided
 *		target is received.
 * @status_cb:	Callback function executed when the receive process has completed.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_add_request_target(char const * const target,
	cccs_request_data_cb_t data_cb, cccs_request_status_cb_t status_cb,
	cccs_resp_t *resp);

/*
 * cccs_add_request_target_tout() - Register a request target
 *
 * @target:	Target name to register.
 * @data_cb:	Callback function executed when a request for the provided
 *		target is received.
 * @status_cb:	Callback function executed when the receive process has completed.
 * @timeout:	Number of seconds to wait for response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_add_request_target_tout(char const * const target,
	cccs_request_data_cb_t data_cb, cccs_request_status_cb_t status_cb,
	unsigned long timeout, cccs_resp_t *resp);

/*
 * cccs_remove_request_target() - Unregister a request target
 *
 * @target:	Target name to unregister.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_remove_request_target(char const * const target, cccs_resp_t *resp);

/*
 * cccs_remove_request_target_tout() - Unregister a request target
 *
 * @target:	Target name to unregister.
 * @timeout:	Number of seconds to wait for response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_remove_request_target_tout(char const * const target,
	unsigned long timeout, cccs_resp_t *resp);

#endif  /* _CCCS_RECEIVE_H_ */
