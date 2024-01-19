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

#ifndef _CCCS_CLIENT_UTILS_H_
#define _CCCS_CLIENT_UTILS_H_

#include "cccs_services.h"

/**
 * struct cccs_srv_resp_t - Response from ConnectCore Cloud Services daemon
 *
 * @srv_err:	Response code from server, 0 success.
 * @ccapi_err:	Response code from daemon, 0 success.
 * @cccs_err:	Other error code, 0 success.
 * @hint:	Null-terminated string with error hint, can be NULL.
 * 		It must be freed.
 */
typedef struct {
	int srv_err;
	int ccapi_err;
	int cccs_err;
	char *hint;
} cccs_srv_resp_t;

/**
 * get_lock() - Create a lock
 *
 * Returns: The created lock, NULL if it fails.
 */
void *get_lock(void);

/**
 * lock_acquire() - Acquire the provided lock
 *
 * @lock: The lock to acquire.
 *
 * Returns: 0 if success, 1 otherwise.
 */
int lock_acquire(void *lock);

/**
 * lock_release() - Release the provided lock
 *
 * @lock: The lock to release.
 *
 * Returns: 0 if success, 1 otherwise.
 */
int lock_release(void *lock);

/**
 * lock_destroy() - Destroy the provided lock
 *
 * @lock: The lock to destroy.
 *
 * Returns: 0 if success, 1 otherwise.
 */
int lock_destroy(void *lock);

/**
 * connect_cccsd() - Connect to CCCS daemon
 *
 * Returns: The file descriptor if success, -1 otherwise.
 */
int connect_cccsd(void);

/*
 * parse_cccsd_response() - Parse received response from CCCS daemon
 *
 * @fd:		Socket to read response from.
 * @resp:	Received response from CCCS daemon.
 * @timeout:	Number of seconds to wait for a response.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 *
 * Expects the reply sequence "i:0" or "i:1 b:error-msg".
 */
cccs_comm_error_t parse_cccsd_response(int fd, cccs_srv_resp_t *resp, unsigned long timeout);

#endif /* _CCCS_CLIENT_UTILS_H_ */