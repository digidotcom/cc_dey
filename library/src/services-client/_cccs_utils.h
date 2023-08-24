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
 * connect_cc_server() - Connect to Cloud Connector server
 *
 * Returns: The file descriptor if success, -1 otherwise.
 */
int connect_cc_server(void);

/*
 * parse_cc_server_response() - Parse received response from Cloud Connector server
 *
 * @fd:		Socket to read response from.
 * @resp:	Received response from Cloud Connector server.
 * @timeout:	Number of seconds to wait for a response.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CC_SRV_SEND_ERROR_NONE if success, any other error if the
 *         communication with the service fails.
 *
 * Expects the reply sequence "i:0" or "i:1 b:error-msg".
 */
cc_srv_comm_error_t parse_cc_server_response(int fd, cc_srv_resp_t *resp, unsigned long timeout);

#endif /* _CCCS_CLIENT_UTILS_H_ */