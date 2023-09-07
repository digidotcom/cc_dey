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

#ifndef _CCCS_DEFINITIONS_H_
#define _CCCS_DEFINITIONS_H_

typedef enum {
	CCCS_SEND_ERROR_NONE,
	CCCS_SEND_ERROR_ERROR_FROM_DAEMON,
	CCCS_SEND_ERROR_INVALID_ARGUMENT,
	CCCS_SEND_ERROR_OUT_OF_MEMORY,
	CCCS_SEND_ERROR_LOCK,
	CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON,
	CCCS_SEND_ERROR_BAD_RESPONSE,
	CCCS_SEND_ERROR_FROM_CLOUD,
} cccs_comm_error_t;

/**
 * struct cccs_resp_t - Response from ConnectCore Cloud Services daemon
 *
 * @code:	Response code, 0 success.
 * @hint:	Null-terminated string with error hint, can be NULL.
 * 		It must be freed.
 */
typedef struct {
	int code;
	char *hint;
} cccs_resp_t;

#endif /* _CCCS_DEFINITIONS_H_ */
