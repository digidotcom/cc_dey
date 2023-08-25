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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "ccimp/ccimp_types.h"

#include "_cccs_utils.h"
#include "cc_logging.h"
#include "services.h"
#include "services_util.h"

#define CCCSD_TAG	"CCCSD:"

/**
 * log_cccsd_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_cccsd_debug(format, ...)					\
	log_debug("%s " format, CCCSD_TAG, __VA_ARGS__)

/**
 * log_cccsd_info() - Log the given message as info
 *
 * @format:		Warning message to log.
 * @args:		Additional arguments.
 */
#define log_cccsd_info(format, ...)					\
	log_info("%s " format, CCCSD_TAG, __VA_ARGS__)

/**
 * log_cccsd_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_cccsd_error(format, ...)					\
	log_error("%s " format, CCCSD_TAG, __VA_ARGS__)

void * ccapi_lock_create_and_release(void);
ccimp_status_t ccapi_lock_acquire(void *lock);
ccimp_status_t ccapi_lock_release(void *lock);
ccimp_status_t ccapi_lock_destroy(void *lock);

void *get_lock(void)
{
	return ccapi_lock_create_and_release();
}

int lock_acquire(void *lock)
{
	ccimp_status_t status;

	if (!lock)
		return 1;

	status = ccapi_lock_acquire(lock);
	switch (status) {
		case CCIMP_STATUS_OK:
			return 0;
		case CCIMP_STATUS_ERROR:
		case CCIMP_STATUS_BUSY:
			break;
		default:
			/* Should not occur */
			log_cccsd_error("Unknown lock acquire status %d", status);
			break;
	}

	return 1;
}

int lock_release(void *lock)
{
	ccimp_status_t status;

	if (!lock)
		return 1;

	status = ccapi_lock_release(lock);
	switch (status) {
		case CCIMP_STATUS_OK:
			return 0;
		case CCIMP_STATUS_ERROR:
		case CCIMP_STATUS_BUSY:
			break;
		default:
			/* Should not occur */
			log_cccsd_error("Unknown lock release status %d", status);
			break;
	}

	return 1;
}

int lock_destroy(void *lock)
{
	ccimp_status_t status;
	int ret = 1;

	if (!lock)
		return 1;

	status = ccapi_lock_destroy(lock);
	switch (status) {
		case CCIMP_STATUS_OK:
			ret = 0;
			break;
		case CCIMP_STATUS_ERROR:
		case CCIMP_STATUS_BUSY:
			break;
		default:
			/* Should not occur */
			log_cccsd_error("Unknown lock release status %d", status);
			break;
	}

	return ret;
}

int connect_cccsd(void)
{
	const struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(CONNECTOR_REQUEST_PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	int s = socket(AF_INET, SOCK_STREAM, 0);

	if (s == -1) {
		log_cccsd_error("Failed to connect to CCCSD: %s (%d)",
			strerror(errno), errno);
		return -1;
	}

	if (connect(s, (const struct sockaddr *)&sa, sizeof sa) == -1) {
		log_cccsd_error("Failed to connect to CCCSD: %s (%d)",
			strerror(errno), errno);
		return -1;
	}

	log_cccsd_debug("Connected to CCCSD (s=%d)", s);

	return s;
}

cccs_comm_error_t parse_cccsd_response(int fd, cccs_resp_t *resp, unsigned long timeout)
{
	uint32_t code;
	void *msg = NULL;
	size_t msg_len = 0;
	struct timeval timeout_val;

	resp->hint = NULL;

	timeout_val.tv_sec = timeout;
	timeout_val.tv_usec = 0;

	if (read_uint32(fd, &code, timeout > 0 ? &timeout_val : NULL) < 0) {
		resp->code = CCCS_SEND_ERROR_BAD_RESPONSE;
		log_cccsd_error("Bad response: %s",
				"Failed to read data type from CCCSD");

		return resp->code;
	}

	switch(code) {
		case RESP_END_OF_MESSAGE:
			resp->code = 0;
			log_cccsd_debug("%s", "Success from CCCSD");

			return CCCS_SEND_ERROR_NONE;
		case RESP_ERRORCODE:
			/* Read error code first */
			if (read_uint32(fd, (uint32_t *) &resp->code, timeout > 0 ? &timeout_val : NULL) < 0) {
				resp->code = CCCS_SEND_ERROR_BAD_RESPONSE;
				log_cccsd_error("Bad response: %s",
						"Failed to read error code from CCCSD");

				return resp->code;
			}
			break;
		case RESP_ERROR:
			resp->code = 255;
			break;
		default:
			resp->code = CCCS_SEND_ERROR_BAD_RESPONSE;
			log_cccsd_error("Bad response: Received unknown data type code %" PRIu32 "from CCCSD", code);

			return resp->code;
	}

	/* Read the error message */
	if (read_blob(fd, &msg, &msg_len, timeout > 0 ? &timeout_val : NULL) < 0) {
		log_cccsd_error("Failed to read response: %s (%d)", strerror(errno), errno);
		resp->code = CCCS_SEND_ERROR_BAD_RESPONSE;

		return resp->code;
	}

	resp->hint = (char *)msg;

	if (resp->hint)
		log_cccsd_debug("Error from Cloud: %s (%d)", resp->hint, resp->code);
	else
		log_cccsd_debug("Error from Cloud (%d)", resp->code);

	return CCCS_SEND_ERROR_FROM_CLOUD;
}
