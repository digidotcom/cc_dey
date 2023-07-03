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

#include "_srv_client_utils.h"
#include "cc_logging.h"
#include "services.h"
#include "services_util.h"

#define SERVICE_TAG	"SRV:"

/**
 * log_srv_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_srv_debug(format, ...)					\
	log_debug("%s " format, SERVICE_TAG, __VA_ARGS__)

/**
 * log_srv_info() - Log the given message as info
 *
 * @format:		Warning message to log.
 * @args:		Additional arguments.
 */
#define log_srv_info(format, ...)					\
	log_info("%s " format, SERVICE_TAG, __VA_ARGS__)

/**
 * log_srv_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_srv_error(format, ...)					\
	log_error("%s " format, SERVICE_TAG, __VA_ARGS__)

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
			log_srv_error("Unknown lock acquire status %d", status);
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
			log_srv_error("Unknown lock release status %d", status);
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
			log_srv_error("Unknown lock release status %d", status);
			break;
	}

	return ret;
}

int connect_cc_server(void)
{
	const struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(CONNECTOR_REQUEST_PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
	};
	int s = socket(AF_INET, SOCK_STREAM, 0);

	if (s == -1) {
		log_srv_error("Failed to connect to Cloud Connector service: %s (%d)",
			strerror(errno), errno);
		return -1;
	}

	if (connect(s, (const struct sockaddr *)&sa, sizeof sa) == -1) {
		log_srv_error("Failed to connect to Cloud Connector service: %s (%d)",
			strerror(errno), errno);
		return -1;
	}

	log_srv_debug("Connected to Cloud Connector service (s=%d)", s);

	return s;
}

int parse_cc_server_response(int fd, char **resp, unsigned long timeout)
{
	uint32_t code;
	void *msg = NULL;
	size_t msg_len = 0;
	struct timeval timeout_val;

	timeout_val.tv_sec = timeout;
	timeout_val.tv_usec = 0;

	if (read_uint32(fd, &code, timeout > 0 ? &timeout_val : NULL) < 0) {
		*resp = strdup("Failed to read data type");
		if (!*resp) {
			log_srv_error("Cannot read Cloud Connector server answer: %s",
				"Out of memory");
			return -2;
		}
		log_srv_error("Bad response: %s",
			"Failed to read data type from Cloud Connector server");
		return -1;
	}

	if (code == 0) {
		log_srv_debug("%s", "Success from Cloud Connector server");

		return 0;
	}

	if (code != 1) {
		int len = snprintf(NULL, 0, "Received an unknown response code %" PRIu32, code);

		*resp = calloc(len + 1, sizeof(char));
		if (*resp == NULL){
			log_srv_error("Cannot read Cloud Connector server answer: %s",
				"Out of memory");
			return -2;
		}

		sprintf(*resp, "Received an unknown response code %" PRIu32, code);

		log_srv_error("Bad response: Received an unknown response from Cloud Connector server %" PRIu32,
			code);

		return -1;
	}

	if (read_blob(fd, &msg, &msg_len, timeout > 0 ? &timeout_val : NULL) < 0) {
		int err = errno;
		int len = snprintf(NULL, 0, "Could not read response: %s (%d)", strerror(err), err);

		*resp = calloc(len + 1, sizeof(char));
		if (*resp == NULL) {
			log_srv_error("Cannot read Cloud Connector server answer: %s",
				"Out of memory");
			return -2;
		}

		sprintf(*resp, "Could not read response: %s (%d)", strerror(err), err);

		log_srv_error("Cannot read response: %s (%d)", strerror(err), err);

		return -1;
	}

	*resp = (char *)msg;

	if (*resp != NULL)
		log_srv_debug("Error from Cloud Connector service: %s", *resp);
	else
		log_srv_debug("%s", "Error from Cloud Connector service");

	return 1;
}
