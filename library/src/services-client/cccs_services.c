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
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "ccimp/ccimp_types.h"

#include "_cccs_utils.h"
#include "cc_logging.h"
#include "service_common.h"
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

static volatile bool stop_requested;

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
		log_cccsd_debug("Failed to connect to CCCSD: %s (%d)",
			strerror(errno), errno);

		return -1;
	}

	if (connect(s, (const struct sockaddr *)&sa, sizeof sa) == -1) {
		log_cccsd_debug("Failed to connect to CCCSD (s=%d): %s (%d)",
			s, strerror(errno), errno);
		close(s);

		return -1;
	}

	log_cccsd_debug("Connected to CCCSD (s=%d)", s);

	return s;
}

/**
 * read_error() - Read error code from socket
 *
 * @fd:		Socket to read error from.
 * @error:	Read error from CCCS daemon.
 * @timeout:	Number of seconds to wait for the reading.
 * @desc:	Description to log it it fails. Cannot be NULL.
 *
 * Return: 0 if success, any other value otherwise.
 */
static int read_error(int fd, uint32_t *error, struct timeval *timeout, const char * const desc)
{
	int ret = read_uint32(fd, error, timeout);

	if (ret == -ETIMEDOUT) {
		ret = CCCS_SEND_ERROR_READ_TIMEOUT;
		log_cccsd_error("Bad response, timeout reading %sfrom CCCSD", desc);
	} else if (ret) {
		ret = CCCS_SEND_ERROR_BAD_RESPONSE;
		log_cccsd_error("Bad response, failed to read %sfrom CCCSD", desc);
	}

	return ret;
}

cccs_comm_error_t parse_cccsd_response(int fd, cccs_srv_resp_t *resp, unsigned long timeout)
{
	uint32_t code;
	void *msg = NULL;
	size_t msg_len = 0;
	struct timeval timeout_val;
	int ret;

	resp->srv_err = 0;
	resp->ccapi_err = 0;
	resp->cccs_err = 0;
	resp->hint = NULL;

	timeout_val.tv_sec = timeout;
	timeout_val.tv_usec = 0;

	ret = read_error(fd, &code, timeout > 0 ? &timeout_val : NULL, "data type ");
	if (ret) {
		resp->cccs_err = ret;
		return ret;
	}

	switch (code) {
		case RESP_END_OF_MESSAGE:
			log_cccsd_debug("%s", "Success from CCCSD");

			return CCCS_SEND_ERROR_NONE;
		case RESP_ERRORCODE:
			/* Read server error code */
			ret = read_error(fd, (uint32_t *)&resp->srv_err, timeout > 0 ? &timeout_val : NULL, "DRM error ");
			if (ret) {
				resp->cccs_err = ret;
				return ret;
			}
			if (resp->srv_err)
				resp->cccs_err = CCCS_SEND_ERROR_SRV_ERROR;

			/* Read ccapi error code */
			ret = read_error(fd, (uint32_t *)&resp->ccapi_err, timeout > 0 ? &timeout_val : NULL, "CCAPI error ");
			if (ret) {
				resp->cccs_err = ret;
				return ret;
			}
			if (resp->ccapi_err)
				resp->cccs_err = CCCS_SEND_ERROR_CCAPI_ERROR;

			/* Read cccs error code */
			ret = read_error(fd, (uint32_t *)&resp->cccs_err, timeout > 0 ? &timeout_val : NULL, "CCCS error ");
			if (ret) {
				resp->cccs_err = ret;
				return ret;
			}

			break;
		case RESP_ERROR:
			resp->srv_err = 255;
			resp->cccs_err = CCCS_SEND_ERROR_SRV_ERROR;
			break;
		default:
			resp->cccs_err = CCCS_SEND_ERROR_BAD_RESPONSE;
			log_cccsd_error("Bad response, received unknown data type code %" PRIu32 "from CCCSD", code);

			return resp->cccs_err;
	}

	/* Read the error message */
	ret = read_blob(fd, &msg, &msg_len, timeout > 0 ? &timeout_val : NULL);
	if (ret == -ETIMEDOUT) {
		resp->cccs_err = CCCS_SEND_ERROR_READ_TIMEOUT;
		log_cccsd_error("Failed to read response: %s", "Timeout");
	} else if (ret == -ENOMEM) {
		resp->cccs_err = CCCS_SEND_ERROR_BAD_RESPONSE;
		log_cccsd_error("Failed to read response: %s", "Out of memory");
	} else if (ret == -EPIPE) {
		resp->cccs_err = CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON;
		log_cccsd_error("Failed to read response: %s", "Socket closed");
	} else if (ret) {
		resp->cccs_err = CCCS_SEND_ERROR_BAD_RESPONSE;
		log_cccsd_error("Failed to read response: %s (%d)", strerror(errno), errno);
	}

	if (ret)
		return resp->cccs_err;

	resp->hint = (char *)msg;

	if (resp->hint)
		log_cccsd_debug("Transaction error: %s (srv: %d, ccapi: %d, cccs: %d)",
			resp->hint, resp->srv_err, resp->ccapi_err, resp->cccs_err);
	else
		log_cccsd_debug("Transaction error (srv: %d, ccapi: %d, cccs: %d)",
			resp->srv_err, resp->ccapi_err, resp->cccs_err);

	return CCCS_SEND_ERROR_FROM_CLOUD;
}

/**
 * signal_handler() - Manage signal received
 *
 * @signum:	Received signal.
 */
static void signal_handler(int signum)
{
	log_debug("%s: Received signal %d", __func__, signum);
	stop_requested = true;
}

/*
 * setup_signal_handler() - Setup process signals
 *
 * Return: 0 on success, 1 otherwise.
 */
static int setup_signal_handler(struct sigaction *orig_action)
{
	struct sigaction new_action;

	memset(&new_action, 0, sizeof(new_action));
	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction(SIGINT, NULL, orig_action);
	if (orig_action->sa_handler != SIG_IGN) {
		if (sigaction(SIGINT, &new_action, NULL)) {
			log_error("Failed to install signal handler: %s (%d)",
				strerror(errno), errno);

			return 1;
		}
	}

	return 0;
}

bool cccs_is_daemon_ready(long timeout)
{
	struct sigaction orig_action;
	int ret;
	bool ready = false;
	int start = time(NULL);

	if (timeout < 0)
		timeout = CCCSD_WAIT_FOREVER;

	/* Set a signal handler to be able to cancel while trying to connect */
	ret = setup_signal_handler(&orig_action);

	do {
		int fd = connect_cccsd();

		if (fd >= 0) {
			close(fd);
			ready = true;
			goto done;
		}
		if (stop_requested)
			goto done;
		sleep(1);
	} while (timeout == CCCSD_WAIT_FOREVER || time(NULL) - start < timeout);

done:
	stop_requested = false;

	/* Restore the original signal handler */
	if (!ret)
		sigaction(SIGINT, &orig_action, NULL);

	if (ready)
		log_debug("%s", "CCCS daemon ready");
	else
		log_debug("%s", "CCCS daemon not ready");

	return ready;
}
