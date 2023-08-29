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

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "cc_logging.h"
#include "_cccs_utils.h"
#include "cccs_services.h"
#include "cccs_receive.h"
#include "service_data_request.h"
#include "services_util.h"

#define DATA_REQUEST_TAG		"DREQ:"

/**
 * log_dr_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_dr_debug(format, ...)					\
	log_debug("%s " format, DATA_REQUEST_TAG, __VA_ARGS__)

/**
 * log_dr_info() - Log the given message as info
 *
 * @format:		Info message to log.
 * @args:		Additional arguments.
 */
#define log_dr_info(format, ...)					\
	log_info("%s " format, DATA_REQUEST_TAG, __VA_ARGS__)


/**
 * log_dr_warning() - Log the given message as warning
 *
 * @format:		Warning message to log.
 * @args:		Additional arguments.
 */
#define log_dr_warning(format, ...)					\
	log_warning("%s " format, DATA_REQUEST_TAG, __VA_ARGS__)

/**
 * log_dr_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_dr_error(format, ...)					\
	log_error("%s " format, DATA_REQUEST_TAG, __VA_ARGS__)

/* Similar to 'ccapi_receive_target_t' in ccapi_definitions.h */
typedef struct {
	char *target;
	cccs_request_data_cb_t data_cb;
	cccs_request_status_cb_t status_cb;
	size_t max_request_size;
	cccs_buffer_info_t req_buffer;
	cccs_buffer_info_t resp_buffer;
} request_data_t;

typedef struct {
#define INITIAL_MAX_SIZE 16
	request_data_t *array;
	size_t size;
	size_t max_size;
	void *lock;
} request_data_darray_t;

typedef struct {
	int fd;
	int port;
	int stop_pipe[2];
} server_sock_t;

typedef enum {
	REQ_KEY_REGISTER_DR,
	REQ_KEY_UNREGISTER_DR,
	REQ_KEY_UNKOWN
} dreq_action_type_t;

static char* req_action_type_tags[] = {
	REQ_TAG_REGISTER_DR,
	REQ_TAG_UNREGISTER_DR,
	"unknown"
};

static request_data_darray_t active_requests = { 0 };

static server_sock_t server_sock = {
	.fd = -1,
	.port = -1
};

static pthread_t listen_thread;
static bool listen_thread_valid;
static volatile bool stop_listening = false;

/* Similar to the one in service_data_request.c */
static int add_registered_target(const request_data_t target)
{
	/* If needed, (re)alloc memory */
	if (active_requests.size == active_requests.max_size) {
		size_t new_max_size = active_requests.max_size ? 2 * active_requests.max_size : INITIAL_MAX_SIZE;
		request_data_t *new_array = realloc(active_requests.array, new_max_size * sizeof(request_data_t));

		if (!new_array)
			return -1;

		active_requests.array = new_array;
		active_requests.max_size = new_max_size;
	}

	active_requests.array[active_requests.size].target = strdup(target.target);
	if (active_requests.array[active_requests.size].target == NULL)
		return -1;

	active_requests.array[active_requests.size].data_cb = target.data_cb;
	active_requests.array[active_requests.size].status_cb = target.status_cb;
	active_requests.array[active_requests.size++].max_request_size = target.max_request_size;

	return 0;
}

/* Similar to the one in service_data_request.c */
static request_data_t *find_request_data(const char *target)
{
	size_t i;

	for (i = 0; i < active_requests.size; i++) {
		if (!strcmp(active_requests.array[i].target, target))
			return &active_requests.array[i];
	}

	return NULL;
}

/* Similar to the one in service_data_request.c */
static int remove_registered_target(const char * target) {
	request_data_t *req = find_request_data(target);
	size_t elements_to_move;

	if (!req)
		return -1;

	free(req->target);
	/* Count number of valid elements after req */
	elements_to_move = active_requests.size - (req - active_requests.array) - 1;
	if (elements_to_move > 0)
		memmove(req, req + 1, elements_to_move * sizeof(request_data_t));

	active_requests.size--;

	return 0;
}

static server_sock_t get_server_socket(void)
{
	socklen_t addr_len;
	const struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0
	};

	if (server_sock.fd != -1)
		goto done;

	if ((server_sock.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_dr_error("Could not open connection to CCCSD to listen to data requests: %s (%d)",
			strerror(errno), errno);
		goto error;
	}

	if (pipe(server_sock.stop_pipe)) {
		log_dr_error("Unable to notify when data requests arrive: %s (%d)",
			strerror(errno), errno);
		goto error;
	}

	if (bind(server_sock.fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) {
		log_dr_error("Failed to bind to CCCSD: %s (%d)",
			strerror(errno), errno);
		goto close_pipes;
	}

	addr_len = sizeof(serv_addr);
	if (getsockname(server_sock.fd, (struct sockaddr *)&serv_addr, &addr_len) == -1) {
		log_dr_error("Failed to get CCCSD port: %s (%d)",
			strerror(errno), errno);
		goto close_pipes;
	}

	server_sock.port = ntohs(serv_addr.sin_port);

	goto done;
close_pipes:
	close(server_sock.stop_pipe[0]);
	close(server_sock.stop_pipe[1]);

	server_sock.stop_pipe[0] = -1;
	server_sock.stop_pipe[1] = -1;
error:
	close(server_sock.fd);

	server_sock.fd = -1;
	server_sock.port = -1;
done:
	return server_sock;
}

static cccs_comm_error_t send_data_request_data(dreq_action_type_t type, int port,
	char const * const target, unsigned long timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret;
	int fd = -1;
	char *type_tag = NULL;

	resp->hint = NULL;

	switch (type) {
		case REQ_KEY_REGISTER_DR:
			log_dr_info("Registering '%s' data request", target);
			break;
		case REQ_KEY_UNREGISTER_DR:
			log_dr_info("Unregistering '%s' data request", target);
			break;
		default:
			log_dr_error("Unknown data request action '%d'", type);
			ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
			resp->code = ret;

			return ret;
	}

	type_tag = req_action_type_tags[type];

	fd = connect_cccsd();
	if (fd < 0) {
		ret = CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON;
		resp->code = ret;

		return ret;
	}

	if (write_string(fd, type_tag)		/* The request type */
		|| write_uint32(fd, port)	/* Port */
		|| write_string(fd, target)	/* Target */
		|| write_uint32(fd, 0)) {	/* End of message */
		log_dr_error("Could not %s '%s' data request: %s (%d)",
			type == REQ_KEY_REGISTER_DR ? "register" : "unregister",
			target, strerror(errno), errno);
		ret = CCCS_SEND_ERROR_BAD_RESPONSE;
		resp->code = ret;
		goto done;
	}

	ret = parse_cccsd_response(fd, resp, timeout);
done:
	close(fd);

	return ret;
}

static void *listen_threaded(void *server_sock)
{
	int request_sock;
	bool lock_acquired = false;
	server_sock_t *sock = (server_sock_t *)server_sock;

	if (listen(sock->fd, 5)) {
		log_dr_error("Failed start listening to data requests: %s (%d)",
			strerror(errno), errno);
		goto done;
	}

	while (!stop_listening) {
		fd_set read_set;
		int ret;
		char *cb_type = NULL, *target = NULL;
		void *data = NULL;
		request_data_t *registered_req = NULL;
		struct timeval timeout = {
			.tv_sec = 3,
			.tv_usec = 0
		};

		FD_ZERO(&read_set);
		FD_SET(sock->fd, &read_set);
		FD_SET(sock->stop_pipe[0], &read_set);
		ret = select(sock->fd > sock->stop_pipe[0] ? sock->fd + 1 : sock->stop_pipe[0] + 1,
					&read_set, NULL, NULL, &timeout);
		if (ret < 0) {
			log_dr_error("Error reading request from CCCSD: %s (%d)",
				strerror(errno), errno);
			goto done;
		}
		if (ret == 0)
			/* Timeout */
			continue;

		if (FD_ISSET(sock->stop_pipe[0], &read_set))
			goto done;

		request_sock = accept4(sock->fd, NULL, NULL, SOCK_CLOEXEC);
		if (request_sock == -1) {
			log_dr_error("Error reading request from CCCSD: %s (%d)",
				strerror(errno), errno);
			goto done;
		}

		timeout.tv_sec = SOCKET_READ_TIMEOUT_SEC;

		/* Read request type and target */
		if (read_string(request_sock, &cb_type, NULL, &timeout)			/* The request type */
			|| read_string(request_sock, &target, NULL, &timeout)) {	/* Target */
			log_dr_error("Error reading request from CCCSD: %s (%d)",
				strerror(errno), errno);
			send_error(request_sock, "Failed to read request code");
			goto loop_done;
		}

		if (lock_acquire(active_requests.lock) != 0) {
			log_dr_error("Error processing '%s' request: Unable to lock, data request service busy",
					target);
			goto loop_done;
		}

		lock_acquired = true;

		/* Search for the target */
		registered_req = find_request_data(target);
		if (!registered_req) {
			/* This should never happen */
			log_dr_error("Got callback for unregistered target '%s'", target);
			goto loop_done;
		}

		/* Execute data callback */
		if (!strcmp(cb_type, REQ_TYPE_REQUEST_CB)) {
			cccs_buffer_info_t req_buffer = registered_req->req_buffer;
			cccs_buffer_info_t resp_buffer = registered_req->resp_buffer;
			cccs_receive_error_t error;

			if (read_blob(request_sock, &req_buffer.buffer, &req_buffer.length, &timeout)) {
				log_dr_error("Unable to get '%s' request data from CCCSD", target);
				resp_buffer.buffer = strdup("Error getting request data");
				if (!resp_buffer.buffer) {
					log_dr_error("Cannot generate error response for target '%s': Out of memory", target);
					goto loop_done;
				}
				error = CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
				resp_buffer.length = strlen(resp_buffer.buffer);
			} else {
				error = registered_req->data_cb(target, &req_buffer, &resp_buffer);

				free(req_buffer.buffer);
				req_buffer.buffer = NULL;
				req_buffer.length = 0;

				if (error != CCCS_RECEIVE_ERROR_NONE)
					log_dr_error("Error executing '%s' request: %d", target, error);
			}

			if (write_uint32(request_sock, error)
				|| write_blob(request_sock, resp_buffer.buffer, resp_buffer.length)) {
				log_dr_error("Unable to send '%s' request response to CCCSD", target);
				free(resp_buffer.buffer);
				resp_buffer.buffer = NULL;
				resp_buffer.length = 0;
				goto loop_done;
			}
		/* Execute status callback */
		} else if (!strcmp(cb_type, REQ_TYPE_STATUS_CB)) {
			cccs_buffer_info_t resp_buffer = registered_req->resp_buffer;
			uint32_t error;
			char *error_str = NULL;

			if (read_uint32(request_sock, &error, &timeout)
				|| read_string(request_sock, &error_str, NULL, &timeout)) {
				log_dr_error("Unable to get '%s' request status from CCCSD", target);
				error = -1;
				error_str = "Unable to get request status from CCCSD";
			}

			registered_req->status_cb(target, &resp_buffer, error, error_str);

			free(error_str);
		/* Unknown callback type */
		} else {
			log_dr_error("Got strange callback type from CCCSD '%s'",
				cb_type);
		}
loop_done:
		if (lock_acquired && lock_release(active_requests.lock) != 0)
			log_dr_error("Error processing '%s' request: Unable to release lock, data request service busy",
					target);

		if (close(request_sock) < 0)
			log_warning("Could not close connection to CCCSD after attending request: %s (%d)",
				strerror(errno), errno);

		free(cb_type);
		free(target);
		free(data);
	}
done:
	close(sock->fd);
	close(sock->stop_pipe[0]);
	close(sock->stop_pipe[1]);
	sock->fd = -1;
	sock->stop_pipe[0] = -1;
	sock->stop_pipe[1] = -1;

	pthread_exit(NULL);

	return NULL;
}

static bool start_listening_for_requests(void)
{
	pthread_attr_t attr;
	int ret;

	stop_listening = false;

	if (listen_thread_valid)
		return listen_thread_valid;

	ret = pthread_attr_init(&attr);
	if (ret) {
		log_dr_error("Unable to start listening for requests (%d)", ret);
		return false;
	}

	ret = pthread_create(&listen_thread, &attr, listen_threaded, &server_sock);
	if (ret)
		log_dr_error("Unable to start listening for requests (%d)", ret);

	pthread_attr_destroy(&attr);

	return ret == 0;
}

static void stop_listening_for_local_requests(void)
{
	server_sock_t sock = get_server_socket();

	stop_listening = true;

	if (sock.stop_pipe[1] > -1) {
		if (write(sock.stop_pipe[1], "!", 1) == -1)
			log_dr_error("Error trying to stop listening for requests: %s (%d)",
				strerror(errno), errno);
	}

	if (listen_thread_valid) {
		pthread_cancel(listen_thread);
		pthread_join(listen_thread, NULL);
		listen_thread_valid = false;
	}
}

cccs_comm_error_t cccs_add_request_target(char const * const target,
	cccs_request_data_cb_t data_cb, cccs_request_status_cb_t status_cb,
	cccs_resp_t *resp)
{
	return cccs_add_request_target_tout(target, data_cb, status_cb, 0, resp);
}

cccs_comm_error_t cccs_add_request_target_tout(char const * const target,
	cccs_request_data_cb_t data_cb, cccs_request_status_cb_t status_cb,
	unsigned long timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret = CCCS_SEND_ERROR_NONE;
	request_data_t *req_data = NULL;
	bool lock_acquired = false;

	resp->hint = NULL;

	if (!target) {
		log_dr_error("%s", "Invalid data request target");
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	if (!active_requests.lock) {
		active_requests.lock = get_lock();
		if (!active_requests.lock) {
			log_dr_error("Error adding target '%s': Unable to create lock, data request service busy",
					target);
			ret = CCCS_SEND_ERROR_LOCK;
			resp->code = ret;

			return ret;
		}
	}
	if (lock_acquire(active_requests.lock) != 0) {
		log_dr_error("Error adding target '%s': Unable to lock, data request service busy",
				target);
		lock_destroy(active_requests.lock);
		ret = CCCS_SEND_ERROR_LOCK;
		resp->code = ret;

		return ret;
	}
	lock_acquired = true;

	req_data = find_request_data(target);

	if (!req_data) {
		server_sock_t sock = get_server_socket();
		request_data_t new_req_data;

		if (sock.fd == -1) {
			ret = CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON;
			resp->code = ret;
			goto done;
		}

		ret = send_data_request_data(REQ_KEY_REGISTER_DR, sock.port,
			target, timeout, resp);
		if (ret)
			goto done;

		new_req_data.target = (char *)target;
		new_req_data.data_cb = data_cb;
		new_req_data.status_cb = status_cb;
		new_req_data.max_request_size = 0;

		if (add_registered_target(new_req_data)) {
			log_dr_error("Could not register '%s' data request: Out of memory",
					target);
			free(req_data);
			ret = -2;
			goto done;
		}
	} else {
		log_dr_warning("Target %s has been overriden by new callbacks",
				target);
		req_data->data_cb = data_cb;
		req_data->status_cb = status_cb;
		req_data->max_request_size = 0;
	}
done:
	if (lock_acquired && lock_release(active_requests.lock) != 0) {
		if (ret == CCCS_SEND_ERROR_NONE)
			ret = CCCS_SEND_ERROR_LOCK;
		log_dr_error("Error adding target '%s': Unable to release lock, data request service busy",
				target);
	}

	if (ret == CCCS_SEND_ERROR_NONE)
		listen_thread_valid = start_listening_for_requests();

	return ret;
}

cccs_comm_error_t cccs_remove_request_target(char const * const target, cccs_resp_t *resp)
{
	return cccs_remove_request_target_tout(target, 0, resp);
}

cccs_comm_error_t cccs_remove_request_target_tout(char const * const target, unsigned long timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret;

	resp->hint = NULL;

	if (!target) {
		log_dr_error("%s", "Invalid data request target");
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	if (active_requests.size == 0) {
		ret = CCCS_SEND_ERROR_NONE;
		resp->code = ret;

		return ret;
	}

	if (lock_acquire(active_requests.lock) != 0) {
		log_dr_error("Error removing target '%s': Unable to lock, data request service busy",
				target);
		ret = CCCS_SEND_ERROR_LOCK;
		resp->code = ret;

		return ret;
	}

	if (remove_registered_target(target)) {
		/*
		 * This should never happen, and if it does happen still 
		 * log the error but continue and try to remove from the server.
		 */
		log_dr_error("Could not remove registered target %s", target);
	}

	if (active_requests.size == 0)
		stop_listening_for_local_requests();

	ret = send_data_request_data(REQ_KEY_UNREGISTER_DR, server_sock.port, target, timeout, resp);

	if (lock_release(active_requests.lock) != 0) {
		log_dr_error("Error removing target '%s': Unable to release lock, data request service busy",
				target);
		if (ret == CCCS_SEND_ERROR_NONE)
			ret = CCCS_SEND_ERROR_LOCK;
	}

	if (active_requests.size == 0) {
		if (lock_destroy(active_requests.lock) != 0)
			log_dr_error("Error removing target '%s': Unable to destroy lock, data request service busy",
					target);
		active_requests.lock = NULL;
	}

	return ret;
}