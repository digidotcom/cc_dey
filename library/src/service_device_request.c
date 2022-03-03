/*
 * Copyright (c) 2022 Digi International Inc.
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

#include "cc_logging.h"
#include "ccapi/ccapi.h"
#include "services_util.h"
#include "service_device_request.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <malloc.h>

ccapi_receive_service_t receive_service = { NULL, NULL, NULL };

typedef struct {
	uint16_t port;
	char *target;
} request_data_t;

typedef struct {
#define INITIAL_MAX_SIZE 16
	request_data_t *array;
	size_t size;
	size_t max_size;
} request_data_darray_t;

static const char REQUEST_CB[] = "request";
static const char STATUS_CB[] = "status";

static request_data_darray_t active_requests = { 0 };

static const char *to_user_error_msg(ccapi_receive_error_t error) {
	switch (error) {
		case CCAPI_RECEIVE_ERROR_NONE:
			return "Success";
		case CCAPI_RECEIVE_ERROR_INVALID_TARGET:
			return "Invalid target";
		case CCAPI_RECEIVE_ERROR_TARGET_NOT_ADDED:
			return "Target is not registered";
		case CCAPI_RECEIVE_ERROR_TARGET_ALREADY_ADDED:
			return "Target already registered";
		case CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY:
			return "Out of memory";
		case CCAPI_RECEIVE_ERROR_STATUS_TIMEOUT:
			return "Timeout";
		default:
			log_error("unknown internal connection error: ccapi_receive_error_t[%d]", error);
			return "Internal connector error";
	}
}

static int add_registered_target(const request_data_t *target)
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

	active_requests.array[active_requests.size++] = *target;

	return 0;
}

static request_data_t *find_request_data(const char *target)
{
	size_t i;

	for (i = 0; i < active_requests.size; i++) {
		if (!strcmp(active_requests.array[i].target, target))
			return &active_requests.array[i];
	}

	return NULL;
}

static int remove_registered_target(const char * target) {
	request_data_t * req = find_request_data(target);
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

static int get_socket_for_target(const char *target)
{
	request_data_t *req = find_request_data(target);
	struct sockaddr_in serv_addr;
	int sock_fd = -1;
	int ret = -1; /* Assume error */

	if (!req) {
		log_error("Could not get port for registered target %s", target);
		goto out;
	}

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_error("Could not open socket to send device request: %s", strerror(errno));
		goto out;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(req->port);
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		log_error("Could not set serv_addr.sin_addr: %s", strerror(errno));
		goto out;
	}

	if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof serv_addr) < 0) {
		log_error("Could not connect to socket to deliver device request: %s", strerror(errno));
		goto out;
	}

	ret = 0;

out:
	if (ret == 0) {
		return sock_fd;
	} else {
		close(sock_fd);
		return ret;
	}
}

static ccapi_receive_error_t device_request(const char *target,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	int ret = 1; /* Assume errors */
	int sock_fd = get_socket_for_target(target);
	struct timeval timeout = {
		.tv_sec = SOCKET_READ_TIMEOUT_SEC,
		.tv_usec = 0
	};

	if (sock_fd < 0) {
		goto out;
	}

	/* Send: request_type, request_target_name, request_payload */
	if (write_string(sock_fd, REQUEST_CB)  ||											/* The request type */
		write_string(sock_fd, target) ||												/* The registered target device name */
		write_blob(sock_fd, request_buffer_info->buffer, request_buffer_info->length)) {/* The payload data passed to the device callback */
		log_error("Could not write device request to socket: %s", strerror(errno));
		goto out;
	}
	/* Read the blob response from the device */
	if (read_blob(sock_fd, &response_buffer_info->buffer, &response_buffer_info->length, &timeout)) {
		log_error("Could not recv device request data from socket: %s", strerror(errno));
		response_buffer_info->length = 0;
		goto out;
	}

	/* If we reach this point, all went well */
	ret = 0;

out:
	if (ret)
		/* An error ocurred, send empty response to DRM */
		response_buffer_info->length = 0;

	if (sock_fd >= 0)
		close(sock_fd);

	return CCAPI_RECEIVE_ERROR_NONE;
}

static void device_request_done(const char *target,
		ccapi_transport_t transport,
		ccapi_buffer_info_t *response_buffer_info,
		ccapi_receive_error_t receive_error)
{
	int error_code = receive_error;
	const char *err_msg = to_user_error_msg(receive_error);
	int sock_fd = get_socket_for_target(target);

	if (receive_error != CCAPI_RECEIVE_ERROR_NONE)
		log_error("Error on device request response, target='%s' - transport='%d' - error='%d'",
			target, transport, receive_error);

	if (sock_fd < 0)
		goto out;

	/* Send the status callback to the target device */
	if (write_string(sock_fd, STATUS_CB)	/* The Status callback type */
		|| write_string(sock_fd, target)		/* The registered target name */
		|| write_uint32(sock_fd, error_code)	/* The DRM call return status code */
		|| write_string(sock_fd, err_msg)) {		/* And a text description of the status code */
		log_error("Could not write device request to socket: %s", strerror(errno));
		goto out;
	}
out:
	if (response_buffer_info)
		free(response_buffer_info->buffer);

	if (sock_fd >= 0)
		close(sock_fd);
}

void builtin_request_done(const char *target,
		ccapi_transport_t transport,
		ccapi_buffer_info_t *response_buffer_info,
		ccapi_receive_error_t receive_error)
{
	if (receive_error != CCAPI_RECEIVE_ERROR_NONE)
		log_error("Error on device request response, target='%s' - transport='%d' - error='%d'",
			target, transport, receive_error);
}


ccapi_receive_error_t builtin_request(char *builtin,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	char *builtin_data = NULL;

	/* The request buffer is not null-terminated, so create a null-terminated string */
	if (request_buffer_info && request_buffer_info->buffer && request_buffer_info->length > 0) {
		builtin_data = malloc(request_buffer_info->length + sizeof(char));

		if (builtin_data) {
			memcpy(builtin_data, request_buffer_info->buffer, request_buffer_info->length);
			*(builtin_data + request_buffer_info->length) = 0;
		} else {
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}
	}
	pid_t pid = fork();
	if (pid == (pid_t) -1)
		return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;

	if (pid == (pid_t) 0) {
		pid = fork();
		if (pid == (pid_t) -1)
			exit(1);
		if (pid != (pid_t) 0)
			exit(0);

		if (builtin_data) {
			char *argv[] = {"/bin/remote_builtin", builtin, builtin_data, NULL};
			execv(argv[0], argv);
		} else {
			char *argv[] = {"/bin/remote_builtin", builtin, NULL};
			execv(argv[0], argv);
		}
		exit(1);

	} else {
		int status, ret;

		do {
			ret = waitpid(pid, &status, 0);
		} while (ret < 0 && errno == EINTR);

		if (builtin_data)
			free(builtin_data);

		if (!WIFEXITED(status) || WEXITSTATUS(status) || ret != pid)
			return CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;

		if (!strcmp(builtin, "subscriptions")) {
			response_buffer_info->buffer = strdup("{}");
			/* Ignore the NULL termination */
			response_buffer_info->length = 2 * sizeof(char);
		} else {
			response_buffer_info->length = 0;
		}
	}

	return CCAPI_RECEIVE_ERROR_NONE;
}

ccapi_receive_error_t builtin_request_speedtest(const char *target,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	return builtin_request("speedtest", transport, request_buffer_info, response_buffer_info);
}


ccapi_receive_error_t builtin_request_modem_firmware_update(const char *target,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	return builtin_request("modem_firmware_update", transport, request_buffer_info, response_buffer_info);
}

ccapi_receive_error_t builtin_request_edp_certificate_update(const char *target,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	return builtin_request("add_drm_certificate", transport, request_buffer_info, response_buffer_info);
}

ccapi_receive_error_t builtin_request_subscriptions(const char *target,
			   ccapi_transport_t transport,
			   const ccapi_buffer_info_t *request_buffer_info,
			   ccapi_buffer_info_t *response_buffer_info)
{
	return builtin_request("subscriptions", transport, request_buffer_info, response_buffer_info);
}

static int read_request(int fd, request_data_t *out)
{
	/* Receive a local device registration request */
	uint32_t end, port;
	struct timeval timeout = {
		.tv_sec = SOCKET_READ_TIMEOUT_SEC,
		.tv_usec = 0
	};

	if (read_uint32(fd, &port, &timeout)) {
		send_error(fd, "Failed to read port");
		return -1;
	}
	out->port = port;

	if (read_string(fd, &out->target, NULL, &timeout)) {
		send_error(fd, "Failed to read target");
		return -1;
	}

	if (read_uint32(fd, &end, &timeout) || end != 0) {
		send_error(fd, "Failed to read message end");
		return -1;
	}

	return 0;
}

static ccapi_receive_error_t unregister_target(const char *target)
{
	ccapi_receive_error_t ret = ccapi_receive_remove_target(target);

	if (ret != CCAPI_RECEIVE_ERROR_NONE)
		return ret;

	if (remove_registered_target(target)) {
		/*
		 * This should never happen, and if it does happen still return OK to
		 * the calling process, as the CCAPI did unregister the target
		 */
		log_error("Could not remove registered target %s", target);
	}

	return ret;
}

/* Note: fd is ignored if < 0 (when there is no need to write the error messages) */
static int register_device_request(int fd, const request_data_t *req_data)
{
	int result = 0;
	bool target_used = false;
	request_data_t *previously_registered_req = NULL;
	ccapi_receive_error_t status = ccapi_receive_add_target(req_data->target, device_request, device_request_done, CCAPI_RECEIVE_NO_LIMIT);

	if (status == CCAPI_RECEIVE_ERROR_TARGET_ALREADY_ADDED) {
		previously_registered_req = find_request_data(req_data->target);
		if (!previously_registered_req) {
			/* This should never happen */
			log_error("%s", "target already registered in CCAPI, but not registered on service_device_request!!");
			if (fd >= 0)
				send_error(fd, "Internal connector error");
		} else {
			log_warning("target %s has been overriden by new process listening on port %d",
				req_data->target, req_data->port);
			previously_registered_req->port = req_data->port;
		}
	} else if (status != CCAPI_RECEIVE_ERROR_NONE) {
		log_error("Could not register device request: %d\n", status);
		if (fd >= 0)
			send_error(fd, to_user_error_msg(status));
		result = status;
		goto exit;
	}

	if (!previously_registered_req) {
		if (add_registered_target(req_data)) {
			if (fd >= 0)
				send_error(fd, "Could not register device request, out of memory");
			result = -1;
		} else {
			target_used = true;
		}
	}

exit:
	if(!target_used)
		free(req_data->target);

	return result;
}

int handle_register_device_request(int fd)
{
	request_data_t req_data;

	if (read_request(fd, &req_data))
		return -1;

	if (register_device_request(fd, &req_data))
		return -1;

	send_ok(fd);

	return 0;
}

int handle_unregister_device_request(int fd)
{
	request_data_t req_data;
	ccapi_receive_error_t status;

	if (read_request(fd, &req_data))
		return -1;

	status = unregister_target(req_data.target);
	if (status != CCAPI_RECEIVE_ERROR_NONE) {
		send_error(fd, to_user_error_msg(status));
		return status;
	}

	send_ok(fd);

	return 0;
}

int import_devicerequests(const char *file_path)
{
	int ret = -1;
	size_t n;
	size_t i;
	FILE *file = fopen(file_path, "r");
	request_data_t temp;
	char *temp_string;
	size_t string_len;
	long fpos, flen;

	if (!file) {
		log_error("Could not read registered targets from %s: %s\n", file_path, strerror(errno));
		return -1;
	}

	if (fread(&n, sizeof n, 1, file) != 1) {
		log_error("Could not read number of registered targets: %s\n", strerror(errno));
		goto out;
	}

	for (i = 0; i < n; i++) {
		if (fread(&temp.port, sizeof temp.port, 1, file) != 1
			|| fread(&string_len, sizeof string_len, 1, file) != 1) {
			log_error("Could not read registered target %zu\n", i);
			goto out;
		}

		/* Verify that the str_len is at less than the EOF */
		fpos = ftell(file);
		if (fseek(file, 0, SEEK_END) != 0)
			goto out;

		flen = ftell(file);
		if (fpos < 0 || flen < 0 || flen < fpos || string_len <= 0 || string_len > (flen - fpos))
			goto out;

		if (fseek(file, fpos, SEEK_SET) != 0)
			goto out;

		temp_string = malloc(string_len + 1);
		/*
		 * We need to check for overflow (as this data can be exposed to an
		 * attacker). If there is an overflow it will be caused by string_len
		 * equalling the maximum memory and then the +1 causing the overflow.
		 * We can't just check that its equal in size as this will just check
		 * that 0 is equal to 0, we need to check that the allocated memory
		 * is greater than string_len as this means that it hasn't wrapped
		 * around e.g. 0 < 0xfffffffffff
		 */
		if (!temp_string || malloc_usable_size(temp_string) < (size_t) (string_len)) {
			log_error("%s", "Could not read registered target, out of memory\n");
			free(temp_string);
			goto out;
		}
		if (fread(temp_string, string_len, 1, file) != 1) {
			log_error("Could not read registered target %zu\n", i);
			free(temp_string);
			goto out;
		}
		temp_string[string_len] = '\0';
		temp.target = temp_string;

		if (register_device_request(-1, &temp))
			free(temp_string);
	}

out:
	fclose(file);

	return ret;
}

int dump_devicerequests(const char *file_path)
{
	int ret = -1;
	size_t n = active_requests.size;
	size_t i;
	FILE *file;

	if (active_requests.size == 0)
		return 0;

	if (!(file = fopen(file_path, "w"))) {
		log_error("Could not dump registered targets to %s: %s\n", file_path, strerror(errno));
		return -1;
	}

	if (fwrite(&n, sizeof n, 1, file) != 1) {
		log_error("Could not write registered targets: %s\n", strerror(errno));
		goto out;
	}

	for (i = 0; i < n; i++) {
		const request_data_t *dr = &active_requests.array[i];
		size_t target_len = strlen(dr->target);

		if (fwrite(&dr->port, sizeof dr->port, 1, file) != 1
			|| fwrite(&target_len, sizeof target_len, 1, file) != 1
			|| fwrite(dr->target, target_len, 1, file) != 1) {
			log_error("Could not write registered targets: %s\n", strerror(errno));
			goto out;
		}
	}

	ret = 0;

out:
	fclose(file);

	return ret;
}

