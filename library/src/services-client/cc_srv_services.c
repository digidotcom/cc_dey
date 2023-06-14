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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "cc_logging.h"
#include "cc_srv_services.h"
#include "service_dp_upload.h"
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

/**
 * connect_cc_server() - Connect to Cloud Connector server
 *
 * Returns: The file descriptor if success, -1 otherwise.
 */
static int connect_cc_server(void)
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

/*
 * parse_cc_server_response() - Parse received response from Cloud Connector server
 *
 * @fd:		Socket to read response from.
 * @resp:	Buffer to store the response.
 * @timeout:	Number of seconds to wait for a response.
 *
 * Response may contain the result of the operation. It must be freed.
 *
 * Returns: 0 if no error messages received.
 *
 * Expects the reply sequence "i:0" or "i:1 b:error-msg".
 * Returns 0 if no error messages received:
 * -2 = out of memory
 * -1 = protocol errors
 *  0 = success
 *  1 = received error
 */
static int parse_cc_server_response(int fd, char **resp, unsigned long timeout)
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

/*
 * Reads a file into memory 
 *
 * @path:	Absolute path of the file to read.
 * @size:	Size of data read.
 *
 * Return: The data read.
 */
static char *read_csv_file(const char *path, size_t *size)
{
	size_t capacity = 0, read_len = 0;
	char *data = NULL, *tmp = NULL;
	struct stat sb;
	int fd = -1, len;

	if (!path) {
		log_srv_error("%s", "Invalid file path");
		return NULL;
	}

	log_srv_debug("Reading data points from '%s'", path);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		log_srv_error("Unable to open file '%s': %s (%d)", path, strerror(errno), errno);
		return NULL;
	}

	/* Preallocate if possible */
	if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_size < (long int)INT32_MAX) {
		capacity = sb.st_size;
		data = calloc(capacity, sizeof(char));
		if (!data) {
			log_srv_error("Unable to read file '%s': Out of memory", path);
			goto error;
		}
	}

	do {
		if (read_len + BUFSIZ >= capacity) {
			/* Grow buffer by BUFSIZ if exceeding capacity */
			tmp = realloc(data, capacity += BUFSIZ);
			if (!tmp) {
				log_srv_error("Unable to read file '%s': Out of memory", path);
				goto error;
			}
			data = tmp;
		}

		len = read(fd, data + read_len, capacity - read_len);
		if (len == -1) {
			log_srv_error("Unable to read file '%s': %s (%d)", path, strerror(errno), errno);
			goto error;
		}
		read_len += len;
	} while (len);

	if (read_len > 0) { /* To avoid a free */
		tmp = realloc(data, read_len);
		if (!tmp) {
			log_srv_error("Unable to read file '%s': Out of memory", path);
			goto error;
		}
		data = tmp;
	}

	goto done;

error:
	free(data);
	data = NULL;
	read_len = 0;

done:
	close(fd);
	*size = read_len;

	return data;
}

/*
 * send_dp_data() - Send data point data to Cloud Connector server
 *
 * @data:	Data points to send in csv format.
 * @length:	Total number of bytes to send.
 * @timeout:	Number of seconds to wait for a response from the server.
 * @resp:	The response from the server.
 *
 * Response may contain the result of the operation. It must be freed.
 *
 * Return: 0 if success, otherwise: 
 * 	-2 = out of memory
 * 	-1 = protocol errors
 * 	0 = success
 * 	1 = received error
 * 	2 = args error
 */
static int send_dp_data(const char *data, size_t length, unsigned long timeout, char **resp)
{
	int fd = -1, ret;

	if (!data || !length) {
		if (!data)
			log_srv_error("%s", "Unable to upload NULL");
		if (!length)
			log_srv_error("%s", "Number of bytes to upload must be greater than 0");
		return 2;
	}

	log_srv_info("%s", "Sending data points to Cloud Connector server");

	fd = connect_cc_server();
	if (fd < 0)
		return 2;

	if (write_string(fd, REQ_TAG_DP_FILE_REQUEST)			/* The request type */
		|| write_uint32(fd, upload_datapoint_file_metrics)	/* CSV data */
		|| write_blob(fd, data, length)
		|| write_uint32(fd, upload_datapoint_file_terminate)) { /* End of message */
		log_srv_error("Could not send data points request to Cloud Connector server: %s (%d)",
			strerror(errno), errno);
		ret = -1;
		goto done;
	}

	ret = parse_cc_server_response(fd, resp, timeout);

done:
	close(fd);

	return ret;
}

int cc_srv_send_dp_csv_file(const char *path, unsigned long const timeout, char **resp)
{
	char *data = NULL;
	size_t size = 0;
	int ret;

	data = read_csv_file(path, &size);
	if (!data)
		return 2;

	ret = send_dp_data(data, size, timeout, resp);

	free(data);

	if (ret == 0)
		log_srv_debug("Data points in '%s' uploaded", path);

	return ret;
}