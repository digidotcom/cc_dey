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
#include <sys/stat.h>
#include <unistd.h>

#include "cc_logging.h"
/* Keep 'dp_csv_generator.h' before 'cccs_services.h' and '_cccs_utils.h' because:
  1. 'dp_csv_generator.h' includes 'ccimp/ccimp_types.h' where
     'ccapi_buffer_info_t' is defined.
  2. 'cccs_services.h' includes 'cccs_receive.h' that redefines
     'ccapi_buffer_info_t' only if 'ccimp/ccimp_types.h' is not included.
  3. '_cccs_utils.h' includes 'cccs_services.h' (see point 2) */
#include "dp_csv_generator.h"
#include "_cccs_utils.h"
#include "cccs_datapoints.h"
#include "cccs_services.h"
#include "service_dp_upload.h"
#include "services_util.h"

#define SERVICE_TAG	"DP:"

/**
 * log_dp_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_dp_debug(format, ...)					\
	log_debug("%s " format, SERVICE_TAG, __VA_ARGS__)

/**
 * log_dp_info() - Log the given message as info
 *
 * @format:		Warning message to log.
 * @args:		Additional arguments.
 */
#define log_dp_info(format, ...)					\
	log_info("%s " format, SERVICE_TAG, __VA_ARGS__)

/**
 * log_dp_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_dp_error(format, ...)					\
	log_error("%s " format, SERVICE_TAG, __VA_ARGS__)

typedef enum {
	CCAPI_DP_ARG_DATA_INT32,
	CCAPI_DP_ARG_DATA_INT64,
	CCAPI_DP_ARG_DATA_FLOAT,
	CCAPI_DP_ARG_DATA_DOUBLE,
	CCAPI_DP_ARG_DATA_STRING,
	CCAPI_DP_ARG_DATA_JSON,
	CCAPI_DP_ARG_DATA_GEOJSON,
	CCAPI_DP_ARG_TS_EPOCH,
	CCAPI_DP_ARG_TS_EPOCH_MS,
	CCAPI_DP_ARG_TS_ISO8601,
	CCAPI_DP_ARG_LOCATION,
	CCAPI_DP_ARG_QUALITY,
	CCAPI_DP_ARG_INVALID
} ccapi_dp_argument_t;

typedef struct ccapi_dp_data_stream {
	connector_data_stream_t *ccfsm_data_stream;
	struct {
		ccapi_dp_argument_t *list;
		unsigned int count;
	} arguments;
	struct ccapi_dp_data_stream * next;
} ccapi_dp_data_stream_t;

typedef struct ccapi_dp_collection {
	ccapi_dp_data_stream_t *ccapi_data_stream_list;
	uint32_t dp_count;
	void * lock;
} ccapi_dp_collection_t;

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
		log_dp_error("%s", "Invalid file path");
		return NULL;
	}

	log_dp_debug("Reading data points from '%s'", path);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		log_dp_error("Unable to open file '%s': %s (%d)", path, strerror(errno), errno);
		return NULL;
	}

	/* Preallocate if possible */
	if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_size < (long int)INT32_MAX) {
		capacity = sb.st_size;
		data = calloc(capacity, sizeof(char));
		if (!data) {
			log_dp_error("Unable to read file '%s': Out of memory", path);
			goto error;
		}
	}

	do {
		if (read_len + BUFSIZ >= capacity) {
			/* Grow buffer by BUFSIZ if exceeding capacity */
			tmp = realloc(data, capacity += BUFSIZ);
			if (!tmp) {
				log_dp_error("Unable to read file '%s': Out of memory", path);
				goto error;
			}
			data = tmp;
		}

		len = read(fd, data + read_len, capacity - read_len);
		if (len == -1) {
			log_dp_error("Unable to read file '%s': %s (%d)", path, strerror(errno), errno);
			goto error;
		}
		read_len += len;
	} while (len);

	if (read_len > 0) { /* To avoid a free */
		tmp = realloc(data, read_len);
		if (!tmp) {
			log_dp_error("Unable to read file '%s': Out of memory", path);
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
 * @resp:	Received response from Cloud Connector server.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CC_SRV_SEND_ERROR_NONE if success, any other error if the
 *         communication with the service fails.
 */
static cc_srv_comm_error_t send_dp_data(const char *data, size_t length, unsigned long timeout, cc_srv_resp_t *resp)
{
	cc_srv_comm_error_t ret = CC_SRV_SEND_ERROR_NONE;
	int fd = -1;

	if (!data || !length) {
		if (!data)
			log_dp_error("%s", "Unable to upload NULL");
		if (!length)
			log_dp_error("%s", "Number of bytes to upload must be greater than 0");
		ret = CC_SRV_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	log_dp_info("%s", "Sending data points to CCCSD");

	fd = connect_cc_server();
	if (fd < 0) {
		ret = CC_SRV_SEND_UNABLE_TO_CONNECT_TO_SRV;
		resp->code = ret;

		return ret;
	}

	if (write_string(fd, REQ_TAG_DP_FILE_REQUEST)			/* The request type */
		|| write_uint32(fd, upload_datapoint_file_metrics)	/* CSV data */
		|| write_blob(fd, data, length)
		|| write_uint32(fd, upload_datapoint_file_terminate)) { /* End of message */
		log_dp_error("Could not send data points request to CCCSD: %s (%d)",
			strerror(errno), errno);
		ret = CC_SRV_SEND_ERROR_BAD_RESPONSE;
		resp->code = ret;
		goto done;
	}

	ret = parse_cc_server_response(fd, resp, timeout);

done:
	close(fd);

	return ret;
}

cc_srv_comm_error_t cc_srv_send_dp_csv_file(const char *path, unsigned long const timeout, cc_srv_resp_t *resp)
{
	char *data = NULL;
	size_t size = 0;
	cc_srv_comm_error_t ret;

	resp->hint = NULL;

	data = read_csv_file(path, &size);
	if (!data) {
		ret = CC_SRV_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	ret = send_dp_data(data, size, timeout, resp);
	if (ret == CC_SRV_SEND_ERROR_NONE)
		log_dp_debug("Data points in '%s' uploaded", path);

	free(data);

	return ret;
}

/*
 * dp_generate_csv() - Generate the CSV contents in memory to send to the server
 *
 * @dp_collection:	Data point collection to send.
 * @buf_info:		The buffer with the generated CSV.
 *
 * Buffer contains the result of the operation. It must be freed.
 *
 * Return: The size of the CSV buffer, -1 if error.
 */
static size_t dp_generate_csv(ccapi_dp_collection_t * const dp_collection, buffer_info_t *buf_info)
{
	csv_process_data_t process_data;

	process_data.current_csv_field = csv_data;
	process_data.current_data_stream = dp_collection->ccapi_data_stream_list->ccfsm_data_stream;
	process_data.current_data_point = dp_collection->ccapi_data_stream_list->ccfsm_data_stream->point;
	process_data.data.init = false;

	buf_info->bytes_written = 0;
	buf_info->bytes_available = 0;

	buf_info->buffer = calloc(BUFSIZ, sizeof(*buf_info->buffer));
	if (!buf_info->buffer) {
		log_dp_error("Unable to generate data to send to CCCSD: %s", "Out of memory");
		return -1;
	}
	buf_info->bytes_available = BUFSIZ;

	return generate_dp_csv(&process_data, buf_info);
}

static void chain_collection_ccfsm_data_streams(ccapi_dp_collection_t * const dp_collection)
{
	ccapi_dp_data_stream_t *current_ds = dp_collection->ccapi_data_stream_list;

	while (current_ds != NULL) {
		connector_data_stream_t *const ccfsm_ds = current_ds->ccfsm_data_stream;
		ccapi_dp_data_stream_t *const next_ds = current_ds->next;

		if (next_ds != NULL)
			ccfsm_ds->next = next_ds->ccfsm_data_stream;

		current_ds = current_ds->next;
	}
}

/*
 * dp_free_data_point() - Free the provided data point
 *
 * @data_point:	The data point to free.
 * @type:	The type of the data point.
 */
static void dp_free_data_point(connector_data_point_t * data_point, connector_data_point_type_t type)
{
	if (data_point == NULL)
		return;

	switch (type) {
		case connector_data_point_type_string:
		{
			free(data_point->data.element.native.string_value);
			break;
		}
		case connector_data_point_type_integer:
		case connector_data_point_type_long:
		case connector_data_point_type_float:
		case connector_data_point_type_double:
		case connector_data_point_type_binary:
		case connector_data_point_type_json:
		case connector_data_point_type_geojson:
			break;
	}

	switch(data_point->time.source) {
		case connector_time_local_iso8601:
		{
			free(data_point->time.value.iso8601_string);
			break;
		}
		case connector_time_cloud:
		case connector_time_local_epoch_fractional:
		case connector_time_local_epoch_whole:
			break;
	}
	free(data_point);
}

/*
 * dp_free_data_points_in_data_stream() - Free all data points in data stream
 *
 * @data_stream:	Data stream to free.
 *
 * Return: Number of freed data points.
 */
static unsigned int dp_free_data_points_in_data_stream(connector_data_stream_t * data_stream)
{
	connector_data_point_t * data_point = data_stream->point;
	unsigned int dp_count = 0;

	while (data_point != NULL) {
		connector_data_point_t * const next_point = data_point->next;

		dp_free_data_point(data_point, data_stream->type);

		data_point = next_point;
		dp_count++;
	}

	return dp_count;
}

/*
 * dp_free_data_points_from_collection() - Free data points in the provided collection
 *
 * @dp_collection:	The data point collection with data points to free.
 */
static void dp_free_data_points_from_collection(ccapi_dp_collection_t * const dp_collection)
{
	ccapi_dp_data_stream_t *current_ds = dp_collection->ccapi_data_stream_list;

	while (current_ds != NULL) {
		connector_data_stream_t * const ccfsm_ds = current_ds->ccfsm_data_stream;
		ccapi_dp_data_stream_t const * const next_ds = current_ds->next;

		if (next_ds != NULL)
			ccfsm_ds->next = next_ds->ccfsm_data_stream;

		dp_free_data_points_in_data_stream(ccfsm_ds);
		ccfsm_ds->point = NULL;
		current_ds = current_ds->next;
	}
	dp_collection->dp_count = 0;
}

/*
 * dp_send_collection() - Send data point collection to Cloud Connector server
 *
 * @dp_collection:	Data point collection to send.
 * @timeout:		Number of seconds to wait for a response from the server.
 * @resp:		Received response from Cloud Connector server.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CC_SRV_SEND_ERROR_NONE if success, any other error if the
 *         communication with the service fails.
 */
static cc_srv_comm_error_t dp_send_collection(ccapi_dp_collection_t * const dp_collection,
	unsigned long const timeout, cc_srv_resp_t *resp)
{
	cc_srv_comm_error_t ret = CC_SRV_SEND_ERROR_NONE;
	bool collection_lock_acquired = false;
	buffer_info_t buf_info;

	resp->hint = NULL;

	if (dp_collection == NULL || dp_collection->ccapi_data_stream_list == NULL) {
		log_dp_error("%s", "Invalid data point collection");
		ret = CC_SRV_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	/* TODO check if it is running */

	if (lock_acquire(dp_collection->lock) != 0) {
		log_dp_error("Data point collection %s", "busy");
		ret = CC_SRV_SEND_ERROR_LOCK;
		resp->code = ret;

		return ret;
	}
	collection_lock_acquired = true;

	chain_collection_ccfsm_data_streams(dp_collection);

	if (dp_generate_csv(dp_collection, &buf_info) > 0) {
		ret = send_dp_data(buf_info.buffer, buf_info.bytes_written, timeout, resp);
	} else {
		ret = CC_SRV_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;
	}

	free(buf_info.buffer);

	dp_free_data_points_from_collection(dp_collection);

	if (collection_lock_acquired && lock_release(dp_collection->lock) != 0) {
		if (ret == CC_SRV_SEND_ERROR_NONE)
			ret = CC_SRV_SEND_ERROR_LOCK;
		log_dp_error("Data point collection %s", "busy");
	}

	return ret;
}

cc_srv_comm_error_t cc_srv_send_dp_collection(ccapi_dp_collection_t *const dp_collection, cc_srv_resp_t *resp)
{
	return dp_send_collection(dp_collection, CCAPI_DP_WAIT_FOREVER, resp);
}

cc_srv_comm_error_t cc_srv_send_dp_collection_with_timeout(ccapi_dp_collection_t *const dp_collection,
	unsigned long const timeout, cc_srv_resp_t *resp)
{
	return dp_send_collection(dp_collection, timeout, resp);
}
