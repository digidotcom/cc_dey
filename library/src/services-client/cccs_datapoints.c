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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ccimp/ccimp_types.h"
#include "ccapi/ccapi_transport.h"
#include "ccapi/ccapi_datapoints.h"

#include "_cccs_utils.h"
#include "cc_logging.h"
#include "cc_utils.h"
#include "cccs_datapoints.h"
#include "cccs_services.h"
#include "dp_csv_generator.h"
#include "service_common.h"
#include "services_util.h"
#include "_utils.h"

#define SERVICE_TAG	"DP:"

/* For internal use only */
#define CCCS_DP_KEY_TS_EPOCH		"ts_epoch"
#define CCCS_DP_KEY_TS_EPOCH_MS		"ts_epoch_ms"
#define CCCS_DP_KEY_TS_ISO8601		"ts_iso"

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
	CCCS_DP_ARG_DATA_INT32,
	CCCS_DP_ARG_DATA_INT64,
	CCCS_DP_ARG_DATA_FLOAT,
	CCCS_DP_ARG_DATA_DOUBLE,
	CCCS_DP_ARG_DATA_STRING,
	CCCS_DP_ARG_DATA_JSON,
	CCCS_DP_ARG_DATA_GEOJSON,
	CCCS_DP_ARG_TS_EPOCH,
	CCCS_DP_ARG_TS_EPOCH_MS,
	CCCS_DP_ARG_TS_ISO8601,
	CCCS_DP_ARG_LOCATION,
	CCCS_DP_ARG_QUALITY,
	CCCS_DP_ARG_INVALID
} cccs_dp_argument_t;

typedef struct cccs_dp_data_stream {
	connector_data_stream_t *ccfsm_data_stream;
	struct {
		cccs_dp_argument_t *list;
		unsigned int count;
	} arguments;
	struct cccs_dp_data_stream *next;
} cccs_dp_data_stream_t;

typedef struct ccapi_dp_collection {
	cccs_dp_data_stream_t *cccs_data_stream_list;
	uint32_t dp_count;
	void * lock;
} cccs_dp_collection_t;

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
 * send_dp_data() - Send data point data to CCCS daemon
 *
 * @data:	Data points to send in csv format.
 * @length:	Total number of bytes to send.
 * @timeout:	Number of seconds to wait for a response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
static cccs_comm_error_t send_dp_data(const char *data, size_t length, unsigned long timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret = CCCS_SEND_ERROR_NONE;
	int fd = -1;

	if (!data || !length) {
		if (!data)
			log_dp_error("%s", "Unable to upload NULL");
		if (!length)
			log_dp_error("%s", "Number of bytes to upload must be greater than 0");
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	log_dp_info("%s", "Sending data points to CCCSD");

	fd = connect_cccsd();
	if (fd < 0) {
		ret = CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON;
		resp->code = ret;

		return ret;
	}

	if (write_string(fd, REQ_TAG_DP_FILE_REQUEST)			/* The request type */
		|| write_uint32(fd, upload_datapoint_file_metrics)	/* CSV data */
		|| write_blob(fd, data, length)
		|| write_uint32(fd, upload_datapoint_file_terminate)) { /* End of message */
		log_dp_error("Could not send data points request to CCCSD: %s (%d)",
			strerror(errno), errno);
		ret = CCCS_SEND_ERROR_BAD_RESPONSE;
		resp->code = ret;
		goto done;
	}

	ret = parse_cccsd_response(fd, resp, timeout);

done:
	close(fd);

	return ret;
}

cccs_comm_error_t cccs_send_dp_csv_file(const char *path, unsigned long const timeout, cccs_resp_t *resp)
{
	char *data = NULL;
	size_t size = 0;
	cccs_comm_error_t ret;

	resp->hint = NULL;

	data = read_csv_file(path, &size);
	if (!data) {
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	ret = send_dp_data(data, size, timeout, resp);
	if (ret == CCCS_SEND_ERROR_NONE)
		log_dp_debug("Data points in '%s' uploaded", path);

	free(data);

	return ret;
}

/*
 * dp_generate_csv() - Generate the CSV contents in memory to send to the daemon
 *
 * @collection:	Data point collection to send.
 * @buf_info:	The buffer with the generated CSV.
 *
 * Buffer contains the result of the operation. It must be freed.
 *
 * Return: The size of the CSV buffer, -1 if error.
 */
static size_t dp_generate_csv(cccs_dp_collection_t * const collection, buffer_info_t *buf_info)
{
	csv_process_data_t process_data;

	process_data.current_csv_field = csv_data;
	process_data.current_data_stream = collection->cccs_data_stream_list->ccfsm_data_stream;
	process_data.current_data_point = collection->cccs_data_stream_list->ccfsm_data_stream->point;
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

static void chain_collection_ccfsm_data_streams(cccs_dp_collection_t * const collection)
{
	cccs_dp_data_stream_t *current_ds = collection->cccs_data_stream_list;

	while (current_ds != NULL) {
		connector_data_stream_t *const ccfsm_ds = current_ds->ccfsm_data_stream;
		cccs_dp_data_stream_t *const next_ds = current_ds->next;

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
 * @collection:	The data point collection with data points to free.
 */
static void dp_free_data_points_from_collection(cccs_dp_collection_t * const collection)
{
	cccs_dp_data_stream_t *current_ds = collection->cccs_data_stream_list;

	while (current_ds != NULL) {
		connector_data_stream_t * const ccfsm_ds = current_ds->ccfsm_data_stream;
		cccs_dp_data_stream_t const * const next_ds = current_ds->next;

		if (next_ds != NULL)
			ccfsm_ds->next = next_ds->ccfsm_data_stream;

		dp_free_data_points_in_data_stream(ccfsm_ds);
		ccfsm_ds->point = NULL;
		current_ds = current_ds->next;
	}
	collection->dp_count = 0;
}

/*
 * dp_send_collection() - Send data point collection to CCCS daemon
 *
 * @collection:	Data point collection to send.
 * @timeout:	Number of seconds to wait for a response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
static cccs_comm_error_t dp_send_collection(cccs_dp_collection_t * const collection,
	unsigned long const timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret = CCCS_SEND_ERROR_NONE;
	bool collection_lock_acquired = false;
	buffer_info_t buf_info;

	resp->hint = NULL;

	if (collection == NULL || collection->cccs_data_stream_list == NULL) {
		log_dp_error("%s", "Invalid data point collection");
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;

		return ret;
	}

	/* TODO check if it is running */

	if (lock_acquire(collection->lock) != 0) {
		log_dp_error("Data point collection %s", "busy");
		ret = CCCS_SEND_ERROR_LOCK;
		resp->code = ret;

		return ret;
	}
	collection_lock_acquired = true;

	chain_collection_ccfsm_data_streams(collection);

	if (dp_generate_csv(collection, &buf_info) > 0) {
		ret = send_dp_data(buf_info.buffer, buf_info.bytes_written, timeout, resp);
	} else {
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;
	}

	free(buf_info.buffer);

	dp_free_data_points_from_collection(collection);

	if (collection_lock_acquired && lock_release(collection->lock) != 0) {
		if (ret == CCCS_SEND_ERROR_NONE)
			ret = CCCS_SEND_ERROR_LOCK;
		log_dp_error("Data point collection %s", "busy");
	}

	return ret;
}

cccs_comm_error_t cccs_send_dp_collection(cccs_dp_collection_t *const collection, cccs_resp_t *resp)
{
	return dp_send_collection(collection, CCCS_DP_WAIT_FOREVER, resp);
}

cccs_comm_error_t cccs_send_dp_collection_tout(cccs_dp_collection_t *const collection,
	unsigned long const timeout, cccs_resp_t *resp)
{
	return dp_send_collection(collection, timeout, resp);
}

cccs_dp_error_t cccs_dp_create_collection(cccs_dp_collection_handle_t *const collection)
{
	return (cccs_dp_error_t) ccapi_dp_create_collection(collection);
}

cccs_dp_error_t cccs_dp_clear_collection(cccs_dp_collection_handle_t const collection)
{
	return (cccs_dp_error_t) ccapi_dp_clear_collection(collection);
}

cccs_dp_error_t cccs_dp_destroy_collection(cccs_dp_collection_handle_t const collection)
{
	return (cccs_dp_error_t)ccapi_dp_destroy_collection(collection);
}

cccs_dp_error_t cccs_dp_add_data_stream_to_collection(
	cccs_dp_collection_handle_t const collection,
	char const * const stream_id,
	char const * const format_string,
	bool add_local_timestamp)
{
	return (cccs_dp_error_t) cccs_dp_add_data_stream_to_collection_extra(collection, stream_id, format_string, add_local_timestamp, NULL, NULL);
}

static char *rm_substring(char *str, const char *rm_str) {
	char *end_rm_ptr = NULL, *end_valid_prt = NULL, *rm_ptr = NULL;
	size_t len;

	if (!str || !rm_str || !*str || !*rm_str)
		return str;

	end_valid_prt = strstr(str, rm_str);
	if (!end_valid_prt)
		return str;

	len = strlen(rm_str);
	rm_ptr = end_valid_prt;

	while ((rm_ptr = strstr(end_rm_ptr = rm_ptr + len, rm_str)) != NULL) {
		int n_bytes_to_move = rm_ptr - end_rm_ptr;

		memmove(end_valid_prt, end_rm_ptr, n_bytes_to_move);
		end_valid_prt += n_bytes_to_move;
	}

	memmove(end_valid_prt, end_rm_ptr, strlen(end_rm_ptr) + 1);

	return str;
}

cccs_dp_error_t cccs_dp_add_data_stream_to_collection_extra(
	cccs_dp_collection_handle_t const collection,
	char const * const stream_id,
	char const * const format_string,
	bool add_local_timestamp,
	char const * const units,
	char const * const forward_to)
{
	cccs_dp_error_t ret;
	char *new_fs = NULL;

	if (add_local_timestamp
	    /*  Avoid adding the key if it is already there */
	    && !strstr(format_string, CCCS_DP_KEY_TS_ISO8601)
	    && !strstr(format_string, CCCS_DP_KEY_TS_EPOCH_MS)
	    && !strstr(format_string, CCCS_DP_KEY_TS_EPOCH)) {
		int len = snprintf(NULL, 0, "%s " CCCS_DP_KEY_TS_EPOCH, format_string);

		new_fs = calloc(len + 1, sizeof(*new_fs));
		if (new_fs) {
			sprintf(new_fs, "%s " CCCS_DP_KEY_TS_EPOCH, format_string);
			new_fs = trim(new_fs);
		} else {
			log_dp_error("Unable to add timeout to data stream format: %s", "Out of memory");
		}
	} else if (!add_local_timestamp
		/* Remove key if it is already there */
		&& (strstr(format_string, CCCS_DP_KEY_TS_ISO8601)
			|| strstr(format_string, CCCS_DP_KEY_TS_EPOCH_MS)
			|| strstr(format_string, CCCS_DP_KEY_TS_EPOCH))) {
		new_fs = strdup(format_string);
		if (new_fs) {
			new_fs = rm_substring(new_fs, CCCS_DP_KEY_TS_ISO8601);
			new_fs = rm_substring(new_fs, CCCS_DP_KEY_TS_EPOCH_MS);
			new_fs = rm_substring(new_fs, CCCS_DP_KEY_TS_EPOCH);

			new_fs = trim(new_fs);
		} else {
			log_dp_error("Unable to add timeout to data stream format: %s", "Out of memory");
		}
	}

	if (!new_fs)
		new_fs = (char *)format_string;

	ret = (cccs_dp_error_t) ccapi_dp_add_data_stream_to_collection_extra(collection, stream_id, new_fs, units, forward_to);

	if (new_fs != format_string)
		free(new_fs);

	return ret;
}

cccs_dp_error_t cccs_dp_remove_data_stream_from_collection(
	cccs_dp_collection_handle_t const collection,
	char const * const stream_id)
{
	return (cccs_dp_error_t) ccapi_dp_remove_data_stream_from_collection(collection, stream_id);
}

cccs_dp_error_t cccs_dp_get_collection_points_count(
	cccs_dp_collection_handle_t const collection,
	uint32_t * const count)
{
	return (cccs_dp_error_t) ccapi_dp_get_collection_points_count(collection, count);
}

static cccs_dp_data_stream_t *find_stream_id_in_collection(cccs_dp_collection_t * const collection, char const * const stream_id)
{
	cccs_dp_data_stream_t *current_ds = collection->cccs_data_stream_list;
	cccs_dp_data_stream_t *data_stream = NULL;

	while (current_ds != NULL) {
		if (strcmp(stream_id, current_ds->ccfsm_data_stream->stream_id) == 0) {
			data_stream = current_ds;
			goto done;
		}
		current_ds = current_ds->next;
	}

done:
	return data_stream;
}

static cccs_dp_error_t parse_arg_list_and_create_dp(
	/*int n_args, */va_list *arg_list, cccs_dp_data_stream_t * const data_stream,
	connector_data_point_t * * const new_data_point)
{
	cccs_dp_argument_t * const arg = data_stream->arguments.list;
	int const fmt_count = data_stream->arguments.count;
	connector_data_point_t *datapoint = calloc(1, sizeof (*datapoint));
	cccs_dp_error_t ret = CCCS_DP_ERROR_NONE;
	int i;
	va_list arg_list_copy;

	if (!datapoint) {
		ret = CCCS_DP_ERROR_INSUFFICIENT_MEMORY;
		goto done;
	}

	datapoint->data.type = connector_data_type_native;
	datapoint->quality.type = connector_quality_type_ignore;
	datapoint->location.type = connector_location_type_ignore;
	datapoint->time.source = connector_time_cloud;

	datapoint->description = NULL;
	datapoint->data.element.native.string_value = NULL;
	datapoint->time.value.iso8601_string = NULL;

	va_copy(arg_list_copy, *arg_list);

	for (i = 0; i < fmt_count; i++) {
		switch (arg[i]) {
			case CCCS_DP_ARG_DATA_INT32:
				{
					datapoint->data.element.native.int_value = va_arg(arg_list_copy, int32_t);
					break;
				}
			case CCCS_DP_ARG_DATA_INT64:
				{
					datapoint->data.element.native.long_value = va_arg(arg_list_copy, int64_t);
					break;
				}
			case CCCS_DP_ARG_DATA_FLOAT:
				{
					double const aux = va_arg(arg_list_copy, double); /* ‘float’ is promoted to ‘double’ when passed through ‘...’ */
					datapoint->data.element.native.float_value = (float)aux;
					break;
				}
			case CCCS_DP_ARG_DATA_DOUBLE:
				{
					datapoint->data.element.native.double_value = va_arg(arg_list_copy, double);
					break;
				}
			case CCCS_DP_ARG_DATA_STRING:
			case CCCS_DP_ARG_DATA_JSON:
			case CCCS_DP_ARG_DATA_GEOJSON:
				{
					char const * const string_dp = va_arg(arg_list_copy, char const * const);

					datapoint->data.element.native.string_value = strdup(string_dp);
					if (datapoint->data.element.native.string_value == NULL) {
						ret = CCCS_DP_ERROR_INSUFFICIENT_MEMORY;
						goto done;
					}
					break;
				}
			case CCCS_DP_ARG_TS_EPOCH:
				{
					ccapi_timestamp_t *timestamp = get_timestamp_by_type(CCCS_TS_EPOCH);

					if (!timestamp) {
						ret = CCCS_DP_ERROR_INSUFFICIENT_MEMORY;
						goto done;
					}

					datapoint->time.source = connector_time_local_epoch_fractional;
					datapoint->time.value.since_epoch_fractional.seconds = timestamp->epoch.seconds;
					datapoint->time.value.since_epoch_fractional.milliseconds = timestamp->epoch.milliseconds;

					/*if (i == n_args)
						free_timestamp(timestamp);*/
					free_timestamp_by_type(timestamp, CCCS_TS_EPOCH);
					break;
				}
			case CCCS_DP_ARG_TS_EPOCH_MS:
				{
					ccapi_timestamp_t *timestamp = get_timestamp_by_type(CCCS_TS_EPOCH_MS);

					if (!timestamp) {
						ret = CCCS_DP_ERROR_INSUFFICIENT_MEMORY;
						goto done;
					}

					datapoint->time.source = connector_time_local_epoch_whole;
					datapoint->time.value.since_epoch_whole.milliseconds = timestamp->epoch_msec;

					free_timestamp_by_type(timestamp, CCCS_TS_EPOCH_MS);
					break;
				}
			case CCCS_DP_ARG_TS_ISO8601:
				{
					ccapi_timestamp_t *timestamp = get_timestamp_by_type(CCCS_TS_ISO8601);

					if (!timestamp) {
						ret = CCCS_DP_ERROR_INSUFFICIENT_MEMORY;
						goto done;
					}

					datapoint->time.source = connector_time_local_iso8601;
					datapoint->time.value.iso8601_string = strdup(timestamp->iso8601);
					if (datapoint->time.value.iso8601_string == NULL)
						ret = CCCS_DP_ERROR_INSUFFICIENT_MEMORY;

					free_timestamp_by_type(timestamp, CCCS_TS_EPOCH_MS);

					if (ret != CCCS_DP_ERROR_NONE)
						goto done;
					break;
				}
			case CCCS_DP_ARG_LOCATION:
				{
					ccapi_location_t const * const location = va_arg(arg_list_copy, ccapi_location_t *);

					datapoint->location.type = connector_location_type_native;
					datapoint->location.value.native.latitude = location->latitude;
					datapoint->location.value.native.longitude = location->longitude;
					datapoint->location.value.native.elevation = location->elevation;
					break;
				}
			case CCCS_DP_ARG_QUALITY:
				{
					datapoint->quality.type = connector_quality_type_native;
					datapoint->quality.value = (int)va_arg(arg_list_copy, int32_t);
					break;
				}
			case CCCS_DP_ARG_INVALID:
				{
					ret = CCCS_DP_ERROR_INVALID_ARGUMENT;
					goto done;
				}
		}
	}
done:
	if (datapoint && ret != CCCS_DP_ERROR_NONE) {
		free(datapoint->data.element.native.string_value);
		free(datapoint->time.value.iso8601_string);
		free(datapoint);
		datapoint = NULL;
	}

	va_end(arg_list_copy);

	*new_data_point = datapoint;

	return ret;
}

cccs_dp_error_t cccs_dp_add(cccs_dp_collection_handle_t const collection, char const * const stream_id, ...)
{
	cccs_dp_error_t ret = CCCS_DP_ERROR_NONE;
	cccs_dp_data_stream_t *data_stream;

	if (!collection)
		return CCCS_DP_ERROR_INVALID_ARGUMENT;

	if (lock_acquire(collection->lock) != 0) {
		log_dp_error("Data point collection %s", "busy");

		return CCCS_DP_ERROR_LOCK_FAILED;
	}

	data_stream = find_stream_id_in_collection(collection, stream_id);
	if (!data_stream) {
		ret = CCCS_DP_ERROR_INVALID_STREAM_ID;
		goto done;
	}

	{
		connector_data_point_t *datapoint = NULL;
		va_list arg_list;

		va_start(arg_list, stream_id);
		ret = parse_arg_list_and_create_dp(&arg_list, data_stream, &datapoint);
		va_end(arg_list);

		if (ret == CCCS_DP_ERROR_NONE && !datapoint)
			ret = CCCS_DP_ERROR_INVALID_ARGUMENT;

		if (ret != CCCS_DP_ERROR_NONE)
			goto done;

		datapoint->next = data_stream->ccfsm_data_stream->point;
		data_stream->ccfsm_data_stream->point = datapoint;
		collection->dp_count += 1;
	}
done:
	if (lock_release(collection->lock) != 0) {
		if (ret == CCCS_DP_ERROR_NONE)
			ret = CCCS_DP_ERROR_LOCK_FAILED;
		log_dp_error("Data point collection %s", "busy");
	}

	return ret;
}

cccs_dp_error_t cccs_dp_remove_older_data_point_from_streams(cccs_dp_collection_handle_t const collection)
{
	return (cccs_dp_error_t) ccapi_dp_remove_older_data_point_from_streams(collection);
}
