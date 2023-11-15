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
#include "_cc_datapoints.h"
#include "cc_logging.h"
#include "cc_utils.h"
#include "cccs_datapoints.h"
#include "cccs_services.h"
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

typedef union {
	struct {
		char *data;
		size_t length;
		char *stream_id;
	} blob;
	struct {
		char *path;
		char *stream_id;
	} file;
} cccs_dp_data_t;

/*
 * send_dp_data_type() - Send data point data to CCCS daemon
 *
 * @fd:		Socket file descriptor.
 * @type:	Type of the data to upload: 'upload_datapoint_file_metrics' or
 *		'upload_datapoint_file_path_metrics' or
 *		'upload_datapoint_file_metrics_binary' or
 *		'upload_datapoint_file_path_binary'.
 * @data:	Data points data to send.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
static cccs_comm_error_t send_dp_data_type(int fd, upload_datapoint_file_t type, cccs_dp_data_t data)
{
	switch (type) {
		case upload_datapoint_file_metrics:
		case upload_datapoint_file_metrics_binary:
			if (write_string(fd, REQ_TAG_DP_FILE_REQUEST)						/* The request type */
				|| write_uint32(fd, type)							/* CSV data or binary data*/
				|| write_blob(fd, data.blob.data, data.blob.length)				/* Data */
				|| (data.blob.stream_id != NULL && write_string(fd, data.blob.stream_id))	/* Stream id, only for binary data */
				|| write_uint32(fd, upload_datapoint_file_terminate)) {				/* End of message */
				log_dp_error("Could not send data points request to CCCSD: %s (%d)",
					strerror(errno), errno);

				return CCCS_SEND_ERROR_BAD_RESPONSE;
			}
			break;
		case upload_datapoint_file_path_metrics:;
		case upload_datapoint_file_path_binary:
			if (write_string(fd, REQ_TAG_DP_FILE_REQUEST)						/* The request type */
				|| write_uint32(fd, type)							/* CSV or Binary File path */
				|| write_string(fd, data.file.path)						/* Path of file to send */
				|| (data.file.stream_id != NULL && write_string(fd, data.file.stream_id))	/* Stream id, only for binary file */
				|| write_uint32(fd, upload_datapoint_file_terminate)) {				/* End of message */
				log_dp_error("Could not send data points file '%s' to CCCSD: %s (%d)",
					data.file.path, strerror(errno), errno);

				return CCCS_SEND_ERROR_BAD_RESPONSE;
			}
			break;
		default:
			/* Should not occur */
			break;
	}

	return CCCS_SEND_ERROR_NONE;
}

/*
 * send_dp_data() - Send data point data to CCCS daemon
 *
 * @type:	Type of the data to upload: 'upload_datapoint_file_metrics' or
 *		'upload_datapoint_file_path_metrics' or
 *		'upload_datapoint_file_metrics_binary' or
 *		'upload_datapoint_file_path_binary'.
 * @data:	Data points data to send.
 * @timeout:	Number of seconds to wait for a response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
static cccs_comm_error_t send_dp_data(upload_datapoint_file_t type, cccs_dp_data_t data, unsigned long timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret = CCCS_SEND_ERROR_NONE;
	int fd = -1;
	cccs_srv_resp_t cccs_resp = {
		.srv_err = 0,
		.ccapi_err = 0,
		.cccs_err = 0,
		.hint = NULL
	};

	if (type != upload_datapoint_file_metrics
		&& type != upload_datapoint_file_path_metrics
		&& type != upload_datapoint_file_path_binary
		&& type != upload_datapoint_file_metrics_binary) {
		log_dp_error("%s", "Invalid upload type");
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		goto done;
	}

	switch (type) {
		/* CSV buffer */
		case upload_datapoint_file_metrics:
			if (!data.blob.data)
				log_dp_error("%s", "Unable to upload NULL");
			if (!data.blob.length)
				log_dp_error("%s", "Number of bytes to upload must be greater than 0");
			if (!data.blob.data || !data.blob.length) {
				ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
				goto done;
			}
			break;
		/* CSV file */
		case upload_datapoint_file_path_metrics:
			if (!data.file.path || *data.file.path == '\0') {
				log_dp_error("%s", "File path must be defined");
				ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
				goto done;
			}
			break;
		/* File contents as binary data */
		case upload_datapoint_file_path_binary:
			if (!data.file.path || *data.file.path == '\0')
				log_dp_error("%s", "File path must be defined");
			if (!data.file.stream_id)
				log_dp_error("%s", "Destination stream id must be defined");
			if (!data.file.path || !data.file.stream_id) {
				ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
				goto done;
			}
			break;
		/* Buffer as binary data point */
		case upload_datapoint_file_metrics_binary:
			if (!data.blob.data)
				log_dp_error("%s", "Unable to upload NULL");
			if (!data.blob.length)
				log_dp_error("%s", "Number of bytes to upload must be greater than 0");
			if (!data.blob.stream_id)
				log_dp_error("%s", "Destination stream id must be defined");
			if (!data.blob.data || !data.blob.length || !data.blob.stream_id) {
				ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
				goto done;
			}
			break;
		default:
			/* Should not occur */
			break;
	}

	log_dp_info("%s", "Sending data points to CCCSD");

	fd = connect_cccsd();
	if (fd < 0) {
		ret = CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON;
		goto done;
	}

	ret = send_dp_data_type(fd, type, data);
	if (ret == CCCS_SEND_ERROR_NONE)
		ret = parse_cccsd_response(fd, &cccs_resp, timeout);

	close(fd);
done:
	resp->hint = cccs_resp.hint;
	resp->code = 0;

	/* cccs_resp.cccs_err   ---> Error while reading command or storing data points */
	switch (cccs_resp.cccs_err) {
		case CCCS_SEND_ERROR_NONE:
			break;
		/* cccs_resp.ccapi_err  ---> Error while sending data points/error from DRM */
		case CCCS_SEND_ERROR_CCAPI_ERROR:
			resp->code = cccs_resp.ccapi_err;
			break;
		/* cccs_resp.srv_err    ---> Error from DRM */
		case CCCS_SEND_ERROR_SRV_ERROR:
			resp->code = cccs_resp.srv_err;
			break;
		default:
			resp->code = cccs_resp.cccs_err;
			break;
	}

	return ret;
}

cccs_comm_error_t cccs_send_dp_csv_file(const char *path, unsigned long const timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret;
	cccs_dp_data_t data_to_send = {
		.file.path = (char *)path,
		.file.stream_id = NULL,
	};

	resp->hint = NULL;

	ret = send_dp_data(upload_datapoint_file_path_metrics, data_to_send, timeout, resp);
	if (ret == CCCS_SEND_ERROR_NONE)
		log_dp_debug("Data points in '%s' uploaded", path);

	return ret;
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
	unsigned int dp_to_rm;

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

	if (dp_generate_csv_from_collection(collection, &buf_info, DP_MAX_NUMBER_PER_REQUEST, &dp_to_rm) > 0) {
		cccs_dp_data_t data_to_send = {
			.blob.data = buf_info.buffer,
			.blob.length = buf_info.bytes_written,
		};

		ret = send_dp_data(upload_datapoint_file_metrics, data_to_send, timeout, resp);
		if (ret == CCCS_SEND_ERROR_NONE || resp->code != CCCS_SEND_ERROR_UNABLE_TO_STORE_DP)
			/* Remove only sent or stored data points from collection */
			dp_remove_from_collection(collection, dp_to_rm);
	} else {
		ret = CCCS_SEND_ERROR_INVALID_ARGUMENT;
		resp->code = ret;
	}

	free(buf_info.buffer);

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

cccs_comm_error_t cccs_send_dp_binary_file(char const * const path,
	char const * const stream_id, unsigned long const timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret;
	cccs_dp_data_t data_to_send = {
		.file.path = (char *)path,
		.file.stream_id = (char *)stream_id,
	};

	resp->hint = NULL;

	ret = send_dp_data(upload_datapoint_file_path_binary, data_to_send, timeout, resp);
	if (ret == CCCS_SEND_ERROR_NONE)
		log_dp_debug("Binary data point in '%s' uploaded to '%s'", path, stream_id);

	return ret;
}

cccs_comm_error_t cccs_send_binary_dp(char const * const stream_id,
	void const * const data, size_t const bytes, cccs_resp_t *resp)
{
	return cccs_send_binary_dp_tout(stream_id, data, bytes, CCCS_DP_WAIT_FOREVER, resp);
}

cccs_comm_error_t cccs_send_binary_dp_tout(char const * const stream_id,
	void const * const data, size_t const bytes,
	unsigned long const timeout, cccs_resp_t *resp)
{
	cccs_comm_error_t ret;
	cccs_dp_data_t data_to_send = {
		.blob.data = (char *)data,
		.blob.length = bytes,
		.blob.stream_id = (char *)stream_id,
	};

	resp->hint = NULL;

	ret = send_dp_data(upload_datapoint_file_metrics_binary, data_to_send, timeout, resp);
	if (ret == CCCS_SEND_ERROR_NONE)
		log_dp_debug("Binary data point uploaded to '%s'", stream_id);

	return ret;
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

cccs_comm_error_t cccs_set_maintenance_status(bool status, unsigned long const timeout, cccs_resp_t *resp)
{
	int fd = -1;
	char *status_str = status ? "true" : "false";
	cccs_comm_error_t ret;
	cccs_srv_resp_t cccs_resp = {
		.srv_err = 0,
		.ccapi_err = 0,
		.cccs_err = 0,
		.hint = NULL
	};

	log_info("MNT: Setting maintenance to '%s'", status_str);

	fd = connect_cccsd();
	if (fd < 0) {
		ret = CCCS_SEND_UNABLE_TO_CONNECT_TO_DAEMON;
		goto done;
	}

	if (write_string(fd, REQ_TAG_MNT_REQUEST)	/* The request type */
		|| write_uint32(fd, status ? 1 : 0)	/* Maintenance status */
		|| write_uint32(fd, 0)) {		/* End of message */
		log_error("MNT: Could not set maintenance to '%s': %s (%d)",
			status_str, strerror(errno), errno);

		ret = CCCS_SEND_ERROR_BAD_RESPONSE;
	} else {
		ret = parse_cccsd_response(fd, &cccs_resp, timeout);
	}

	close(fd);
done:
	resp->hint = cccs_resp.hint;
	resp->code = 0;

	/* cccs_resp.cccs_err   ---> Error while reading command */
	switch (cccs_resp.cccs_err) {
		case CCCS_SEND_ERROR_NONE:
			break;
		/* cccs_resp.ccapi_err  ---> Error while sending data points/error from DRM */
		case CCCS_SEND_ERROR_CCAPI_ERROR:
			resp->code = cccs_resp.ccapi_err;
			break;
		/* cccs_resp.srv_err    ---> Error from DRM */
		case CCCS_SEND_ERROR_SRV_ERROR:
			resp->code = cccs_resp.srv_err;
			break;
		default:
			resp->code = cccs_resp.cccs_err;
			break;
	}

	return ret;
}
