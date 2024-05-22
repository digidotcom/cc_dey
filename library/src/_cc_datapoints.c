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

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "ccimp/ccimp_types.h"
#include "ccapi/ccapi_transport.h"
#include "ccapi/ccapi_send.h"
#include "ccapi/ccapi_datapoints.h"
#include "ccapi/ccapi_datapoints_binary.h"

#include "cc_error_msg.h"
#include "cc_logging.h"
#include "_cc_datapoints.h"
#include "service_common.h"
#include "_utils.h"

#define DIR_PATH_OUTPUT_FORMAT			"%s/cccs/"
#define DP_FILE_NAME_OUTPUT_FORMAT		"%llu%03lld_%s"

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

size_t dp_generate_csv_from_collection(cccs_dp_collection_t * const collection, buffer_info_t *buf_info, unsigned int max_dp, unsigned int *n_dp)
{
	csv_process_data_t process_data;

	max_dp = collection->dp_count < max_dp ? collection->dp_count : max_dp;

	chain_collection_ccfsm_data_streams(collection);

	process_data.current_csv_field = csv_data;
	process_data.current_data_stream = collection->cccs_data_stream_list->ccfsm_data_stream;
	process_data.current_data_point = collection->cccs_data_stream_list->ccfsm_data_stream->point;
	process_data.data.init = false;

	buf_info->bytes_written = 0;
	buf_info->bytes_available = 0;

	buf_info->buffer = calloc(BUFSIZ, sizeof(*buf_info->buffer));
	if (!buf_info->buffer) {
		log_error("Unable to generate CSV data: %s", "Out of memory");
		return -1;
	}
	buf_info->bytes_available = BUFSIZ;

	return generate_dp_csv(&process_data, buf_info, max_dp, n_dp);
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

unsigned int dp_remove_from_collection(cccs_dp_collection_t * const collection, unsigned int n_to_remove)
{
	connector_data_stream_t *current_ds = NULL;
	connector_data_point_t *current_dp = NULL;
	unsigned int removed = 0;

	if (!collection || !collection->cccs_data_stream_list)
		return 0;

	/* If n_to_remove is 0, remove all */
	if (!n_to_remove)
		n_to_remove = collection->dp_count;

	current_ds = collection->cccs_data_stream_list->ccfsm_data_stream;
	if (!current_ds)
		return 0;

	current_dp = current_ds->point;

	while (current_dp && removed < n_to_remove) {
		current_ds->point = current_dp->next;

		dp_free_data_point(current_dp, current_ds->type);
		current_dp = current_ds->point;

		collection->dp_count -= 1;
		removed += 1;

		/* Get the first data point of the next stream */
		if (!current_dp) {
			current_ds = current_ds->next;

			if (current_ds)
				current_dp = current_ds->point;
		}
	}

	return removed;
}

/*
 * dp_get_backlog_dir() - Return the absolute path of the backlog directory
 *
 * @base_dir:	Absolute path where the backlog directory is or will be.
 *
 * Returned path must be freed.
 *
 * Return: The absolute path of the backlog directory, NULL if an error occur.
 */
static char* dp_get_backlog_dir(char const * const base_dir)
{
	char *out_dir = NULL;
	int path_len;

	if (!base_dir || strlen(base_dir) == 0)
		return NULL;

	path_len = snprintf(NULL, 0, DIR_PATH_OUTPUT_FORMAT, base_dir);
	out_dir = calloc(path_len + 1, sizeof(*out_dir));
	if (!out_dir) {
		log_error("Unable to store data points: %s", "Out of memory");

		return NULL;
	}

	sprintf(out_dir, DIR_PATH_OUTPUT_FORMAT, base_dir);

	return out_dir;
}

/*
 * dp_get_backlog_file_path() - Return the absolute path of a backlog file
 *
 * @type:	Type of the data in the backlog file.
 * @stream_id:	Stream id of the data for binary data, otherwise not used.
 * @out_dir:	Absolute path where the backlog directory is or will be.
 *
 * Returned path must be freed.
 *
 * Return: The absolute path of the backlog file, NULL if an error occur.
 */
static char* dp_get_backlog_file_path(uint32_t type, char const stream_id[], char const * const out_dir)
{
	char *out_file = NULL;
	struct timeval now;
	int path_len;

	if (!out_dir)
		return NULL;

	gettimeofday(&now, NULL);

	path_len = snprintf(NULL, 0, "%s" DP_FILE_NAME_OUTPUT_FORMAT,
		out_dir, (long long unsigned)now.tv_sec, (long long int)now.tv_usec / 1000,
		type == upload_datapoint_file_path_binary || type == upload_datapoint_file_metrics_binary ? stream_id : "");
	out_file = calloc(path_len + 1, sizeof(*out_file));
	if (!out_file) {
		log_error("Unable to store data points: %s", "Out of memory");
		goto done;
	}

	sprintf(out_file, "%s" DP_FILE_NAME_OUTPUT_FORMAT,
		out_dir, (long long unsigned)now.tv_sec, (long long int)now.tv_usec / 1000,
		type == upload_datapoint_file_path_binary || type == upload_datapoint_file_metrics_binary ? stream_id : "");

done:
	return out_file;
}

/*
 * store_dp() - Store provided data points inside the backlog directory
 *
 * @type:		Type of data points.
 * @buff:		Data points buffer (binary or CVS).
 * @size:		Size of data buffer.
 * @stream_id:		Stream id of the data for binary data points, otherwise not used.
 * @backlog_dir:	Absolute path where the backlog directory is or will be.
 *
 * Return: 0 if success, 1 otherwise.
 */
static int store_dp(uint32_t type, char const * const buff, size_t size,
	char const stream_id[], const char * const backlog_dir)
{
	/* 0664 = Owner RW + Group RW + Others R */
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
	char *out_file = NULL, *dir_path = NULL, *aux = NULL;
	int ret;

	out_file = dp_get_backlog_file_path(type, stream_id, backlog_dir);
	if (!out_file)
		return 1;

	log_debug("Storing data points at '%s'", out_file);

	aux = strdup(out_file);
	if (!aux) {
		log_error("Error creating data backlog directory at '%s': Out of memory",
			backlog_dir);
		ret = 1;
		goto done;
	}

	dir_path = dirname(aux);
	ret = mkpath(dir_path, mode);
	free(aux);

	if (ret == -1) {
		log_error("Error creating data backlog directory at '%s'", backlog_dir);
		ret = 1;
		goto done;
	}

	switch (type) {
		case upload_datapoint_file_events:
		case upload_datapoint_file_metrics:
		case upload_datapoint_file_metrics_binary:
			/* Generate file */
			ret = write_buffer_to_file(out_file, buff, size);
			break;
		case upload_datapoint_file_path_metrics:
		case upload_datapoint_file_path_binary:
			ret = cp_file(buff, out_file);
			break;
		default:
			/* Should not occur */
			ret = 0;
			break;
	}

done:
	free(out_file);

	return ret;
}

/*
 * dp_get_next_store_dp_file() - Get absolute path of the next data file
 *
 * @backlog_dir:	Absolute path where the backlog directory is.
 *
 * Returned path must be freed.
 *
 * Return: The absolute path of the next backlog file.
 */
static char *dp_get_next_store_dp_file(char const * const backlog_dir)
{
	struct dirent **entry_list = NULL;
	char *file = NULL;
	int n_entries, i;

	if (!backlog_dir || strlen(backlog_dir) == 0)
		return NULL;

	n_entries = scandir(backlog_dir, &entry_list, NULL, alphasort);
	for (i = 0; i < n_entries; i++) {
		struct stat st;
		int len;

		if (strcmp(entry_list[i]->d_name, "..") == 0
			|| strcmp(entry_list[i]->d_name, ".") == 0)
			continue;

		len = snprintf(NULL, 0, "%s%s", backlog_dir, entry_list[i]->d_name);

		file = calloc(len + 1, sizeof(*file));
		if (!file) {
			log_error("Unable to get stored data to upload: %s",
				"Out of memory");
			goto done;
		}

		sprintf(file, "%s/%s", backlog_dir, entry_list[i]->d_name);

		stat(file, &st);
		if (S_ISREG(st.st_mode))
			break;

		free(file);
		file = NULL;
	}

done:
	if (entry_list) {
		for (i = 0; i < n_entries; i++)
			free(entry_list[i]);
		free(entry_list);
	}

	return file;
}

/*
 * remove_oldest_stored_data() - Remove the oldest data file in the directory
 *
 * @backlog_dir_path:	Absolute path of the directory to look for stored data.
 *
 * Return: 0 if success, 1 otherwise.
 */
static int remove_oldest_stored_data(char const * const backlog_dir_path)
{
	int ret = 0;
	char *next_file = dp_get_next_store_dp_file(backlog_dir_path);

	if (remove(next_file)) {
		log_error("Unable to remove stored data in '%s': %s (%d)",
				next_file, strerror(errno), errno);
		ret = 1;
	}

	free(next_file);

	return ret;
}

/*
 * check_backlog_size() - Checks the size of the backlog directory
 *
 * @backlog_dir:	Absolute path of the directory to store samples if required.
 * @backlog_kb:		Maximum size (kb) of the data backlog.
 *
 * If the size of the backlog directory is bigger than the maximum size in the
 * configuration, this function removes the oldest data file stored in the
 * directory until the size is less than the maximum.
 * If it cannot calculate the size or cannot remove files 1 is returned.
 *
 * Return: 0 if success, 1 otherwise.
 */
static int check_backlog_size(const char * const backlog_dir, uint32_t backlog_kb)
{
	unsigned long long dir_size, init_dir_size;
	int ret;

	if (!backlog_dir || strlen(backlog_dir) == 0 || backlog_kb == 0)
		return 0;

	ret = get_directory_size(backlog_dir, &init_dir_size);
	if (ret == -1) /* Directory does not exist */
		return 0;
	if (ret != 0) {
		log_error("Unable to get size of backlog directory '%s'", backlog_dir);
		return 1;
	}

	dir_size = init_dir_size;

	log_debug("Backlog size, current: %llu (%llu kb), maximum: %llu (%u kb)",
		dir_size, dir_size / 1024, backlog_kb * 1024ULL, backlog_kb);

	while (backlog_kb * 1024ULL < dir_size) {
		if (remove_oldest_stored_data(backlog_dir) != 0)
			return 1;

		if (get_directory_size(backlog_dir, &dir_size) != 0) {
			log_error("Unable to get size of backlog directory '%s'", backlog_dir);
			return 1;
		}
	}

	if (dir_size != init_dir_size)
		log_debug("Backlog size, current: %llu (%llu kb), maximum: %llu (%u kb)",
			dir_size, dir_size / 1024, backlog_kb * 1024ULL, backlog_kb);

	return 0;
}

int dp_process_send_dp_error(uint32_t type, unsigned int error,
	char const * const buff, size_t size, char const stream_id[],
	const char * const backlog_dir_path, uint32_t backlog_kb)
{
	int ret = 1;
	char *backlog_dir = NULL;

	if (!backlog_dir_path || strlen(backlog_dir_path) == 0 || backlog_kb == 0)
		return 0;

	if (error == upload_datapoint_file_metrics_binary
		|| error == upload_datapoint_file_path_binary) {
		/*
		 * Possible errors:
		 *
		 *   CCAPI_DP_B_ERROR_NONE
		 *   CCAPI_DP_B_ERROR_CCAPI_NOT_RUNNING
		 *   CCAPI_DP_B_ERROR_TRANSPORT_NOT_STARTED
		 *   CCAPI_DP_B_ERROR_FILESYSTEM_NOT_SUPPORTED
		 *   CCAPI_DP_B_ERROR_INVALID_STREAM_ID
		 *   CCAPI_DP_B_ERROR_INVALID_DATA
		 *   CCAPI_DP_B_ERROR_INVALID_LOCAL_PATH
		 *   CCAPI_DP_B_ERROR_NOT_A_FILE
		 *   CCAPI_DP_B_ERROR_ACCESSING_FILE
		 *   CCAPI_DP_B_ERROR_INVALID_HINT_POINTER
		 *   CCAPI_DP_B_ERROR_INSUFFICIENT_MEMORY
		 *   CCAPI_DP_B_ERROR_LOCK_FAILED
		 *   CCAPI_DP_B_ERROR_INITIATE_ACTION_FAILED
		 *   CCAPI_DP_B_ERROR_STATUS_CANCEL
		 *   CCAPI_DP_B_ERROR_STATUS_TIMEOUT
		 *   CCAPI_DP_B_ERROR_STATUS_SESSION_ERROR
		 *   CCAPI_DP_B_ERROR_RESPONSE_BAD_REQUEST
		 *   CCAPI_DP_B_ERROR_RESPONSE_UNAVAILABLE
		 *   CCAPI_DP_B_ERROR_RESPONSE_CLOUD_ERROR
		 */
		switch (error) {
			case CCAPI_DP_B_ERROR_TRANSPORT_NOT_STARTED:
			case CCAPI_DP_B_ERROR_LOCK_FAILED:
			case CCAPI_DP_B_ERROR_INITIATE_ACTION_FAILED:
			case CCAPI_DP_B_ERROR_STATUS_CANCEL:
			case CCAPI_DP_B_ERROR_STATUS_TIMEOUT:
			case CCAPI_DP_B_ERROR_STATUS_SESSION_ERROR:
			case CCAPI_DP_B_ERROR_RESPONSE_BAD_REQUEST:
			case CCAPI_DP_B_ERROR_RESPONSE_UNAVAILABLE:
			case CCAPI_DP_B_ERROR_RESPONSE_CLOUD_ERROR:
				break;
			default:
				return 0;
		}

	} else { /* upload_datapoint_file_path_metrics || upload_datapoint_file_events || upload_datapoint_file_metrics */
		/*
		 *   Possible errors:
		 *
		 *   CCAPI_SEND_ERROR_NONE
		 *   CCAPI_SEND_ERROR_CCAPI_NOT_RUNNING
		 *   CCAPI_SEND_ERROR_TRANSPORT_NOT_STARTED
		 *   CCAPI_SEND_ERROR_FILESYSTEM_NOT_SUPPORTED	Should not happen, only if CCIMP_FILE_SYSTEM_SERVICE_ENABLED is not defined
		 *   CCAPI_SEND_ERROR_INVALID_CLOUD_PATH	Should not happen: hardcoded DeviceLog/EventLog.json or DataPoint/.csv, NULL or empty cloud path
		 *   CCAPI_SEND_ERROR_INVALID_CONTENT_TYPE	Should not happen: hardcoded, only if empty string or too long
		 *   CCAPI_SEND_ERROR_INVALID_DATA 		(N file) Should not happen: checked before, empty data
		 *   CCAPI_SEND_ERROR_INVALID_LOCAL_PATH	(file) Should not happen: already checked, NULL or empty local path
		 *   CCAPI_SEND_ERROR_NOT_A_FILE		(file) If not a file but any other resource
		 *   CCAPI_SEND_ERROR_ACCESSING_FILE		(file) If cannot open file
		 *   CCAPI_SEND_ERROR_INVALID_HINT_POINTER	Should not happen (internal definition)
		 *   CCAPI_SEND_ERROR_INSUFFICIENT_MEMORY	We will not be able to store anything
		 *   CCAPI_SEND_ERROR_LOCK_FAILED
		 *   CCAPI_SEND_ERROR_INITIATE_ACTION_FAILED
		 *   CCAPI_SEND_ERROR_STATUS_CANCEL		The device request was canceled by the user (if not connection we are getting this code)
		 *   CCAPI_SEND_ERROR_STATUS_TIMEOUT		Session timed out
		 *   CCAPI_SEND_ERROR_STATUS_SESSION_ERROR	Cloud Connector encountered error - error from lower communication layer
		 *   CCAPI_SEND_ERROR_RESPONSE_BAD_REQUEST	At least some portion of the request is not valid
		 *   CCAPI_SEND_ERROR_RESPONSE_UNAVAILABLE	Service not available, may retry later
		 *   CCAPI_SEND_ERROR_RESPONSE_CLOUD_ERROR	Device Cloud encountered error while handling the request
		 */
		switch (error) {
			case CCAPI_SEND_ERROR_TRANSPORT_NOT_STARTED:
			case CCAPI_SEND_ERROR_LOCK_FAILED:
			case CCAPI_SEND_ERROR_INITIATE_ACTION_FAILED:
			case CCAPI_SEND_ERROR_STATUS_CANCEL:
			case CCAPI_SEND_ERROR_STATUS_TIMEOUT:
			case CCAPI_SEND_ERROR_STATUS_SESSION_ERROR:
			case CCAPI_SEND_ERROR_RESPONSE_BAD_REQUEST:
			case CCAPI_SEND_ERROR_RESPONSE_UNAVAILABLE:
			case CCAPI_SEND_ERROR_RESPONSE_CLOUD_ERROR:
				break;
			default:
				return 0;
		}
	}

	log_info("%s", "Storing data points");

	backlog_dir = dp_get_backlog_dir(backlog_dir_path);
	if (!backlog_dir)
		return 1;

	if (check_backlog_size(backlog_dir, backlog_kb) == 0)
		ret = store_dp(type, buff, size, stream_id, backlog_dir);

	free(backlog_dir);

	return ret;
}

int dp_send_stored_data(char const * const backlog_dir_path)
{
	char *backlog_dir = dp_get_backlog_dir(backlog_dir_path);
	char *next_file = NULL;
	char *file_name = NULL, *aux = NULL, *stream_id = NULL;
	int error = -1;

	next_file = dp_get_next_store_dp_file(backlog_dir);
	if (!next_file) {
		error = 0;
		goto done;
	}

	log_debug("Sending stored data in '%s'", next_file);

	aux = strdup(next_file);
	if (!aux) {
		log_error("Unable to send stored data: %s", "Out of memory");
		goto done;
	}

	file_name = basename(aux);

	stream_id = strchr(file_name, '_');
	if (stream_id)
		stream_id = stream_id + 1;

	if (!stream_id || !strlen(stream_id)) {
		/* CSV file */
		error = ccapi_send_file(CCAPI_TRANSPORT_TCP, next_file,
			"DataPoint/.csv", "text/plain", CCAPI_SEND_BEHAVIOR_OVERWRITE);
		if (error != CCAPI_SEND_ERROR_NONE)
			log_error("Unable to send stored data: %s (%d)",
				to_send_error_msg(error), error);
	} else {
		/* Binary file */
		error = ccapi_dp_binary_send_file(CCAPI_TRANSPORT_TCP,
			next_file, stream_id);
		if (error != CCAPI_DP_B_ERROR_NONE)
			log_error("Unable to send stored data: %s (%d)",
				dp_b_to_send_error_msg(error), error);
	}

	if (!error && remove(next_file)) {
		log_error("Unable to remove stored data in '%s': %s (%d)",
				next_file, strerror(errno), errno);
		error = -1;
	}

done:
	free(aux);
	free(next_file);
	free(backlog_dir);

	return error;
}
