/*
 * Copyright (c) 2017-2023 Digi International Inc.
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

#ifndef _CCCS_DATAPOINTS_H_
#define _CCCS_DATAPOINTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cccs_definitions.h"

#define CCCS_DP_WAIT_FOREVER		0UL

#define CCCS_DP_KEY_DATA_INT32		"int32"
#define CCCS_DP_KEY_DATA_INT64		"int64"
#define CCCS_DP_KEY_DATA_FLOAT		"float"
#define CCCS_DP_KEY_DATA_DOUBLE		"double"
#define CCCS_DP_KEY_DATA_STRING		"string"
#define CCCS_DP_KEY_DATA_JSON		"json"
#define CCCS_DP_KEY_DATA_GEOJSON	"geojson"

#define CCCS_DP_KEY_LOCATION		"loc"
#define CCCS_DP_KEY_QUALITY		"qual"

typedef enum {
	CCCS_DP_ERROR_NONE,
	CCCS_DP_ERROR_INVALID_ARGUMENT,
	CCCS_DP_ERROR_INVALID_STREAM_ID,
	CCCS_DP_ERROR_INVALID_FORMAT,
	CCCS_DP_ERROR_INVALID_UNITS,
	CCCS_DP_ERROR_INVALID_FORWARD_TO,
	CCCS_DP_ERROR_INSUFFICIENT_MEMORY,
	CCCS_DP_ERROR_LOCK_FAILED,
	CCCS_DP_ERROR_CCAPI_NOT_RUNNING,
	CCCS_DP_ERROR_TRANSPORT_NOT_STARTED,
	CCCS_DP_ERROR_INITIATE_ACTION_FAILED,
	CCCS_DP_ERROR_RESPONSE_BAD_REQUEST,
	CCCS_DP_ERROR_RESPONSE_UNAVAILABLE,
	CCCS_DP_ERROR_RESPONSE_CLOUD_ERROR,
	CCCS_DP_ERROR_STATUS_CANCEL,
	CCCS_DP_ERROR_STATUS_TIMEOUT,
	CCCS_DP_ERROR_STATUS_INVALID_DATA,
	CCCS_DP_ERROR_STATUS_SESSION_ERROR
} cccs_dp_error_t;

/**
 * struct cccs_location_t - Location of a data point
 *
 * @latitude:	Latitude value
 * @longitude:	Longitude value
 * @elevation:	Altitude value
 */
typedef struct {
	float latitude;
	float longitude;
	float elevation;
} cccs_location_t;

typedef struct ccapi_dp_collection *cccs_dp_collection_handle_t;


/*
 * cccs_dp_create_collection() - Create a data point collection
 *
 * @collection:	The collection to create.
 *
 * Collection must be destroyed with 'cccs_dp_destroy_collection'.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_create_collection(cccs_dp_collection_handle_t *const collection);

/*
 * cccs_dp_clear_collection() - Clear provided data point collection
 *
 * @collection:	The collection to clear.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_clear_collection(cccs_dp_collection_handle_t const collection);

/*
 * cccs_dp_destroy_collection() - Destroy provided data point collection
 *
 * @collection:	The collection to destroy.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_destroy_collection(cccs_dp_collection_handle_t const collection);

/*
 * cccs_dp_add_data_stream_to_collection() - Add a data stream to a data point collection
 *
 * @collection:		The collection to add the data stream.
 * @stream_id:		Null-terminated string with the name of the data stream.
 *			Must be unique.
 * @format_string:	Null-terminated string to define the data points the
 * 			stream contains and how it is expected.
 * @add_local_timestamp:If true, the timestamp of each data point in the stream
 *			will be the timestamp when the sample is added to
 *			the data stream using 'cccs_dp_data()' function.
 *			If false, the timestamp will be set by the server when
 *			data is uploaded.
 *
 * For 'format_string' information see 'cccs_dp_add_data_stream_to_collection_extra()'.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_add_data_stream_to_collection(
	cccs_dp_collection_handle_t const collection,
	char const * const stream_id,
	char const * const format_string,
	bool add_local_timestamp);

/*
 * cccs_dp_add_data_stream_to_collection_extra() - Add a data stream to a data point collection
 *
 * @collection:		The collection to add the data stream.
 * @stream_id:		Null-terminated string with the name of the data stream.
 *			Must be unique.
 * @format_string:	Null-terminated string to define the data points the
 *			stream contains and how it is expected.
 * @add_local_timestamp:If true, the timestamp of each data point in the stream
 *			will be the timestamp when the sample is added to
 *			the data stream using 'cccs_dp_data()' function.
 *			If false, the timestamp will be set by the server when
 *			data is uploaded.
 * @units:		Null-terminated string for the units of the data in
 *			the stream, such as, seconds, C, etc.
 *			NULL for no units.
 * @forward_to:		Name of the data stream to replicate data points to.
 *			NULL to not use.
 *
 * The 'format_string' specifies:
 *
 *    - Data type	[Required] Type of the data points value to add to the data stream.
 *      Possible values:
 *         CCCS_DP_KEY_DATA_INT32	32-bit signed integer value
 *         CCCS_DP_KEY_DATA_INT64	64-bit signed integer value
 *         CCCS_DP_KEY_DATA_FLOAT	Floating point value
 *         CCCS_DP_KEY_DATA_DOUBLE	Double precision floating point value
 *         CCCS_DP_KEY_DATA_STRING	Null-terminated string
 *         CCCS_DP_KEY_DATA_JSON	Null-terminated string that represents a JSON object
 *         CCCS_DP_KEY_DATA_GEOJSON	Null-terminated string that represents a GeoJSON object
 *
 *    - Location	[Optional] Data points capture location.
 *      		See 'cccs_location_t'.
 *      Possible values:
 *         CCCS_DP_KEY_LOCATION		Location structure, with latitude, longitude, and altitude as floating point values
 *
 *    - Quality		[Optional] Sample quality.
 *      Possible values:
 *         CCCS_DP_KEY_QUALITY		Data Point quality value, as an integer
 *
 * The order of the keywords in the 'format_string' defines the expected order
 * when adding a data point with 'cccs_dp_add' (like in printf/scanf functions).
 *
 * For example:
 *      CCCS_DP_KEY_DATA_STRING CCCS_DP_KEY_LOCATION CCCS_DP_KEY_QUALITY
 *
 * It is equivalent to 'string loc qual'.
 * It means that all data points added to the data stream must pass:
 *     - a null-terminated string as the first argument,
 *     - the location structure as the second one,
 *     - and an integer for the quality as the third one.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_add_data_stream_to_collection_extra(
	cccs_dp_collection_handle_t const collection,
	char const * const stream_id,
	char const * const format_string,
	bool add_local_timestamp,
	char const * const units,
	char const * const forward_to);

/*
 * cccs_dp_remove_data_stream_from_collection() - Remove a data stream from a collection
 *
 * @collection:		The collection to remove the data stream.
 * @stream_id:		Name of the data stream to remove.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_remove_data_stream_from_collection(
	cccs_dp_collection_handle_t const collection,
	char const * const stream_id);

/*
 * cccs_dp_get_collection_points_count() - Return the number of data points in the collection
 *
 * @collection:		The collection to get the total number of data points.
 * @count:		Output argument with the total number of data points.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_get_collection_points_count(
	cccs_dp_collection_handle_t const collection,
	uint32_t * const count);

/*
 * cccs_dp_add() - Add data point to a data stream in a data point collection
 *
 * @collection:		The collection with the data stream.
 * @stream_id:		The name of the data stream.
 * @variable arguments:	Data point attributes (value, timestamp, location, quality).
 *			They must match (in number and order) the specified
 *			'format_string' specified in
 *			'ccapi_dp_add_data_stream_to_collection()' or
 *			'cccs_dp_add_data_stream_to_collection_extra()'.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_add(cccs_dp_collection_handle_t const collection, char const * const stream_id, ...);

/*
 * cccs_dp_remove_older_data_point_from_streams() - Remove the oldest data point of each data stream in a collection
 *
 * @collection:		The collection to remove oldest data points.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if it fails.
 */
cccs_dp_error_t cccs_dp_remove_older_data_point_from_streams(cccs_dp_collection_handle_t const collection);

/*
 * cccs_send_dp_csv_file() - Send provided CSV file with data points to CCCS daemon to be uploaded
 *
 * @path:	Absolute path of the CSV file.
 * @timeout:	Number of seconds to wait for a CCCS daemon response.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Each line of the CSV file represents a data point following the format:
 *
 * DATA,TIMESTAMP,QUALITY,DESCRIPTION,LOCATION,DATA_TYPE,UNITS,FORWARD_TO,STREAM_ID
 *
 * Where:
 *    - DATA:		Value of the data point.
 *      		It must be in the format specified by 'DATA_TYPE'.
 *    - TIMESTAMP:	Specifies when the value was captured.
 *      		It can be a:
 *      			- 64-bit unsigned integer with the number of milliseconds since 00:00:00 UTC on 1 January 1970.
 *      			- A quoted string with the timestamp in ISO 8601 format.
 *      		If it is empty, Remote Manager will add it according to the time of the upload.
 *    - QUALITY:	Value to define the quality of the sample.
 *      		It must be an integer value.
 *    - DESCRIPTION:	Sample description.
 *      		Empty not to use it.
 *    - LOCATION:	Value to establish the device location when the sample was taken.
 *      		Three float values separated by commas with leading and trailing quotes:
 *      		"X.x,Y.y,H.h"
 *      		Empty not to use it.
 *    - DATA_TYPE:	Type of the data point. One of the following:
 *      		INTEGER, LONG, FLOAT, DOUBLE, STRING, JSON, GEOJSON
 *    - UNITS:		String to define the unit of the data, such as, seconds, C, etc.
 *      		Empty not to use it.
 *    - FORWARD_TO:	Name of the data stream to replicate data points to.
 *      		Empty not to use it.
 *    - STREAM_ID:	Name of the data stream destination in Remote Manager.
 *
 * For example:
 *
 * 3600,1685440800000,,,,INTEGER,seconds,,/mystream/integer
 * 27.450000,1685440800000,,,,FLOAT,%,,/mystream/float
 * 21987692,1685440800000,,,,LONG,bytes,,/mystream/long
 * "string test",1685440800000,,,,STRING,,/mystream/string
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_dp_csv_file(const char *path, unsigned long const timeout, cccs_resp_t *resp);

/*
 * cccs_send_dp_collection() - Send provided data point collection to CCCS daemon to be uploaded
 *
 * @collection:	Data point collection to send to CCCS daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_dp_collection(cccs_dp_collection_handle_t const collection, cccs_resp_t *resp);

/*
 * cccs_send_dp_collection_tout() - Send provided data point collection to CCCS daemon to be uploaded
 *
 * @collection:	Data point collection to send to CCCS daemon.
 * @timeout:	Number of seconds to wait for response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_dp_collection_tout(cccs_dp_collection_handle_t const collection,
	unsigned long const timeout, cccs_resp_t *resp);

/*
 * cccs_send_dp_binary_file() - Send provided file as binary data point to CCCS daemon to be uploaded
 *
 * @path:	Absolute path of the binary file.
 * @stream_id:	Stream id to upload the file as binary data point.
 * @timeout:	Number of seconds to wait for a CCCS daemon response.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_dp_binary_file(char const * const path,
	char const * const stream_id, unsigned long const timeout, cccs_resp_t *resp);

/*
 * cccs_send_binary_dp() - Send provided data as binary data point to CCCS daemon to be uploaded
 *
 * @stream_id:	Data point collection to send to CCCS daemon.
 * @data:	The data bytes to be uploaded.
 * @bytes:	The number of bytes to be uploaded.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_binary_dp(char const * const stream_id,
	void const * const data, size_t const bytes, cccs_resp_t *resp);

/*
 * cccs_send_binary_dp_tout() - Send provided data as binary data point to CCCS daemon to be uploaded
 *
 * @stream_id:	Data point collection to send to CCCS daemon.
 * @data:	The data bytes to be uploaded.
 * @bytes:	The number of bytes to be uploaded.
 * @timeout:	Number of seconds to wait for response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_send_binary_dp_tout(char const * const stream_id,
	void const * const data, size_t const bytes,
	unsigned long const timeout, cccs_resp_t *resp);

#endif /* _CCCS_DATAPOINTS_H_ */
