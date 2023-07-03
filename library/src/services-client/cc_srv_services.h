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

#ifndef _CC_SRV_SERVICES_H_
#define _CC_SRV_SERVICES_H_

#include "cc_logging.h"
#include "ccapi_receive.h"
#include "ccapi_datapoints.h"
#include "cc_utils.h"

typedef ccapi_receive_error_t (*cc_srv_request_data_cb_t)(char const * const target,
	ccapi_buffer_info_t const * const request_buffer_info,
	ccapi_buffer_info_t * const response_buffer_info);
typedef void (*cc_srv_request_status_cb_t)(char const * const target,
	ccapi_buffer_info_t * const response_buffer_info,
	int receive_error, const char * const receive_error_hint);

/*
 * cc_srv_send_dp_csv_file() - Send provided CSV file with data points to Cloud Connector server
 *
 * @path:		Absolute path of the CSV file.
 * @timeout:	Number of seconds to wait for a Cloud Connector server response.
 * @resp:		Received response from Cloud Connector server.
 *
 * Response may contain the result of the operation. It must be freed.
 *
 * Each line of the CSV file represents a data point following the format:
 *
 * DATA,TIMESTAMP,QUALITY,DESCRIPTION,LOCATION,DATA_TYPE,UNITS,FORWARD_TO,STREAM_ID
 *
 * Where:
 *    - DATA:			Value of the data point.
 *      				It must be in the format specified by 'DATA_TYPE'.
 *    - TIMESTAMP:		Specifies when the value was captured.
 *      				It can be a:
 *      					- 64-bit unsigned integer with the number of milliseconds since 00:00:00 UTC on 1 January 1970.
 *      					- A quoted string with the timestamp in ISO 8601 format.
 *      				If it is empty, Remote Manager will add it according to the time of the upload.
 *    - QUALITY:		Value to define the quality of the sample.
 *      				It must be an integer value.
 *    - DESCRIPTION:	Sample description.
 *      				Empty not to use it.
 *    - LOCATION:		Value to establish the device location when the sample was taken.
 *      				Three float values separated by commas with leading and trailing quotes:
 *      							"X.x,Y.y,H.h"
 *      				Empty not to use it.
 *    - DATA_TYPE:		Type of the data point. One of the following:
 *      				INTEGER, LONG, FLOAT, DOUBLE, STRING, JSON, GEOJSON
 *    - UNITS:			String to define the unit of the data, such as, seconds, C, etc.
 *      				Empty not to use it.
 *    - FORWARD_TO:		Name of the data stream to replicate data points to.
 *      				Empty not to use it.
 *    - STREAM_ID:		Name of the data stream destination in Remote Manager.
 *
 * For example:
 *
 * 3600,1685440800000,,,,INTEGER,seconds,,/mystream/integer
 * 27.450000,1685440800000,,,,FLOAT,%,,/mystream/float
 * 21987692,1685440800000,,,,LONG,bytes,,/mystream/long
 * "string test",1685440800000,,,,STRING,,/mystream/string
 *
 * Return: 0 on success, otherwise
 * -2 = out of memory
 * -1 = protocol errors
 *  0 = success
 *  1 = received error
 *  2 = args error
 */
int cc_srv_send_dp_csv_file(const char *path, unsigned long const timeout, char **resp);

/*
 * cc_srv_send_dp_collection() - Send provided data point collection to Cloud Connector server
 *
 * @dp_collection:	Data point collection to send to Cloud Connector server.
 * @resp:		Received response from Cloud Connector server.
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
int cc_srv_send_dp_collection(ccapi_dp_collection_handle_t const dp_collection, char **resp);

/*
 * cc_srv_send_dp_collection_with_timeout() - Send provided data point collection to Cloud Connector server
 *
 * @dp_collection:	Data point collection to send to Cloud Connector server.
 * @timeout:		Number of seconds to wait for response from the server.
 * @resp:		Received response from Cloud Connector server.
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
int cc_srv_send_dp_collection_with_timeout(ccapi_dp_collection_handle_t const dp_collection, unsigned long const timeout, char **resp);

/*
 * cc_srv_add_request_target() - Register a request target
 *
 * @target:	Target name to register.
 * @data_cb:	Callback function executed when a request for the provided
 *		target is received.
 * @status_cb:	Callback function executed when the receive process has completed.
 * @resp:	Received response from Cloud Connector server.
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
int cc_srv_add_request_target(char const * const target,
	cc_srv_request_data_cb_t data_cb, cc_srv_request_status_cb_t status_cb,
	char **resp);

/*
 * cc_srv_add_request_target_with_timeout() - Register a request target
 *
 * @target:	Target name to register.
 * @data_cb:	Callback function executed when a request for the provided
 *		target is received.
 * @status_cb:	Callback function executed when the receive process has completed.
 * @timeout:	Number of seconds to wait for response from the server.
 * @resp:	Received response from Cloud Connector server.
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
int cc_srv_add_request_target_with_timeout(char const * const target,
	cc_srv_request_data_cb_t data_cb, cc_srv_request_status_cb_t status_cb,
	unsigned long timeout, char **resp);

/*
 * cc_srv_remove_request_target() - Unregister a request target
 *
 * @target:	Target name to unregister.
 * @resp:	Received response from Cloud Connector server.
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
int cc_srv_remove_request_target(char const * const target, char **resp);

/*
 * cc_srv_remove_request_target_with_timeout() - Unregister a request target
 *
 * @target:	Target name to unregister.
 * @timeout:	Number of seconds to wait for response from the server.
 * @resp:	Received response from Cloud Connector server.
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
int cc_srv_remove_request_target_with_timeout(char const * const target,
	unsigned long timeout, char **resp);

#endif /* _CC_SRV_SERVICES_H_ */
