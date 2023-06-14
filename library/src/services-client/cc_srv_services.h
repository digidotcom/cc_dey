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

#endif /* _CC_SRV_SERVICES_H_ */
