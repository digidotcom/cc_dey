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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "ccapi/ccapi.h"
#include "cc_utils.h"

ccapi_timestamp_t *get_timestamp(void)
{
	return get_timestamp_by_type(CC_TS_DEFAULT);
}

ccapi_timestamp_t *get_timestamp_by_type(cc_timestamp_type_t type)
{
	ccapi_timestamp_t *timestamp = NULL;
	struct timeval now;

	if (type >= CC_TS_INVALID || type < CC_TS_DEFAULT)
		return NULL;

	timestamp = calloc(1, sizeof(*timestamp));
	if (timestamp == NULL)
		return NULL;

	if (gettimeofday(&now, NULL) != 0)
		goto error;

	switch (type) {
		case CC_TS_EPOCH_MS:
			timestamp->epoch_msec = now.tv_sec * 1000 + now.tv_usec / 1000;
			break;
		case CC_TS_ISO8601:
			{
				size_t len = strlen("2016-09-27T07:07:09.546Z") + 1;
				char *date = calloc(len, sizeof(*date));

				if (date == NULL)
					goto error;

				if (strftime(date, len, "%FT%H:%M:%S", gmtime(&now.tv_sec)) > 0) {
					sprintf(date + strlen(date), ".%03ldZ", now.tv_usec/10000);
					timestamp->iso8601 = date;
					break;
				}

				free(date);
				goto error;
			}
		case CC_TS_DEFAULT:
		case CC_TS_EPOCH:
			timestamp->epoch.seconds = now.tv_sec;
			timestamp->epoch.milliseconds = now.tv_usec / 1000;
			break;
		default:
			/* Should not occur */
			break;
	}

	return timestamp;
error:
	free_timestamp_by_type(timestamp, type);

	return NULL;
}

void free_timestamp(ccapi_timestamp_t *timestamp)
{
	free_timestamp_by_type(timestamp, CC_TS_DEFAULT);
}

void free_timestamp_by_type(ccapi_timestamp_t *timestamp, cc_timestamp_type_t type)
{
	if (!timestamp)
		return;

	switch (type) {
		case CC_TS_EPOCH_MS:
			timestamp->epoch_msec = 0;
			break;
		case CC_TS_ISO8601:
			free((char *)timestamp->iso8601);
			timestamp->iso8601 = NULL;
			break;
		case CC_TS_DEFAULT:
		case CC_TS_EPOCH:
			timestamp->epoch.seconds = 0;
			timestamp->epoch.milliseconds = 0;
			break;
		default:
			/* Should not occur */
			break;
	}

	free(timestamp);
}