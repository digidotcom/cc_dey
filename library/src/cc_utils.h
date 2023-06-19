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

#ifndef __CC_UTILS_H__
#define __CC_UTILS_H__

typedef enum {
	CC_TS_DEFAULT = -1,
	CC_TS_EPOCH,
	CC_TS_EPOCH_MS,
	CC_TS_ISO8601,
	CC_TS_INVALID
} cc_timestamp_type_t;

/*
 * get_timestamp() - Get the current timestamp of the system
 *
 * This is equivalent to 'get_timestamp_by_type(CC_TS_DEFAULT)'.
 * 'CC_TS_DEFAULT' is equivalent to 'CC_TS_EPOCH'.
 *
 * Return: The current timestamp, NULL if error. It must be freed.
 */
ccapi_timestamp_t *get_timestamp(void);

/*
 * get_timestamp_by_type() - Get the current timestamp of the system
 *
 * @type:	Timestamp type, 'CC_TS_DEFAULT' to use default timestamp type, 'CC_TS_EPOCH'.
 *
 * Return: The current timestamp, NULL if error. It must be freed. 
 */
ccapi_timestamp_t *get_timestamp_by_type(cc_timestamp_type_t type);

/*
 * free_timestamp() - Free given timestamp structure
 *
 * This is equivalent to 'free_timestamp_by_type(timestamp, CC_TS_DEFAULT)'.
 * 'CC_TS_DEFAULT' is equivalent to 'CC_TS_EPOCH'.
 *
 * @timestamp:	The timestamp structure to release.
 */
void free_timestamp(ccapi_timestamp_t *timestamp);

/*
 * free_timestamp_by_type() - Free given timestamp structure
 *
 * @timestamp:	The timestamp structure to release.
 * @type:	Timestamp type, 'CC_TS_DEFAULT' to use default timestamp type, 'CC_TS_EPOCH'.
 */
void free_timestamp_by_type(ccapi_timestamp_t *timestamp, cc_timestamp_type_t type);

#endif /* _CC_UTILS_H__ */