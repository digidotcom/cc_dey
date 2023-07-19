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

#ifndef DEVICE_REQUEST_H_
#define DEVICE_REQUEST_H_

#include <cloudconnector.h>

#if !(defined ARRAY_SIZE)
#define ARRAY_SIZE(array)		(sizeof(array) / sizeof(array[0]))
#endif

/*
 * register_cc_device_requests() - Register custom device requests
 *
 * Return: Error code after registering the custom device requests.
 */
ccapi_receive_error_t register_cc_device_requests(void);

/*
 * unregister_cc_device_requests() - Unregister custom device requests
 */
void unregister_cc_device_requests(void);

#endif /* DEVICE_REQUEST_H_ */