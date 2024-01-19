/*
 * Copyright (c) 2022, 2023 Digi International Inc.
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

#ifndef SERVICE_DATA_REQUEST_H
#define SERVICE_DATA_REQUEST_H

#include "cc_config.h"
#include "service_common.h"

int handle_register_data_request(int fd, const cc_cfg_t *const cc_cfg);
int handle_unregister_data_request(int fd, const cc_cfg_t *const cc_cfg);
int handle_register_data_request_ipv4(int fd, const cc_cfg_t *const cc_cfg);
int handle_unregister_data_request_ipv4(int fd, const cc_cfg_t *const cc_cfg);

/*
 * register_builtin_requests() - Register built-in data requests
 *
 * Return: Error code after registering the built-in data requests.
 */
ccapi_receive_error_t register_builtin_requests(void);

#endif /* SERVICE_DATA_REQUEST_H */
