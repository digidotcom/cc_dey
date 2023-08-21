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

#ifndef SERVICE_DEVICE_REQUEST_H
#define SERVICE_DEVICE_REQUEST_H

#define REQ_TAG_REGISTER_DR		"register_devicerequest"
#define REQ_TAG_UNREGISTER_DR		"unregister_devicerequest"
#define REQ_TAG_REGISTER_DR_IPV4	"register_devicerequest_ipv4"
#define REQ_TAG_UNREGISTER_DR_IPV4	"unregister_devicerequest_ipv4"

#define REQ_TYPE_REQUEST_CB	"request"
#define REQ_TYPE_STATUS_CB	"status"

int handle_register_device_request(int fd);
int handle_unregister_device_request(int fd);
int handle_register_device_request_ipv4(int fd);
int handle_unregister_device_request_ipv4(int fd);

/*
 * register_builtin_requests() - Register built-in device requests
 *
 * Return: Error code after registering the built-in device requests.
 */
ccapi_receive_error_t register_builtin_requests(void);

#endif
