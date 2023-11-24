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

#ifndef CC_FIRMWARE_UPDATE_H_
#define CC_FIRMWARE_UPDATE_H_

#include <stdbool.h>

#include "ccapi/ccapi.h"

/*
 * init_fw_service() - Initialization of firmware service
 *
 * @enable:	True to enable the firmware service, false otherwise.
 * @fw_version:	The current firmware version.
 * @fw_service:	Struct to store the firmware service initialization.
 *
 * Returns: 0 on success, 1 otherwise.
 */
int init_fw_service(const bool enable, const char * const fw_version, ccapi_fw_service_t **fw_service);

#endif /* CC_FIRMWARE_UPDATE_H_ */
