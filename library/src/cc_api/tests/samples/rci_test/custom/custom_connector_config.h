/*
* Copyright (c) 2017 Digi International Inc.
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
* Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
* =======================================================================
*/

#ifndef _CUSTOM_CONNECTOR_CONFIG_H_
#define _CUSTOM_CONNECTOR_CONFIG_H_

#include "rci_usenames_defines.h"
/* Cloud Connector Configuration Categories */

/* Services */
#define CCIMP_RCI_SERVICE_ENABLED
/*#define CCIMP_FIRMWARE_SERVICE_ENABLED */
#define CCIMP_FILE_SYSTEM_SERVICE_ENABLED

/* OS Features */
#define CCIMP_LITTLE_ENDIAN
#define CCIMP_COMPRESSION_ENABLED
#define CCIMP_64_BIT_INTEGERS_SUPPORTED
#define CCIMP_FLOATING_POINT_SUPPORTED

#define CCIMP_HAS_STDINT_HEADER

/* Debugging (Logging / Halt) */
#define CCIMP_DEBUG_ENABLED

/* Limits */
#define CCIMP_FILE_SYSTEM_MAX_PATH_LENGTH   256
#undef  CCIMP_FILE_SYSTEM_LARGE_FILES_SUPPORTED

#define CCIMP_SM_UDP_MAX_RX_SEGMENTS   256
#define CCIMP_SM_SMS_MAX_RX_SEGMENTS   256

#define CCIMP_IDLE_SLEEP_TIME_MS 100

#endif /* _CUSTOM_CONNECTOR_CONFIG_H_ */
