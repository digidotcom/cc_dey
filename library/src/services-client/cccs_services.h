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

#ifndef _CCCS_SERVICES_H_
#define _CCCS_SERVICES_H_

#include "cc_logging.h"
#include "cccs_datapoints.h"
#include "cccs_receive.h"

#define CCCSD_WAIT_FOREVER		-1
#define CCCSD_NO_WAIT			0

/*
 * cccs_is_daemon_ready() - Check if CCCS daemon is ready
 *
 * @timeout:	Number of seconds to wait for CCCS daemon readiness.
 *		CCCSD_WAIT_FOREVER to block until the daemon is ready,
 *		CCCSD_NO_WAIT to return immediately,
 *		any other value blocks until either the daemon is ready or the time is up.
 *
 * Return: True if ready, false otherwise.
 */
bool cccs_is_daemon_ready(long timeout);

/*
 * cccs_set_maintenance_status() - Enable or disable maintenance status
 *
 * @status:	True to enable maintenance, false otherwise.
 * @timeout:	Number of seconds to wait for a response from the daemon.
 * @resp:	Received response from CCCS daemon.
 *
 * Response may contain a string with the result of the operation (resp->hint).
 * This string must be freed.
 *
 * Return: CCCS_SEND_ERROR_NONE if success, any other error if the
 *         communication with the daemon fails.
 */
cccs_comm_error_t cccs_set_maintenance_status(bool status, unsigned long const timeout, cccs_resp_t *resp);

#endif /* _CCCS_SERVICES_H_ */
