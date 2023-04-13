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

#include <linux/reboot.h>
#include <stdio.h>
#include <sys/reboot.h>
#include <unistd.h>

#include "ccimp/ccimp_hal.h"
#include "cc_logging.h"

/*------------------------------------------------------------------------------
                             D E F I N I T I O N S
------------------------------------------------------------------------------*/
#if (defined UNIT_TEST)
#define ccimp_hal_halt			ccimp_hal_halt_real
#define ccimp_hal_reset			ccimp_hal_reset_real
#endif

/*------------------------------------------------------------------------------
                     F U N C T I O N  D E F I N I T I O N S
------------------------------------------------------------------------------*/

#if (defined CCIMP_DEBUG_ENABLED)
ccimp_status_t ccimp_hal_halt(void)
{
	log_debug("%s", "Halt evoked: Shutting down connector");

	exit(2);

	/* Should not get here */

	return CCIMP_STATUS_OK;
}
#endif

ccimp_status_t ccimp_hal_reset(void)
{
	log_debug("%s", "Resetting device");

	/* Note: we must be running as the superuser to reboot the system */
	sync();
	reboot(LINUX_REBOOT_CMD_RESTART);

	/* Should not get here */
	return CCIMP_STATUS_OK;
}

