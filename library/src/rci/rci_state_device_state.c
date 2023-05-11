/*
 * Copyright (c) 2017-2022 Digi International Inc.
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

#include <stdio.h>
#include "rci_state_device_state.h"
#include "cc_logging.h"
#include <linux/kernel.h>       /* for struct sysinfo */
#include <sys/sysinfo.h>

ccapi_state_device_state_error_id_t rci_state_device_state_start(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return CCAPI_STATE_DEVICE_STATE_ERROR_NONE;
}

ccapi_state_device_state_error_id_t rci_state_device_state_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return CCAPI_STATE_DEVICE_STATE_ERROR_NONE;
}

ccapi_state_device_state_error_id_t rci_state_device_state_system_up_time_get(
		ccapi_rci_info_t * const info, uint32_t * const value)
{
	ccapi_state_device_state_error_id_t ret = CCAPI_STATE_DEVICE_STATE_ERROR_NONE;
	struct sysinfo s_info;
	int error;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	error = sysinfo(&s_info);
	if (error) {
		log_error("sysinfo failed: %s", strerror(error));
		ret = CCAPI_STATE_DEVICE_STATE_ERROR_LOAD_FAIL;
	} else {
		*value = s_info.uptime;
	}

	return ret;
}
