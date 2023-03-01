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

#include "cc_logging.h"
#include "cc_system_monitor.h"
#include "cc_config.h"
#include "rci_setting_system_monitor.h"

extern cc_cfg_t *cc_cfg;

static int restart = 0;

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_start(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	return CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
}

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	if (restart) {
		stop_system_monitor();
		start_system_monitor(cc_cfg);
		restart = 0;
	}

	return CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
}

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_enable_sysmon_get(
		ccapi_rci_info_t * const info, ccapi_on_off_t * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	*value = (cc_cfg->services & SYS_MONITOR_SERVICE) ? CCAPI_ON : CCAPI_OFF;

	return CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
}

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_enable_sysmon_set(
		ccapi_rci_info_t * const info, ccapi_on_off_t const * const value)
{
	ccapi_setting_system_monitor_error_id_t ret = CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	if (*value == CCAPI_ON) {
		cc_cfg->services |= SYS_MONITOR_SERVICE;
		if (start_system_monitor(cc_cfg) != CC_SYS_MON_ERROR_NONE)
			ret = CCAPI_SETTING_SYSTEM_MONITOR_ERROR_MEMORY_FAIL;
	} else {
		stop_system_monitor();
		cc_cfg->services &= ~SYS_MONITOR_SERVICE;
	}

	return ret;
}

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_sample_rate_get(
		ccapi_rci_info_t * const info, uint32_t * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	*value = cc_cfg->sys_mon_sample_rate;

	return CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
}

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_sample_rate_set(
		ccapi_rci_info_t * const info, uint32_t const * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	cc_cfg->sys_mon_sample_rate = *value;

	return CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
}

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_n_dp_upload_get(
		ccapi_rci_info_t * const info, uint32_t * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	*value = cc_cfg->sys_mon_num_samples_upload;

	return CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
}

ccapi_setting_system_monitor_error_id_t rci_setting_system_monitor_n_dp_upload_set(
		ccapi_rci_info_t * const info, uint32_t const * const value)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'\n", __func__);

	cc_cfg->sys_mon_num_samples_upload = *value;

	return CCAPI_SETTING_SYSTEM_MONITOR_ERROR_NONE;
}
