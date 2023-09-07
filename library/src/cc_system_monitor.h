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

#ifndef CC_SYSTEM_MONITOR_H_
#define CC_SYSTEM_MONITOR_H_

#include <stdbool.h>

#include "cc_config.h"

typedef enum {
	CC_SYS_MON_ERROR_NONE,
	CC_SYS_MON_ERROR_THREAD
} cc_sys_mon_error_t;

/*
 * start_system_monitor() - Start the monitoring of system variables
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the
 * 			settings parsed from the configuration file are stored.
 *
 * The variables being monitored are: CPU temperature, CPU load, and free
 * memory.
 *
 * Return: Error code after starting the monitoring.
 */
cc_sys_mon_error_t start_system_monitor(const cc_cfg_t * const cc_cfg);

/*
 * is_system_monitor_running() - Check system monitor status
 *
 * Return: True if system monitor is running, false if it is not.
 */
bool is_system_monitor_running(void);

/*
 * stop_system_monitor() - Stop the monitoring of system variables
 */
void stop_system_monitor(void);

#endif /* CC_SYSTEM_MONITOR_H_ */
