/*
 * Copyright (c) 2016-2023 Digi International Inc.
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

#ifndef CC_LOGGING_H_
#define CC_LOGGING_H_

#include <syslog.h>

/*------------------------------------------------------------------------------
                             D E F I N I T I O N S
------------------------------------------------------------------------------*/
#define DAEMON_NAME			"CONNECTOR"

/*------------------------------------------------------------------------------
                                  M A C R O S
------------------------------------------------------------------------------*/
#ifndef UNUSED_ARGUMENT
#define UNUSED_ARGUMENT(a)		(void)(a)
#endif

/**
 * init_logger() - Initialize the logger with the given log level
 *
 * @level:	Log level.
 */
#define init_logger(level, options)								\
	do {														\
		openlog(DAEMON_NAME, options, LOG_USER);				\
		setlogmask(LOG_UPTO(level));							\
	} while (0)

/**
 * set_log_level() - Set the new log level
 *
 * @level:	New log level.
 */
#define set_log_level(level)									\
	setlogmask(LOG_UPTO(level))

/**
 * log_error() - Log the given message as error
 *
 * @format:	Error message to log.
 * @args:	Additional arguments.
 */
#define log_error(format, ...)										\
	syslog(LOG_ERR, "[ERROR] " format, __VA_ARGS__)

/**
 * log_warning() - Log the given message as warning
 *
 * @format:	Info message to log.
 * @args:	Additional arguments.
 */
#define log_warning(format, ...)									\
	syslog(LOG_WARNING, "[WARN] " format, __VA_ARGS__)


/**
 * log_info() - Log the given message as info
 *
 * @format:	Info message to log.
 * @args:	Additional arguments.
 */
#define log_info(format, ...)										\
	syslog(LOG_INFO, "[INFO] " format, __VA_ARGS__)

/**
 * log_debug() - Log the given message as debug
 *
 * @format:	Debug message to log.
 * @args:	Additional arguments.
 */
#define log_debug(format, ...)										\
	syslog(LOG_DEBUG, "[DEBUG] " format, __VA_ARGS__)

#endif /* CC_LOGGING_H_ */
