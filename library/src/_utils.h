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

#ifndef ___UTILS_H__
#define ___UTILS_H__

#include <stdint.h>

#ifndef TEMP_FAILURE_RETRY

#define TEMP_FAILURE_RETRY(expression) ({ \
	__typeof(expression) __temp_result; \
	do { \
			__temp_result = (expression); \
	} while (__temp_result == (__typeof(expression))-1 && errno == EINTR); \
	__temp_result; \
})

#endif

int mkpath(char *dir, mode_t mode);
int crc32file(char const *const path, uint32_t *crc);
char *delete_quotes(char *str);
char *delete_leading_spaces(char *str);
char *delete_trailing_spaces(char *str);
char *trim(char *str);
char *delete_newline_character(char *str);

int ccimp_logging_init(void);
void ccimp_logging_deinit(void);

#endif /* ___UTILS_H__ */
