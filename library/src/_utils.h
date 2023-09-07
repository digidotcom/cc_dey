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

/**
 * mkpath() - Create a directory and its parents if they do not exist
 *
 * @dir:	Full path of the directory to create.
 * @mode:	Permissions to use.
 *
 * Return: 0 if success, -1 otherwise.
 */
int mkpath(char *dir, mode_t mode);

/**
 * crc32file() - Calculate the CRC32 hash of a file
 *
 * @path:	Full path of the file to calculate its CRC32 hash.
 * @crc:	CRC32 hash calculated.
 *
 * Returns: 0 if success, -1 otherwise.
 */
int crc32file(char const *const path, uint32_t *crc);

/*
 * delete_quotes() - Delete quotes from the given string.
 *
 * @str:	String to delete quotes from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without the quotes.
 */
char *delete_quotes(char *str);

/*
 * delete_leading_spaces() - Delete leading spaces from the given string.
 *
 * @str:	String to delete leading spaces from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without leading white spaces.
 */
char *delete_leading_spaces(char *str);

/*
 * delete_trailing_spaces() - Delete trailing spaces from the given string.
 *
 * Trailing spaces also include new line '\n' and carriage return '\r' chars.
 *
 * @str:	String to delete trailing spaces from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without trailing white spaces.
 */
char *delete_trailing_spaces(char *str);

/*
 * trim() - Trim the given string removing leading and trailing spaces.
 *
 * Trailing spaces also include new line '\n' and carriage return '\r' chars.
 *
 * @str:	String to delete leading and trailing spaces from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without leading nor trailing white spaces.
 */
char *trim(char *str);

/*
 * delete_newline_character() - Remove new line character '\n' from the end of
 *                              the given string.
 *
 * @str:	String to delete ending new line character '\n' from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without the final new line.
 */
char *delete_newline_character(char *str);

int ccimp_logging_init(void);
void ccimp_logging_deinit(void);

#endif /* ___UTILS_H__ */
