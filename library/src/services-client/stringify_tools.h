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
#ifndef _STRINGIFY_TOOLS_H_
#define _STRINGIFY_TOOLS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define largest_uint_t uint64_t
#define largest_int_t int64_t

#define QUOTES_NEEDED_FLAG		UINT32_C(0x01)

#define BitClear(flag, bit)		((flag) &= ~(bit))

#define ClearQuotesNeeded(flag)		BitClear((flag), QUOTES_NEEDED_FLAG)

typedef struct {
	largest_uint_t value;
	int figures;
	bool negative;
	unsigned int base;
} int_info_t;

typedef struct {
	int_info_t integer;
	int_info_t fractional;
	bool point_set;
} double_info_t;

typedef struct {
	char const * next_char;
	int quotes_info;
} string_info_t;

typedef struct {
	char * buffer;
	size_t bytes_available;
	size_t bytes_written;
} buffer_info_t;

bool put_character(char const character, buffer_info_t * const buffer_info);
bool process_integer(int_info_t * const int_info, buffer_info_t * const buffer_info);
bool process_string(string_info_t * const string_info, buffer_info_t * const buffer_info);
bool process_double(double_info_t * const double_info, buffer_info_t * const buffer_info);
void init_int_info(int_info_t * const int_info, largest_int_t const value, unsigned int const base);
void init_double_info(double_info_t * const double_info, double const value);
void init_string_info(string_info_t * const string_info, char const * const string);

#endif /* _STRINGIFY_TOOLS_H_ */