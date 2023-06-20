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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "_utils.h"
#include "cc_logging.h"
#include "ccimp/ccimp_logging.h"

#if (defined UNIT_TEST)
#define ccimp_hal_logging_vprintf		ccimp_hal_logging_vprintf_real
#endif

#if (defined CCIMP_DEBUG_ENABLED)

#define CCAPI_DEBUG_PREFIX		"[DEBUG] CCAPI: "

static struct {
	pthread_mutex_t mutex;
	bool init;
	char * data;
	size_t length;
	size_t offset;
	size_t remaining;
} buffer;

static bool enlarge_buffer(size_t const additional)
{
	size_t const characters = 80;
	size_t const lines = (additional + characters - 1) / characters;
	size_t const length = buffer.length + (lines * characters);
	char * const new = realloc(buffer.data, length);
	bool const success = (new != NULL);

	if (success) {
		buffer.data = new;
		buffer.length = length;
		buffer.remaining = (buffer.length - buffer.offset);
	}

	return success;
}

static bool lock(void)
{
	static struct timespec const timeout = { .tv_sec = 1, .tv_nsec = 0 };
	int result;

	result = pthread_mutex_timedlock(&buffer.mutex, &timeout);
	if (result == 0)
		goto done;

	if (result != EOWNERDEAD) {
		log_error(CCAPI_DEBUG_PREFIX "pthread_mutex_timedlock() failure: %d", result);
		goto done;
	}

	result = pthread_mutex_consistent(&buffer.mutex);
	if (result != 0) {
		log_error(CCAPI_DEBUG_PREFIX "pthread_mutex_consistent() failure: %d", result);
		goto done;
	}

done:
	return (result == 0);
}

static void unlock(void)
{
	int const result = pthread_mutex_unlock(&buffer.mutex);

	if (result != 0) {
		log_error(CCAPI_DEBUG_PREFIX "pthread_mutex_unlock() failure: %d", result);
	}
}

static void buffer_printf(char const * const format, va_list args)
{
	bool retry = true;

	if (!buffer.data)
		return;

	for (;;) {
		int const result = vsnprintf(buffer.data + buffer.offset, buffer.remaining, format, args);

		if (result < 0) {
			log_error(CCAPI_DEBUG_PREFIX "vsnprintf() failure: %d", result);
			syslog(LOG_DEBUG, format, args);
			break;
		}

		if ((size_t)result < buffer.remaining) {
			buffer.offset += result;
			buffer.remaining -= result;
			break;
		}

		if (!retry) {
			log_error(CCAPI_DEBUG_PREFIX "buffer overflow: %d/%zu/%zu", result, buffer.remaining, buffer.length);
			syslog(LOG_DEBUG, format, args);
			break;
		}

		enlarge_buffer(result);
		retry = false;
	}
}

static void buffer_flush(void)
{
	char * state;
	char * line;

	for (char * s = buffer.data; (line = strtok_r(s, "\n", &state)); s = NULL) {
		syslog(LOG_DEBUG, "%s", line);
	}

	buffer.offset = 0;
	buffer.remaining = buffer.length;
}

static void buffer_reset(void)
{
	if (buffer.offset != 0) {
		log_error(CCAPI_DEBUG_PREFIX "buffer invalid state: %zu", buffer.offset);
		syslog(LOG_DEBUG, "%s", buffer.data);
		buffer_flush();
	}

	if (buffer.data) {
		strcpy(buffer.data, CCAPI_DEBUG_PREFIX);
		buffer.offset = strlen(CCAPI_DEBUG_PREFIX);
		buffer.remaining -= buffer.offset;
	}
}

int ccimp_logging_init(void)
{
	pthread_mutexattr_t attribute;
	int result;

	if (buffer.init)
		return 0;

	result = pthread_mutexattr_init(&attribute);
	if (result != 0) {
		log_error(CCAPI_DEBUG_PREFIX "pthread_attr_init() failure: %d", result);
		return result; // no cleanup needed
	}

	result = pthread_mutexattr_settype(&attribute, PTHREAD_MUTEX_ERRORCHECK);
	if (result != 0) {
		log_error(CCAPI_DEBUG_PREFIX "pthread_mutexattr_settype() failure: %d", result);
		goto done;
	}

	result = pthread_mutexattr_setrobust(&attribute, PTHREAD_MUTEX_ROBUST);
	if (result != 0) {
		log_error(CCAPI_DEBUG_PREFIX "pthread_mutexattr_setrobust() failure: %d", result);
		goto done;
	}

	result = pthread_mutex_init(&buffer.mutex, &attribute);
	if (result != 0) {
		log_error(CCAPI_DEBUG_PREFIX "pthread_mutex_init() failure: %d", result);
		goto done;
	}

	{
		size_t const minimum = sizeof CCAPI_DEBUG_PREFIX;

		if (!enlarge_buffer(minimum)) {
			log_error(CCAPI_DEBUG_PREFIX "enlarge_buffer() failure: %zu", minimum);
			pthread_mutex_destroy(&buffer.mutex);
			goto done;
		}
	}

	buffer.init = true;
	result = 0;

done:
	pthread_mutexattr_destroy(&attribute);
	return result;
}

void ccimp_hal_logging_vprintf(debug_t const debug, char const * const format, va_list args)
{
	if (!buffer.init)
		return;

	switch (debug)
	{
		case debug_beg:
		case debug_all:
		{
			if (!lock()) {
				syslog(LOG_DEBUG, format, args);
				return;
			}

			buffer_reset();
			break;
		}

		case debug_mid:
		case debug_end:
			break;
	}

	buffer_printf(format, args);

	switch (debug)
	{
		case debug_end:
		case debug_all:
		{
			buffer_flush();
			unlock();
			break;
		}

		case debug_beg:
		case debug_mid:
			break;
	}

	return;
}

void ccimp_logging_deinit(void)
{
	if (!buffer.init)
		return;

	pthread_mutex_destroy(&buffer.mutex);
	free(buffer.data);
	buffer.data = NULL;
	buffer.length = 0;
	buffer.offset = 0;
	buffer.remaining = 0;
	buffer.init = false;
}

#else /* CCIMP_DEBUG_ENABLED */
int ccimp_logging_init(void)
{
	return 0;
}

void ccimp_logging_deinit(void)
{
	return;
}
#endif /* CCIMP_DEBUG_ENABLED */
