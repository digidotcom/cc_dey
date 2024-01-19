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

#include "ccimp/ccimp_os_condition.h"
#include "cc_logging.h"
#include "_utils.h"

#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

struct ccimp_os_condition_st {
	bool cond_init;
	bool mutex_init;

	pthread_cond_t cond;
	pthread_mutex_t lock;
};

static uint32_t const ns_per_sec = 1000000000;
static uint32_t const ms_per_sec = 1000;
static uint32_t const ns_per_ms = ns_per_sec / ms_per_sec;

static inline void timespec_add_ns(struct timespec * const ts, uint64_t const ns)
{
	uint64_t const new_ns = ts->tv_nsec + ns;

	ts->tv_nsec = new_ns % ns_per_sec;
	ts->tv_sec += new_ns / ns_per_sec;
}

static int wait_for_condition(
	ccimp_os_condition_st * const cond, struct timespec const * const ts)
{
	int ret;

	if (ts == NULL)
		ret = TEMP_FAILURE_RETRY(pthread_cond_wait(&cond->cond, &cond->lock));
	else
		ret = TEMP_FAILURE_RETRY(pthread_cond_timedwait(&cond->cond, &cond->lock, ts));

	return ret;
}

ccimp_status_t ccimp_os_condition_init(ccimp_os_condition_st * const cond)
{
	pthread_condattr_t cattr;

	if (cond == NULL) {
		log_error("%s: NULL cond", __func__);
		return CCIMP_STATUS_ERROR;
	}

	if (pthread_mutex_init(&cond->lock, NULL) != 0) {
		log_error("%s: mutex init failed", __func__);
		return CCIMP_STATUS_ERROR;
	}
	cond->mutex_init = true;

	pthread_condattr_init(&cattr);
	if (pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC) != 0) {
		log_error("%s: condattr setclock failed", __func__);
		pthread_condattr_destroy(&cattr);
		return CCIMP_STATUS_ERROR;
	}

	if (pthread_cond_init(&cond->cond, &cattr) != 0) {
		log_error("%s: cond init failed", __func__);
		pthread_condattr_destroy(&cattr);
		return CCIMP_STATUS_ERROR;
	}
	cond->cond_init = true;

	pthread_condattr_destroy(&cattr);
	return CCIMP_STATUS_OK;
}

ccimp_status_t ccimp_os_condition_destroy(ccimp_os_condition_st * const cond)
{
	ccimp_status_t res = CCIMP_STATUS_OK;

	if (cond == NULL) {
		log_error("%s: NULL cond", __func__);
		return CCIMP_STATUS_ERROR;
	}

	if (cond->mutex_init && pthread_mutex_destroy(&cond->lock) != 0) {
		log_error("%s: mutex destroy failed", __func__);
		res = CCIMP_STATUS_ERROR;
	}

	if (cond->cond_init && pthread_cond_destroy(&cond->cond) != 0) {
		log_error("%s: cond destroy failed", __func__);
		res = CCIMP_STATUS_ERROR;
	}

	return res;
}

ccimp_os_condition_st * ccimp_os_condition_alloc(void)
{
	ccimp_os_condition_st * const cond = calloc(1, sizeof *cond);

	return cond;
}

void ccimp_os_condition_free(ccimp_os_condition_st * const cond)
{
	free(cond);
}

ccimp_status_t ccimp_os_condition_lock(ccimp_os_condition_st * const cond)
{
	if (cond == NULL) {
		log_error("%s: NULL cond", __func__);
		return CCIMP_STATUS_ERROR;
	}

	if (pthread_mutex_lock(&cond->lock) != 0) {
		log_error("%s: failed", __func__);
		return CCIMP_STATUS_ERROR;
	}

	return CCIMP_STATUS_OK;
}

ccimp_status_t ccimp_os_condition_unlock(ccimp_os_condition_st * const cond)
{
	if (cond == NULL) {
		log_error("%s: NULL cond", __func__);
		return CCIMP_STATUS_ERROR;
	}

	if (pthread_mutex_unlock(&cond->lock) != 0) {
		log_error("%s: failed", __func__);
		return CCIMP_STATUS_ERROR;
	}

	return CCIMP_STATUS_OK;
}

ccimp_status_t ccimp_os_condition_wait(
	ccimp_os_condition_st * const cond,
	unsigned const max_wait_millisecs,
	ccimp_os_condition_predicate_fn const predicate_cb,
	void * const cb_ctx)
{
	int ret;
	struct timespec ts;
	struct timespec * pts;

	if (cond == NULL) {
		log_error("%s: NULL cond", __func__);
		return CCIMP_STATUS_ERROR;
	}

	if (max_wait_millisecs != OS_CONDITION_WAIT_INFINITE) {
		pts = &ts;
		clock_gettime(CLOCK_MONOTONIC, pts);
		timespec_add_ns(pts, (uint64_t)max_wait_millisecs * ns_per_ms);
	}
	else {
		pts = NULL;
	}

	ret = 0;

	if (ccimp_os_condition_lock(cond) != CCIMP_STATUS_OK)
		return CCIMP_STATUS_ERROR;

	while (predicate_cb(cb_ctx) == CCAPI_FALSE && ret == 0)
		ret = wait_for_condition(cond, pts);

	if (ccimp_os_condition_unlock(cond) != CCIMP_STATUS_OK)
		return CCIMP_STATUS_ERROR;

	if (ret == ETIMEDOUT) {
		return CCIMP_STATUS_BUSY;
	}
	else if (ret != 0) {
		log_error("%s: wait error", __func__);
		return CCIMP_STATUS_ERROR;
	}

	return CCIMP_STATUS_OK;
}

ccimp_status_t ccimp_os_condition_signal(ccimp_os_condition_st * const cond)
{
	if (cond == NULL) {
		log_error("%s: NULL cond", __func__);
		return CCIMP_STATUS_ERROR;
	}

	if (pthread_cond_signal(&cond->cond) != 0) {
		log_error("%s: failed", __func__);
		return CCIMP_STATUS_ERROR;
	}

	return CCIMP_STATUS_OK;
}

ccimp_status_t ccimp_os_condition_broadcast(ccimp_os_condition_st * const cond)
{
	if (cond == NULL) {
		log_error("%s: NULL cond", __func__);
		return CCIMP_STATUS_ERROR;
	}

	if (pthread_cond_broadcast(&cond->cond) != 0) {
		log_error("%s: failed", __func__);
		return CCIMP_STATUS_ERROR;
	}

	return CCIMP_STATUS_OK;
}
