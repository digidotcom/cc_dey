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

#include <cccs_services.h>
#include <libdigiapix/gpio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "data_points.h"

#define LOOP_MS				100UL
#define USER_BUTTON_ALIAS		"USER_BUTTON"
#define DATA_STREAM_USER_BUTTON		"demo_monitor/user_button"
#define DATA_STREAM_BUTTON_UNITS	"state"

#define MONITOR_TAG			"DEMO-MON:"

/**
 * log_mon_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_mon_debug(format, ...)					\
	log_debug("%s " format, MONITOR_TAG, __VA_ARGS__)

/**
 * log_mon_info() - Log the given message as info
 *
 * @format:		Info message to log.
 * @args:		Additional arguments.
 */
#define log_mon_info(format, ...)					\
	log_info("%s " format, MONITOR_TAG, __VA_ARGS__)

/**
 * log_mon_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_mon_error(format, ...)					\
	log_error("%s " format, MONITOR_TAG, __VA_ARGS__)

/**
 * button_cb_data_t - Data for button interrupt
 *
 * @button:		GPIO button.
 * @dp_collection:	Collection of data points to store the button value.
 * @value:		Last status of the GPIO.
 * @num_samples_upload:	Number of samples to store before uploading.
 */
typedef struct {
	gpio_t *button;
	cccs_dp_collection_handle_t dp_collection;
	gpio_value_t value;
	uint32_t num_samples_upload;
} button_cb_data_t;

static bool is_running = false;
static button_cb_data_t cb_data;

/*
 * get_user_button() - Retrieves the user button GPIO
 *
 * Return: The user button GPIO, NULL on error.
 */
static gpio_t *get_user_button(void)
{
	if (cb_data.button != NULL)
		return cb_data.button;
	cb_data.button = ldx_gpio_request_by_alias(USER_BUTTON_ALIAS, 
		GPIO_IRQ_EDGE_BOTH, REQUEST_SHARED);
	if (cb_data.button == NULL)
		return NULL;
	ldx_gpio_set_active_mode(cb_data.button, GPIO_ACTIVE_HIGH);

	return cb_data.button;
}

/*
 * init_monitor() - Create and initialize the monitor data point collection
 *
 * @dp_collection:	Data point collection.
 *
 * Return: Error code after the initialization of the monitor collection.
 *
 * The return value will always be 'CCCS_DP_ERROR_NONE' unless there is any
 * problem creating the collection.
 */
static cccs_dp_error_t init_monitor(cccs_dp_collection_handle_t *dp_collection)
{
	cccs_dp_error_t dp_error = cccs_dp_create_collection(dp_collection);

	if (dp_error != CCCS_DP_ERROR_NONE) {
		log_mon_error("Error initializing demo monitor, %d", dp_error);
		return dp_error;
	}

	dp_error = cccs_dp_add_data_stream_to_collection_extra(*dp_collection,
			DATA_STREAM_USER_BUTTON, CCCS_DP_KEY_DATA_INT32,
			true, DATA_STREAM_BUTTON_UNITS, NULL);
	if (dp_error != CCCS_DP_ERROR_NONE) {
		log_mon_error("Cannot add '%s' stream to data point collection, error %d",
					DATA_STREAM_USER_BUTTON, dp_error);
		return dp_error;
	}

	return CCCS_DP_ERROR_NONE;
}

/*
 * add_button_sample() - Add USER_BUTTON value to the data point collection
 *
 * @data:	Button interrupt data (button_cb_data_t).
 */
static void add_button_sample(button_cb_data_t *data)
{
	cccs_dp_error_t dp_error;
	uint32_t count = 0;

	data->value = data->value ? GPIO_LOW : GPIO_HIGH;

	dp_error = cccs_dp_add(data->dp_collection, DATA_STREAM_USER_BUTTON,
			data->value);
	if (dp_error != CCCS_DP_ERROR_NONE) {
		log_mon_error("Cannot add user_button value, %d", dp_error);
		return;
	} else {
		log_mon_debug("user_button = %d %s", data->value, DATA_STREAM_BUTTON_UNITS);
	}

	cccs_dp_get_collection_points_count(data->dp_collection, &count);
	if (count >= data->num_samples_upload) {
		cccs_comm_error_t ret;
		cccs_resp_t resp;

		log_mon_debug("Sending %s samples", USER_BUTTON_ALIAS);
		ret = cccs_send_dp_collection_tout(data->dp_collection, 5, &resp);
		if (ret != CCCS_SEND_ERROR_NONE) {
			log_mon_error("Error sending monitor samples: CCCSD error %d", ret);
		} else if (resp.code != 0) {
			if (resp.hint)
				log_mon_error("Error sending monitor samples: CCCSD error, %s (%d)", resp.hint, resp.code);
			else
				log_mon_error("Error sending monitor samples: CCCSD error, %d", resp.code);
		}

		free(resp.hint);
	}
}

/*
 * button_interrupt_cb() - Callback for button interrupts
 *
 * @arg:	Button interrupt data (button_cb_data_t).
 */
static int button_interrupt_cb(void *arg)
{
	button_cb_data_t *data = arg;

	if (data->button == NULL) {
		log_mon_error("Cannot get %s value: Failed to initialize user button", USER_BUTTON_ALIAS);
		return GPIO_VALUE_ERROR;
	}

	log_mon_debug("%s interrupt detected", USER_BUTTON_ALIAS);

	add_button_sample(data);

	return 0;
}

int start_monitoring(void)
{
	if (is_monitoring())
		return 0;

	cccs_dp_error_t dp_error = init_monitor(&cb_data.dp_collection);
	if (dp_error != CCCS_DP_ERROR_NONE)
		goto error;

	cb_data.button = get_user_button();
	if (cb_data.button == NULL)
		goto error;

	cb_data.value = GPIO_HIGH;
	cb_data.num_samples_upload = 2;

	if (ldx_gpio_start_wait_interrupt(cb_data.button, &button_interrupt_cb, &cb_data) != EXIT_SUCCESS) {
		log_mon_error("Error initializing demo monitor: Unable to capture %s interrupts", USER_BUTTON_ALIAS);
		goto error;
	}

	is_running = true;

	return 0;

error:
	ldx_gpio_free(cb_data.button);
	cccs_dp_destroy_collection(cb_data.dp_collection);

	return 1;
}

bool is_monitoring(void) {
	return is_running;
}

void stop_monitoring(void)
{
	if (!is_monitoring())
		return;

	if (cb_data.button != NULL)
		ldx_gpio_stop_wait_interrupt(cb_data.button);

	ldx_gpio_free(cb_data.button);
	cccs_dp_destroy_collection(cb_data.dp_collection);

	is_running = false;

	log_mon_info("%s", "Stop monitoring");
}
