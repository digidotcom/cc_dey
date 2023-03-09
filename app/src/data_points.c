/*
 * Copyright (c) 2022, 2023 Digi International Inc.
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

#include <cloudconnector.h>
#include <libdigiapix/gpio.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "data_points.h"

/*------------------------------------------------------------------------------
                             D E F I N I T I O N S
------------------------------------------------------------------------------*/
#define LOOP_MS						100UL

#define USER_BUTTON_ALIAS			"USER_BUTTON"

#define DATA_STREAM_USER_BUTTON		"demo_monitor/user_button"

#define DATA_STREAM_BUTTON_UNITS	"state"

#define MONITOR_TAG					"MON:"

/*------------------------------------------------------------------------------
                 D A T A    T Y P E S    D E F I N I T I O N S
------------------------------------------------------------------------------*/
/**
 * button_cb_data_t - Data for button interrupt
 *
 * @button:			GPIO button.
 * @dp_collection:	Collection of data points to store the button value.
 */
typedef struct {
	gpio_t *button;
	ccapi_dp_collection_handle_t dp_collection;
	gpio_value_t value;
	uint32_t num_samples_upload;
} button_cb_data_t;

/*------------------------------------------------------------------------------
                    F U N C T I O N  D E C L A R A T I O N S
------------------------------------------------------------------------------*/
static ccapi_dp_error_t init_monitor(ccapi_dp_collection_handle_t *dp_collection);
static gpio_t *get_user_button(void);
static int button_interrupt_cb(void *arg);
static void add_button_sample(button_cb_data_t *data);
static ccapi_timestamp_t *get_timestamp(void);
static void free_timestamp(ccapi_timestamp_t *timestamp);

/*------------------------------------------------------------------------------
                                  M A C R O S
------------------------------------------------------------------------------*/
/**
 * log_mon_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_mon_debug(format, ...)									\
	log_debug("%s " format, MONITOR_TAG, __VA_ARGS__)

/**
 * log_mon_info() - Log the given message as info
 *
 * @format:		Info message to log.
 * @args:		Additional arguments.
 */
#define log_mon_info(format, ...)									\
	log_info("%s " format, MONITOR_TAG, __VA_ARGS__)

/**
 * log_mon_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_mon_error(format, ...)									\
	log_error("%s " format, MONITOR_TAG, __VA_ARGS__)

/*------------------------------------------------------------------------------
                         G L O B A L  V A R I A B L E S
------------------------------------------------------------------------------*/
static bool is_running = false;
static button_cb_data_t cb_data;

/*------------------------------------------------------------------------------
                     F U N C T I O N  D E F I N I T I O N S
------------------------------------------------------------------------------*/
/*
 * start_monitoring() - Start monitoring
 *
 * The variables being monitored are: USER_BUTTON.
 *
 * Return: 0 on success, 1 otherwise.
 */
int start_monitoring(void)
{
	if (is_monitoring())
		return 0;

	ccapi_dp_error_t dp_error = init_monitor(&cb_data.dp_collection);
	if (dp_error != CCAPI_DP_ERROR_NONE)
		goto error;

	cb_data.button = get_user_button();
	if (cb_data.button == NULL)
		goto error;

	cb_data.value = GPIO_HIGH;
	cb_data.num_samples_upload = 2;

	if (ldx_gpio_start_wait_interrupt(cb_data.button, &button_interrupt_cb, &cb_data) != EXIT_SUCCESS) {
		log_mon_error("Error initializing app monitor: Unable to capture %s interrupts", USER_BUTTON_ALIAS);
		goto error;
	}

	is_running = true;

	return 0;

error:
	ldx_gpio_free(cb_data.button);
	ccapi_dp_destroy_collection(cb_data.dp_collection);

	return 1;
}

/*
 * is_monitoring() - Check monitor status
 *
 * Return: True if demo monitor is running, false otherwise.
 */
bool is_monitoring(void) {
	return is_running;
}

/*
 * stop_monitoring() - Stop monitoring
 */
void stop_monitoring(void)
{
	if (!is_monitoring())
		return;

	if (cb_data.button != NULL)
		ldx_gpio_stop_wait_interrupt(cb_data.button);

	ldx_gpio_free(cb_data.button);
	ccapi_dp_destroy_collection(cb_data.dp_collection);

	is_running = false;

	log_mon_info("%s", "Stop monitoring");
}

/*
 * init_monitor() - Create and initialize the monitor data point collection
 *
 * @dp_collection:	Data point collection.
 *
 * Return: Error code after the initialization of the monitor collection.
 *
 * The return value will always be 'CCAPI_DP_ERROR_NONE' unless there is any
 * problem creating the collection.
 */
static ccapi_dp_error_t init_monitor(ccapi_dp_collection_handle_t *dp_collection)
{
	ccapi_dp_error_t dp_error = ccapi_dp_create_collection(dp_collection);
	if (dp_error != CCAPI_DP_ERROR_NONE) {
		log_mon_error("Error initializing app monitor, %d", dp_error);
		return dp_error;
	}

	dp_error = ccapi_dp_add_data_stream_to_collection_extra(*dp_collection,
			DATA_STREAM_USER_BUTTON, "int32 ts_iso", DATA_STREAM_BUTTON_UNITS, NULL);
	if (dp_error != CCAPI_DP_ERROR_NONE) {
		log_mon_error("Cannot add '%s' stream to data point collection, error %d",
					DATA_STREAM_USER_BUTTON, dp_error);
		return dp_error;
	}

	return CCAPI_DP_ERROR_NONE;
}

/*
 * get_user_button() - Retrieves the user button GPIO
 *
 * Return: The user button GPIO, NULL on error.
 */
static gpio_t *get_user_button(void)
{
	if (cb_data.button != NULL)
		return cb_data.button;
	cb_data.button = ldx_gpio_request_by_alias(USER_BUTTON_ALIAS, GPIO_IRQ_EDGE_BOTH, REQUEST_SHARED);
	if (cb_data.button == NULL)
		return NULL;
	ldx_gpio_set_active_mode(cb_data.button, GPIO_ACTIVE_HIGH);

	return cb_data.button;
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

/*
 * add_button_sample() - Add USER_BUTTON value to the data point collection
 *
 * @arg:	Button interrupt data (button_cb_data_t).
 */
static void add_button_sample(button_cb_data_t *data)
{
	ccapi_dp_error_t dp_error;
	uint32_t count = 0;
	ccapi_timestamp_t *timestamp = get_timestamp();

	data->value = data->value ? GPIO_LOW : GPIO_HIGH;

	dp_error = ccapi_dp_add(data->dp_collection, DATA_STREAM_USER_BUTTON,
			data->value, timestamp);
	free_timestamp(timestamp);
	if (dp_error != CCAPI_DP_ERROR_NONE) {
		log_mon_error("Cannot add user_button value, %d", dp_error);
		return;
	} else {
		log_mon_debug("user_button = %d %s", data->value, DATA_STREAM_BUTTON_UNITS);
	}

	ccapi_dp_get_collection_points_count(data->dp_collection, &count);
	if (count >= data->num_samples_upload) {
		log_mon_debug("Sending %s samples", USER_BUTTON_ALIAS);
		dp_error = ccapi_dp_send_collection(CCAPI_TRANSPORT_TCP, data->dp_collection);
		if (dp_error != CCAPI_DP_ERROR_NONE)
			log_mon_error("Error sending monitor samples, %d", dp_error);
	}
}

/*
 * get_timestamp() - Get the current timestamp of the system
 *
 * Return: The timestamp of the system.
 */
static ccapi_timestamp_t *get_timestamp(void)
{
	ccapi_timestamp_t *timestamp = NULL;
	size_t len = strlen("2016-09-27T07:07:09.546Z") + 1;
	char *date = NULL;
	time_t now;

	timestamp = (ccapi_timestamp_t*) malloc(sizeof (ccapi_timestamp_t));
	if (timestamp == NULL)
		return NULL;

	date = (char*) malloc(sizeof (char) * len);
	if (date == NULL) {
		free(timestamp);
		return NULL;
	}

	time(&now);
	if (strftime(date, len, "%FT%TZ", gmtime(&now)) > 0) {
		timestamp->iso8601 = date;
	} else {
		free(date);
		timestamp->iso8601 = strdup("");
	}

	return timestamp;
}

/*
 * free_timestamp() - Free given timestamp structure
 *
 * @timestamp:	The timestamp structure to release.
 */
static void free_timestamp(ccapi_timestamp_t *timestamp)
{
	if (timestamp == NULL)
		return;

	if (timestamp->iso8601 != NULL) {
		free((char *) timestamp->iso8601);
		timestamp->iso8601 = NULL;
	}
	free(timestamp);
	timestamp = NULL;
}
