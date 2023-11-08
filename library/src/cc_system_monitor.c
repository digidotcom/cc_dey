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

#ifdef ENABLE_BT
#include <libdigiapix/bluetooth.h>
#endif /* ENABLE_BT */
#include <libdigiapix/network.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

#include "ccapi/ccapi.h"
#include "cc_config.h"
#include "cc_init.h"
#include "cc_logging.h"
#include "cc_system_monitor.h"
#include "cc_utils.h"
#include "utils.h"

#define LOOP_MS				100

#define MAX_LENGTH			256

#define MAX_DP_IN_COLLECTION		250

#define SYSTEM_MONITOR_TAG		"SYSMON:"

#ifdef ENABLE_BT
#define BLUETOOTH_INTERFACE		"hci0"
#endif /* ENABLE_BT */

#define METRIC_FREE_MEMORY		"free_memory"
#define METRIC_USED_MEMORY		"used_memory"
#define METRIC_CPU_LOAD			"cpu_load"
#define METRIC_CPU_TEMP			"cpu_temperature"
#define METRIC_FREQ			"frequency"
#define METRIC_UPTIME			"uptime"
#define METRIC_STATE			"state"
#define METRIC_RX_BYTES			"rx_bytes"
#define METRIC_TX_BYTES			"tx_bytes"

#define SYS_MON_DATA_STREAM_PREFIX	"system_monitor/"

#define DATA_STREAM_FREE_MEMORY		SYS_MON_DATA_STREAM_PREFIX METRIC_FREE_MEMORY
#define DATA_STREAM_USED_MEMORY		SYS_MON_DATA_STREAM_PREFIX METRIC_USED_MEMORY
#define DATA_STREAM_CPU_LOAD		SYS_MON_DATA_STREAM_PREFIX METRIC_CPU_LOAD
#define DATA_STREAM_CPU_TEMP		SYS_MON_DATA_STREAM_PREFIX METRIC_CPU_TEMP
#define DATA_STREAM_FREQ		SYS_MON_DATA_STREAM_PREFIX METRIC_FREQ
#define DATA_STREAM_UPTIME		SYS_MON_DATA_STREAM_PREFIX METRIC_UPTIME

#define DATA_STREAM_NET_STATE		SYS_MON_DATA_STREAM_PREFIX "%s/" METRIC_STATE
#define DATA_STREAM_NET_TRAFFIC_RX	SYS_MON_DATA_STREAM_PREFIX "%s/" METRIC_RX_BYTES
#define DATA_STREAM_NET_TRAFFIC_TX	SYS_MON_DATA_STREAM_PREFIX "%s/" METRIC_TX_BYTES

#define DATA_STREAM_MEMORY_UNITS	"kB"
#define DATA_STREAM_CPU_LOAD_UNITS	"%"
#define DATA_STREAM_CPU_TEMP_UNITS	"C"
#define DATA_STREAM_FREQ_UNITS		"kHz"
#define DATA_STREAM_UPTIME_UNITS	"s"
#define DATA_STREAM_STATE_UNITS		"state"
#define DATA_STREAM_BYTES_UNITS		"bytes"

#define FILE_CPU_LOAD			"/proc/stat"
#define FILE_CPU_TEMP			"/sys/class/thermal/thermal_zone0/temp"
#define FILE_CPU_FREQ			"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq"

/**
 * log_sm_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_sm_debug(format, ...)					\
	log_debug("%s " format, SYSTEM_MONITOR_TAG, __VA_ARGS__)

/**
 * log_sm_info() - Log the given message as info
 *
 * @format:		Info message to log.
 * @args:		Additional arguments.
 */
#define log_sm_info(format, ...)					\
	log_info("%s " format, SYSTEM_MONITOR_TAG, __VA_ARGS__)

/**
 * log_sm_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_sm_error(format, ...)					\
	log_error("%s " format, SYSTEM_MONITOR_TAG, __VA_ARGS__)

typedef enum {
	STREAM_FREE_MEM,
	STREAM_USED_MEM,
	STREAM_CPU_LOAD,
	STREAM_CPU_TEMP,
	STREAM_FREQ,
	STREAM_UPTIME,
	STREAM_STATE,
	STREAM_RX_BYTES,
	STREAM_TX_BYTES,
} stream_type_t;

typedef struct {
	char *name;
	char *path;
	const char *units;
	const char *format;
	stream_type_t type;
} stream_t;

typedef struct {
	stream_t *streams;
	int n_streams;
} stream_list_t;

static volatile bool stop_requested = false;
static volatile bool dp_thread_valid = false;
static pthread_t dp_thread;
static ccapi_dp_collection_handle_t dp_collection;
static unsigned long long last_work = 0, last_total = 0;
#ifdef ENABLE_BT
static stream_list_t bt_stream_list;
#endif /* ENABLE_BT */
static stream_list_t net_stream_list;
static stream_list_t sys_stream_list;
static stream_t net_stream_formats[] = {
	{
		.name = METRIC_STATE,
		.path = DATA_STREAM_NET_STATE,
		.units = DATA_STREAM_STATE_UNITS,
		.format = CCAPI_DP_KEY_DATA_INT64 " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_STATE
	},
	{
		.name = METRIC_RX_BYTES,
		.path = DATA_STREAM_NET_TRAFFIC_RX,
		.units = DATA_STREAM_BYTES_UNITS,
		.format = CCAPI_DP_KEY_DATA_INT64 " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_RX_BYTES
	},
	{
		.name = METRIC_TX_BYTES,
		.path = DATA_STREAM_NET_TRAFFIC_TX,
		.units = DATA_STREAM_BYTES_UNITS,
		.format = CCAPI_DP_KEY_DATA_INT64 " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_TX_BYTES
	},
};
static stream_t sys_streams_formats[] = {
	{
		.name = METRIC_FREE_MEMORY,
		.path = DATA_STREAM_FREE_MEMORY,
		.units = DATA_STREAM_MEMORY_UNITS,
		.format = CCAPI_DP_KEY_DATA_DOUBLE " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_FREE_MEM
	},
	{
		.name = METRIC_USED_MEMORY,
		.path = DATA_STREAM_USED_MEMORY,
		.units = DATA_STREAM_MEMORY_UNITS,
		.format = CCAPI_DP_KEY_DATA_DOUBLE " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_USED_MEM
	},
	{
		.name = METRIC_CPU_LOAD,
		.path = DATA_STREAM_CPU_LOAD,
		.units = DATA_STREAM_CPU_LOAD_UNITS,
		.format = CCAPI_DP_KEY_DATA_DOUBLE " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_CPU_LOAD
	},
	{
		.name = METRIC_CPU_TEMP,
		.path = DATA_STREAM_CPU_TEMP,
		.units = DATA_STREAM_CPU_TEMP_UNITS,
		.format = CCAPI_DP_KEY_DATA_DOUBLE " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_CPU_TEMP
	},
	{
		.name = METRIC_FREQ,
		.path = DATA_STREAM_FREQ,
		.units = DATA_STREAM_FREQ_UNITS,
		.format = CCAPI_DP_KEY_DATA_INT32 " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_FREQ
	},
	{
		.name = METRIC_UPTIME,
		.path = DATA_STREAM_UPTIME,
		.units = DATA_STREAM_UPTIME_UNITS,
		.format = CCAPI_DP_KEY_DATA_INT32 " " CCAPI_DP_KEY_TS_EPOCH,
		.type = STREAM_UPTIME
	}
};

/*
 * free_stream_list() - Free the stream list
 *
 * @stream_list:	The list to free.
 */
static void free_stream_list(stream_list_t *stream_list)
{
	int i;

	for (i = 0; i < stream_list->n_streams; i++) {
		free(stream_list->streams[i].name);
		free(stream_list->streams[i].path);
	}

	free(stream_list->streams);

	stream_list->n_streams = 0;
}

/*
 * value_matches_wildcard_pattern() - Determines whether the given value matches
 *                                    the given wildcard pattern.
 *
 * @value:	The string to check.
 * @pattern:	The pattern string.
 *
 * Return: 'true' if the value matches the wildcard pattern, 'false' otherwise.
 */
static bool value_matches_wildcard_pattern(char *value, char *pattern)
{
	int wildcard = 0;
	char *last_pattern_start = 0;
	char *last_value_start = 0;

	do {
		if (*pattern == *value) {
			if (wildcard == 1)
				last_value_start = value + 1;

			value++;
			pattern++;
			wildcard = 0;
		} else if (*pattern == '?') {
			if (*value == '\0') /* the value has ended but a char was expected */
				return false;

			if (wildcard == 1)
				last_value_start = value + 1;

			value++;
			pattern++;
			wildcard = 0;
		} else if (*pattern == '*') {
			if (*(pattern + 1) == '\0')
				return true;

			last_pattern_start = pattern;
			wildcard = 1;

			pattern++;
		} else if (wildcard) {
			if (*value == *pattern) {
				wildcard = 0;
				value++;
				pattern++;
				last_value_start = value + 1 ;
			} else {
				value++;
			}
		} else {
			if (*pattern == '\0' && *value == '\0') {  /* end of mask */
				return true; /* if the value also ends here then the pattern match */
			} else {
				if (last_pattern_start != 0) { /* try to restart the mask on the rest */
					pattern = last_pattern_start;
					value = last_value_start;
					last_value_start = 0;
				} else {
					return false;
				}
			}
		}

	} while (*value);

	return *pattern == '\0';
}

/*
 * should_read_metric() - Determines whether the given metric must be read or not
 *                        based on the given configuration.
 *
 * @metric_name:	The metric name.
 * @cc_cfg:		The Cloud Connector configuration.
 *
 * Return: 'true' if metric should be read, 'false' otherwise.
 */
static bool should_read_metric(char *metric_name, const cc_cfg_t *const cc_cfg)
{
	unsigned int i;

	if (cc_cfg->sys_mon_all_metrics)
		return true;

	for (i = 0; i < cc_cfg->n_sys_mon_metrics; i++) {
		char *metric = cc_cfg->sys_mon_metrics[i];

		/* Sanity check. */
		if (metric == NULL)
			continue;

		/* Check if the metric name matches the metric wildcard. */
		if (value_matches_wildcard_pattern(metric_name, metric))
			return true;

		/* Check if the metric name is composed. */
		if (strchr(metric_name, '/') != NULL) {
			char *interface = NULL;
			ccapi_bool_t matches = false;
			char *metric_name_copy = strdup(metric_name);

			if (metric_name_copy == NULL) {
				log_sm_error("%s", "Not enough memory to check metrics criteria");
				continue;
			}
			/* Extract interface from the metric name. */
			interface = (char *)strtok(metric_name_copy, "/");
			if (interface == NULL) {
				free(metric_name_copy);
				continue;
			}
			/* Check if the interface matches the metric. */
			matches = strcmp(interface, metric) == 0;
			free(metric_name_copy);
			if (matches)
				return true;
		}
	}

	return false;
}

/*
 * should_read_interface() - Determines whether the given interface must be read or not
 *                           based on the given configuration.
 *
 * @iface_name:	The interface name.
 * @cc_cfg:	The Cloud Connector configuration.
 *
 * Return: 'true' if interface should be read, 'false' otherwise.
 */
static bool should_read_interface(char *iface_name, const cc_cfg_t *const cc_cfg)
{
	unsigned int i;

	if (cc_cfg->sys_mon_all_metrics)
		return true;

	for (i = 0; i < cc_cfg->n_sys_mon_metrics; i++) {
		char *metric = cc_cfg->sys_mon_metrics[i];

		/* Sanity check. */
		if (metric == NULL)
			continue;

		/* Check if the interface matches the metric wildcard. */
		if (value_matches_wildcard_pattern(iface_name, metric))
			return true;

		/* Check if the metric is composed. */
		if (strchr(metric, '/') != NULL) {
			char *iface_wildcard = NULL;
			ccapi_bool_t matches = false;
			char *metric_copy = strdup(metric);

			if (metric_copy == NULL) {
				log_sm_error("%s", "Not enough memory to check metrics criteria");
				continue;
			}
			/* Extract interface wildcard from the metric. */
			iface_wildcard = (char *)strtok(metric_copy, "/");
			if (iface_wildcard == NULL) {
				free(metric_copy);
				continue;
			}
			/* Check if the interface name matches the interface wildcard. */
			matches = value_matches_wildcard_pattern(iface_name, iface_wildcard);
			free(metric_copy);
			if (matches)
				return true;
		}
	}

	return false;
}

/*
 * init_sys_streams() - Add the system data point streams to collection
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the parsed
 * 		settings from the configuration file are stored.
 *
 * Return: Error code after the addition to the collection.
 *
 * The return value will always be 'CCAPI_DP_ERROR_NONE' unless there is any
 * problem creating the collection.
 */
static ccapi_dp_error_t init_sys_streams(const cc_cfg_t *const cc_cfg)
{
	unsigned int i;
	int n_metrics_to_monitor = 0;
	ccapi_dp_error_t dp_error = CCAPI_DP_ERROR_NONE;

	/* Calculate the number of metrics to monitor. */
	for (i = 0; i < ARRAY_SIZE(sys_streams_formats); i++) {
		if (should_read_metric(sys_streams_formats[i].name, cc_cfg))
			n_metrics_to_monitor += 1;
	}

	/* Allocate memory for the metric streams. */
	sys_stream_list.streams = calloc(n_metrics_to_monitor, sizeof(stream_t));
	if (sys_stream_list.streams == NULL) {
		log_sm_error("Cannot initialize system metrics: %s", "Out of memory");
		dp_error = CCAPI_DP_ERROR_INSUFFICIENT_MEMORY;
		goto error;
	}

	/* Initialize streams. */
	for (i = 0; i < ARRAY_SIZE(sys_streams_formats); i++) {
		stream_t stream_format = sys_streams_formats[i];
		stream_t *stream = &sys_stream_list.streams[sys_stream_list.n_streams];

		/* Check if the metric should be skipped. */
		if (!should_read_metric(stream_format.name, cc_cfg)) {
			log_sm_debug("Skipping metric '%s'...", stream_format.name);
			continue;
		}

		sys_stream_list.n_streams++;

		stream->name = strdup(stream_format.name);
		stream->path = strdup(stream_format.path);
		stream->format = stream_format.format;
		stream->units = stream_format.units;
		stream->type = stream_format.type;
		if (stream->name == NULL || stream->path == NULL) {
			log_sm_error("Cannot initialize '%s' metric stream: Out of memory", stream_format.name);
			dp_error = CCAPI_DP_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}

		dp_error = ccapi_dp_add_data_stream_to_collection_extra(
					dp_collection, stream->path, stream->format, stream->units, NULL);
		if (dp_error != CCAPI_DP_ERROR_NONE) {
			log_sm_error("Cannot add '%s' stream to data point collection, error %d",
				stream->path, dp_error);
			goto error;
		}
	}

error:
	if (dp_error != CCAPI_DP_ERROR_NONE)
		free_stream_list(&sys_stream_list);

	return dp_error;
}

/*
 * init_iface_streams() - Add to collection the given interface data point streams
 *
 * @iface_name:		Name of the interface to init.
 * @stream_list:	Structure to initialize.
 * @cc_cfg:		Connector configuration struct (cc_cfg_t) where the
 * 			parsed settings from the configuration file are stored.
 *
 * Return: Error code after the addition to the collection.
 *
 * The return value will always be 'CCAPI_DP_ERROR_NONE' unless there is any
 * problem creating the collection.
 */
static ccapi_dp_error_t init_iface_streams(const char *const iface_name, stream_list_t *stream_list, const cc_cfg_t *const cc_cfg)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(net_stream_formats); i++) {
		char *metric_name;
		void *tmp;
		stream_t *stream = NULL;
		size_t path_len = 0;
		stream_t stream_format = net_stream_formats[i];
		ccapi_dp_error_t dp_error;

		/* Build metric name. */
		metric_name = calloc(snprintf(NULL, 0, "%s/%s", iface_name, stream_format.name) + 1, sizeof(*metric_name));
		if (metric_name == NULL) {
			log_sm_error("Cannot initialize interface '%s' metric name '%s': Out of memory", iface_name, net_stream_formats[i].name);
			return CCAPI_DP_ERROR_INSUFFICIENT_MEMORY;
		}
		sprintf(metric_name, "%s/%s", iface_name, stream_format.name);

		/* Check if metric should be measured. */
		if (!should_read_metric(metric_name, cc_cfg)) {
			log_sm_debug("Skipping %s...", metric_name);
			free(metric_name);
			continue;
		}
		free(metric_name);

		/* Allocate memory for the metric stream. */
		if (stream_list->streams == NULL)
			tmp = calloc(1, sizeof(stream_t));
		else
			tmp = realloc(stream_list->streams, (stream_list->n_streams + 1) * sizeof(stream_t));

		if (tmp == NULL) {
			log_sm_error("Cannot initialize interface '%s' metric '%s': Out of memory", iface_name, net_stream_formats[i].name);
			return CCAPI_DP_ERROR_INSUFFICIENT_MEMORY;
		}
		stream_list->streams = tmp;

		stream = &stream_list->streams[stream_list->n_streams];
		path_len = snprintf(NULL, 0, stream_format.path, iface_name);

		stream_list->n_streams++;

		stream->name = strdup(iface_name);
		stream->path = calloc(path_len + 1, sizeof(char));
		if (stream->name == NULL || stream->path == NULL) {
			log_sm_error("Cannot initialize interface '%s' metric '%s': Out of memory", iface_name, net_stream_formats[i].name);
			return CCAPI_DP_ERROR_INSUFFICIENT_MEMORY;
		}

		sprintf(stream->path, stream_format.path, iface_name);

		stream->format = stream_format.format;
		stream->units = stream_format.units;
		stream->type = stream_format.type;

		dp_error = ccapi_dp_add_data_stream_to_collection_extra(
					dp_collection, stream->path, stream->format, stream->units, NULL);
		if (dp_error != CCAPI_DP_ERROR_NONE) {
			log_sm_error("Cannot add '%s' stream to data point collection, error %d",
				stream->path, dp_error);
			return dp_error;
		}
	}

	return CCAPI_DP_ERROR_NONE;
}

/*
 * init_net_streams() - Add the network interfaces data point streams to
 *                      collection
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the parsed
 * 		settings from the configuration file are stored.
 *
 * Return: Error code after the addition to the collection.
 *
 * The return value will always be 'CCAPI_DP_ERROR_NONE' unless there is any
 * problem creating the collection.
 */
static ccapi_dp_error_t init_net_streams(const cc_cfg_t *const cc_cfg)
{
	ccapi_dp_error_t dp_error;
	net_names_list_t list_ifaces;
	int i;

	if (ldx_net_list_available_ifaces(&list_ifaces) <= 0)
		return CCAPI_DP_ERROR_NONE;

	for (i = 0; i < list_ifaces.n_ifaces; i++) {
		/* Check if the interface should be skipped. */
		if (!should_read_interface(list_ifaces.names[i], cc_cfg)) {
			log_sm_debug("Skipping interface '%s'...", list_ifaces.names[i]);
			continue;
		}
		dp_error = init_iface_streams(list_ifaces.names[i], &net_stream_list, cc_cfg);
		if (dp_error != CCAPI_DP_ERROR_NONE)
			goto error;
	}

	dp_error = CCAPI_DP_ERROR_NONE;

error:
	if (dp_error != CCAPI_DP_ERROR_NONE)
		free_stream_list(&net_stream_list);

	return dp_error;
}

#ifdef ENABLE_BT
/*
 * init_bt_streams() - Add Bluetooth interface data point streams to collection
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the parsed
 * 		settings from the configuration file are stored.
 *
 * Return: Error code after the addition to the collection.
 *
 * The return value will always be 'CCAPI_DP_ERROR_NONE' unless there is any
 * problem creating the collection.
 */
static ccapi_dp_error_t init_bt_streams(const cc_cfg_t *const cc_cfg)
{
	ccapi_dp_error_t dp_error;

	/* Check if the interface should be skipped. */
	if (!should_read_interface(BLUETOOTH_INTERFACE, cc_cfg)) {
		log_sm_debug("Skipping interface '%s'...", BLUETOOTH_INTERFACE);
		return CCAPI_DP_ERROR_NONE;
	}

	/* Initialize streams. */
	dp_error = init_iface_streams(BLUETOOTH_INTERFACE, &bt_stream_list, cc_cfg);
	if (dp_error != CCAPI_DP_ERROR_NONE)
		free_stream_list(&bt_stream_list);

	return dp_error;
}
#endif /* ENABLE_BT */

/*
 * init_system_monitor() - Create and initialize the system monitor data point
 *                         collection
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the parsed
 * 		settings from the configuration file are stored.
 *
 * Return: Error code after the initialization of the system monitor collection.
 *
 * The return value will always be 'CCAPI_DP_ERROR_NONE' unless there is any
 * problem creating the collection.
 */
static ccapi_dp_error_t init_system_monitor(const cc_cfg_t *const cc_cfg)
{
	/* Create data point collection. */
	ccapi_dp_error_t dp_error = ccapi_dp_create_collection(&dp_collection);
	if (dp_error != CCAPI_DP_ERROR_NONE) {
		log_sm_error("Error initializing system monitor, %d", dp_error);
		return dp_error;
	}

	/* Initialize system metrics streams. */
	dp_error = init_sys_streams(cc_cfg);
	if (dp_error != CCAPI_DP_ERROR_NONE)
		return dp_error;

	/* Initialize network interfaces metrics streams. */
	dp_error = init_net_streams(cc_cfg);
	if (dp_error != CCAPI_DP_ERROR_NONE) {
		free_stream_list(&sys_stream_list);
		return dp_error;
	}

#ifdef ENABLE_BT
	/* Initialize bluetooth interface metrics streams. */
	dp_error = init_bt_streams(cc_cfg);
	if (dp_error != CCAPI_DP_ERROR_NONE) {
		free_stream_list(&sys_stream_list);
		free_stream_list(&net_stream_list);
		return dp_error;
	}
#endif /* ENABLE_BT */

	return dp_error;
}

/*
 * get_free_memory() - Get the free memory of the system
 *
 * Return: The free memory of the system in kB, -1 if error.
 */
static double get_free_memory(void)
{
	struct sysinfo info;

	if (sysinfo(&info) != 0) {
		log_sm_error("%s", "Error getting free memory");
		return -1;
	}

	return info.freeram / 1024;
}

/*
 * get_used_memory() - Get the used memory of the system
 *
 * Return: The used memory of the system in kB, -1 if error.
 */
static double get_used_memory(void)
{
	struct sysinfo info;

	if (sysinfo(&info) != 0) {
		log_sm_error("%s", "Error getting used memory");
		return -1;
	}

	return (info.totalram - info.freeram) / 1024;
}

/*
 * get_cpu_load() - Get the CPU load of the system
 *
 * Return: The CPU load in %, -1 if the value is not available.
 */
static double get_cpu_load(void) {
	char file_data[MAX_LENGTH] = {0};
	long file_size;
	unsigned long long int fields[10];
	unsigned long long work = 0, total = 0;
	double usage = -1;
	int i, result;

	file_size = read_file(FILE_CPU_LOAD, file_data, MAX_LENGTH);
	if (file_size <= 0) {
		log_sm_error("%s", "Error getting CPU load");
		return -1;
	}

	result = sscanf(file_data, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			&fields[0], &fields[1], &fields[2], &fields[3], &fields[4],
			&fields[5], &fields[6], &fields[7], &fields[8], &fields[9]);

	if (result < 4) {
		log_sm_error("%s", "Error getting CPU load");
		return -1;
	}

	for (i = 0; i < 3; i++)
		work += fields[i];
	for (i = 0; i < result; i++)
		total += fields[i];

	if (last_work == 0 && last_total == 0) {
		/* The first time report 0%. */
		usage = 0;
	} else {
		unsigned long long diff_work = work - last_work;
		unsigned long long diff_total = total - last_total;

		usage = diff_work * 100.0 / diff_total;
	}

	last_total = total;
	last_work = work;

	return usage;
}

/*
 * get_cpu_temp() - Get the CPU temperature of the system
 *
 * Return: The CPU temperature in C.
 */
static double get_cpu_temp(void)
{
	char file_data[MAX_LENGTH] = {0};
	long file_size;
	double temperature;
	int result;

	file_size = read_file(FILE_CPU_TEMP, file_data, MAX_LENGTH);
	if (file_size <= 0) {
		log_sm_error("%s", "Error getting CPU temperature");
		return -1;
	}

	result = sscanf(file_data, "%lf", &temperature);
	if (result < 1) {
		log_sm_error("%s", "Error getting CPU temperature");
		return -1;
	}

	return temperature / 1000;
}

/*
 * get_cpu_freq() - Get the CPU frequency
 *
 * Return: The CPU frequency in kHz, -1 if error.
 */
static unsigned long get_cpu_freq(void)
{
	char data[MAX_LENGTH] = {0};
	long file_size;
	long freq;

	freq = -1;

	file_size = read_file(FILE_CPU_FREQ, data, MAX_LENGTH);
	if (file_size <= 0) {
		log_sm_error("%s", "Error getting CPU frequency");
		return -1;
	}

	if (sscanf(data, "%ld", &freq) < 1) {
		log_sm_error("%s", "Error getting CPU frequency");
		return -1;
	}

	return freq;
}

/*
 * get_uptime() - Get number of seconds since boot
 *
 * Return: Number of seconds since boot.
 */
static unsigned long get_uptime(void)
{
	struct sysinfo info;

	if (sysinfo(&info) != 0) {
		log_sm_error("%s", "Error getting uptime");
		return -1;
	}

	return info.uptime;
}

/*
 * add_sys_samples() - Add system metrics values to the data point collection
 *
 * @timestamp: The timestamp for the samples.
 */
static void add_sys_samples(ccapi_timestamp_t timestamp)
{
	int i;
	double free_mem, used_mem, load, temp;
	unsigned long freq, uptime;
	ccapi_dp_error_t dp_error;

	for (i = 0; i < sys_stream_list.n_streams; i++) {
		stream_t stream = sys_stream_list.streams[i];

		switch(stream.type) {
			case STREAM_FREE_MEM:
				free_mem = get_free_memory();
				dp_error = ccapi_dp_add(dp_collection, stream.path, free_mem, &timestamp);
				log_sm_debug("%s = %f %s", stream.name, free_mem, stream.units);
				break;
			case STREAM_USED_MEM:
				used_mem = get_used_memory();
				dp_error = ccapi_dp_add(dp_collection, stream.path, used_mem, &timestamp);
				log_sm_debug("%s = %f %s", stream.name, used_mem, stream.units);
				break;
			case STREAM_CPU_LOAD:
				load = get_cpu_load();
				dp_error = ccapi_dp_add(dp_collection, stream.path, load, &timestamp);
				log_sm_debug("%s = %f %s", stream.name, load, stream.units);
				break;
			case STREAM_CPU_TEMP:
				temp =  get_cpu_temp();
				dp_error = ccapi_dp_add(dp_collection, stream.path, temp, &timestamp);
				log_sm_debug("%s = %f %s", stream.name, temp, stream.units);
				break;
			case STREAM_FREQ:
				freq = get_cpu_freq();
				dp_error = ccapi_dp_add(dp_collection, stream.path, freq, &timestamp);
				log_sm_debug("%s = %lu %s", stream.name, freq, stream.units);
				break;
			case STREAM_UPTIME:
				uptime = get_uptime();
				dp_error = ccapi_dp_add(dp_collection, stream.path, uptime, &timestamp);
				log_sm_debug("%s = %lu %s", stream.name, uptime, stream.units);
				break;
			default:
				/* Should not occur */
				log_sm_error("Cannot add %s value, unknown stream (%d)", stream.name, stream.type);
				continue;
		}

		if (dp_error != CCAPI_DP_ERROR_NONE)
			log_sm_error("Cannot add %s value, %d", stream.name, dp_error);
	}
}

/*
 * add_net_samples() - Add network interfaces RX and TX bytes values to the
 *                     data point collection
 *
 * @timestamp: The timestamp for the samples.
 */
static void add_net_samples(ccapi_timestamp_t timestamp)
{
	net_state_t net_state;
	net_stats_t stats;
	char *iface_name = NULL;
	int i;

	for (i = 0; i < net_stream_list.n_streams; i++) {
		char desc[50] = {0};
		unsigned long long value = 0;
		ccapi_dp_error_t dp_error;
		stream_t stream = net_stream_list.streams[i];

		if (iface_name == NULL || strcmp(iface_name, stream.name) != 0) {
			iface_name = stream.name;
			ldx_net_get_iface_stats(iface_name, &stats);
			ldx_net_get_iface_state(iface_name, &net_state);
		}

		switch(stream.type) {
			case STREAM_STATE:
				value = net_state.status == NET_STATUS_CONNECTED;
				strcpy(desc, " status");
				break;
			case STREAM_RX_BYTES:
				value = stats.rx_bytes;
				strcpy(desc, " RX bytes");
				break;
			case STREAM_TX_BYTES:
				value = stats.tx_bytes;
				strcpy(desc, " TX bytes");
				break;
			default:
				/* Should not occur */
				strcpy(desc, "");
				break;
		}

		dp_error = ccapi_dp_add(dp_collection, stream.path, value, &timestamp);

		if (dp_error != CCAPI_DP_ERROR_NONE)
			log_sm_error("Cannot add %s%s value, %d", stream.name, desc, dp_error);
		else
			log_sm_debug("%s%s = %llu %s", stream.name, desc, value, stream.units);
	}
}

#ifdef ENABLE_BT
/*
 * add_bt_samples() - Add Bluetooth interface RX and TX bytes values to the
 *                    data point collection
 *
 * @timestamp: The timestamp for the samples.
 */
static void add_bt_samples(ccapi_timestamp_t timestamp)
{
	bt_state_t bt_state;
	bt_stats_t bt_stats;
	char *iface_name = NULL;
	int i;

	for (i = 0; i < bt_stream_list.n_streams; i++) {
		char desc[50] = {0};
		unsigned long long value = 0;
		ccapi_dp_error_t dp_error;
		stream_t stream = bt_stream_list.streams[i];

		if (iface_name == NULL || strcmp(iface_name, stream.name) != 0) {
			int dev_id = atoi(stream.name + 3);

			iface_name = stream.name;
			ldx_bt_get_state(dev_id, &bt_state);
			ldx_bt_get_stats(dev_id, &bt_stats);
		}

		switch(stream.type) {
			case STREAM_STATE:
				value = bt_state.enable == BT_ENABLED;
				strcpy(desc, " status");
				break;
			case STREAM_RX_BYTES:
				value = bt_stats.rx_bytes;
				strcpy(desc, " RX bytes");
				break;
			case STREAM_TX_BYTES:
				value = bt_stats.tx_bytes;
				strcpy(desc, " TX bytes");
				break;
			default:
				/* Should not occur */
				strcpy(desc, "");
				break;
		}

		dp_error = ccapi_dp_add(dp_collection, stream.path, value, &timestamp);

		if (dp_error != CCAPI_DP_ERROR_NONE)
			log_sm_error("Cannot add %s%s value, %d", stream.name, desc, dp_error);
		else
			log_sm_debug("%s%s = %llu %s", stream.name, desc, value, stream.units);
	}
}
#endif /* ENABLE_BT */

/*
 * add_samples() - Add samples to the data point collection
 */
static void add_samples(void)
{
	ccapi_timestamp_t *timestamp = get_timestamp();

	if (!timestamp) {
		log_sm_error("%s", "Cannot get samples timestamp");
		return;
	}

	add_sys_samples(*timestamp);

	add_net_samples(*timestamp);

#ifdef ENABLE_BT
	add_bt_samples(*timestamp);
#endif /* ENABLE_BT */

	free_timestamp(timestamp);
}

/*
 * system_monitor_loop() - Start the system monitoring loop
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the parsed
 * 		settings from the configuration file are stored.
 *
 * This loop reads the values of the parameters to monitor every
 * 'cc_cfg->sys_mon_sample_rate' seconds and send them to Remote Manager when
 * the number of samples per parameter is at least
 * 'cc_cfg->sys_mon_num_samples_upload'.
 *
 * The monitored values are defined in 'cc_cfg->sys_mon_metrics'.
 */
static void system_monitor_loop(const cc_cfg_t *const cc_cfg)
{
	log_sm_info("%s", "Start monitoring the system");

	while (!stop_requested) {
		uint32_t n_samples_to_send = (sys_stream_list.n_streams + net_stream_list.n_streams) * cc_cfg->sys_mon_num_samples_upload;
#ifdef ENABLE_BT
		n_samples_to_send += bt_stream_list.n_streams * cc_cfg->sys_mon_num_samples_upload;
#endif /* ENABLE_BT */
		long n_loops = cc_cfg->sys_mon_sample_rate * 1000 / LOOP_MS;
		uint32_t count = 0;
		long loop;

		add_samples();

		ccapi_dp_get_collection_points_count(dp_collection, &count);
		while (count > MAX_DP_IN_COLLECTION) {
			log_sm_debug("%s", "Removing old data points...");
			ccapi_dp_remove_older_data_point_from_streams(dp_collection);
			ccapi_dp_get_collection_points_count(dp_collection, &count);
		}

		if (count >= n_samples_to_send && !stop_requested) {
			ccapi_dp_error_t dp_error;

			/*
			 * TODO: If the connection is lost, this thread blocks at this point
			 * and does not continue collecting data points.
			 *
			 * The expected behavior is an error after a timeout to keep the
			 * sampling process, so all the collected data is sent when the
			 * connection is restored.
			 * We tried to get this by using 'ccapi_dp_send_collection_with_reply'
			 * but it seems it does not work:
			 *
			 * unsigned long timeout = 2; // seconds
			 * dp_error = ccapi_dp_send_collection_with_reply(CCAPI_TRANSPORT_TCP, dp_collection, timeout, NULL);
			 */
			if (get_cloud_connection_status() == CC_STATUS_CONNECTED) {
				log_sm_debug("%s", "Sending system monitor samples");
				dp_error = ccapi_dp_send_collection(CCAPI_TRANSPORT_TCP, dp_collection);
				if (dp_error != CCAPI_DP_ERROR_NONE)
					log_sm_error("Error sending system monitor samples, %d", dp_error);
			}
		}

		for (loop = 0; loop < n_loops; loop++) {
			struct timespec sleepValue = {0};

			if (stop_requested)
				break;

			sleepValue.tv_nsec = LOOP_MS * 1000 * 1000;
			nanosleep(&sleepValue, NULL);
		}
	}
}

/*
 * system_monitor_threaded() - Execute the system monitoring in a new thread
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the parsed
 * 		settings from the configuration file are stored.
 */
static void *system_monitor_threaded(void *cc_cfg)
{
	ccapi_dp_error_t dp_error = init_system_monitor(cc_cfg);
	if (dp_error != CCAPI_DP_ERROR_NONE)
		/* The data point collection could not be created. */
		return NULL;

	system_monitor_loop(cc_cfg);

	pthread_exit(NULL);

	return NULL;
}

cc_sys_mon_error_t start_system_monitor(const cc_cfg_t *const cc_cfg)
{
	pthread_attr_t attr;
	int error;

	/* Do not continue if system monitor feature and store backlog feature are disabled */
	if ((!(cc_cfg->services & SYS_MONITOR_SERVICE) || cc_cfg->sys_mon_sample_rate <= 0)
		&& (cc_cfg->data_backlog_kb == 0 || !cc_cfg->data_backlog_path || strlen(cc_cfg->data_backlog_path) == 0)) {
		return CC_SYS_MON_ERROR_NONE;
	}

	if (dp_thread_valid)
		return CC_SYS_MON_ERROR_NONE;

	error = pthread_attr_init(&attr);
	if (error != 0) {
		/* On Linux this function always succeeds. */
		log_sm_error("pthread_attr_init() error %d", error);
	}
	stop_requested = false;
	dp_thread_valid = (pthread_create(&dp_thread, &attr, system_monitor_threaded, (void *) cc_cfg) == 0);
	pthread_attr_destroy(&attr);
	if (!dp_thread_valid) {
		log_sm_error("Error while starting the system monitor, %d", error);
		return CC_SYS_MON_ERROR_THREAD;
	}

	return CC_SYS_MON_ERROR_NONE;
}

bool is_system_monitor_running(void) {
	return dp_thread_valid;
}

void stop_system_monitor(void)
{
	stop_requested = true;

	if (dp_thread_valid) {
		dp_thread_valid = false;
		pthread_cancel(dp_thread);
		pthread_join(dp_thread, NULL);
	}

	free_stream_list(&sys_stream_list);
	free_stream_list(&net_stream_list);
#ifdef ENABLE_BT
	free_stream_list(&bt_stream_list);
#endif /* ENABLE_BT */
	ccapi_dp_destroy_collection(dp_collection);

	log_sm_info("%s", "Stop monitoring the system");
}
