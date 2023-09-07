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
#include <errno.h>
#include <json_object_iterator.h>
#include <json_object.h>
#include <json_tokener.h>
#include <libdigiapix/bluetooth.h>
#include <libdigiapix/gpio.h>
#include <libdigiapix/process.h>
#include <libdigiapix/network.h>
#include <libdigiapix/wifi.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

#include "data_request.h"

#define TARGET_DEVICE_INFO		"device_info"
#define TARGET_GET_CONFIG		"get_config"
#define TARGET_GET_TIME			"get_time"
#define TARGET_PLAY_MUSIC		"play_music"
#define TARGET_SET_VOLUME		"set_audio_volume"
#define TARGET_SET_CONFIG		"set_config"
#define TARGET_USER_LED			"user_led"

#define RESPONSE_ERROR			"ERROR"
#define RESPONSE_OK			"OK"
#define STRING_NA			"N/A"

#define USER_LED_ALIAS			"USER_LED"

#define DREQ_TAG			"DEMO-REQ:"

#define MAX_RESPONSE_SIZE		512
#define PARAM_LENGTH			25

#define BUILD_FILE			"/etc/build"
#define EMMC_SIZE_FILE			"/sys/class/mmc_host/mmc0/mmc0:0001/block/mmcblk0/size"
#define NAND_SIZE_FILE			"/proc/mtd"
#define RESOLUTION_FILE			"/sys/class/graphics/fb0/modes"
#define RESOLUTION_FILE_CCMP		"/sys/class/drm/card0/card0-DPI-1/modes"
#define RESOLUTION_FILE_CCMP_HDMI	"/sys/class/drm/card0/card0-HDMI-A-1/modes"

#define CMD_PLAY_MUSIC			"setsid mpg123 %s"
#define CMD_STOP_MUSIC			"pkill -KILL -f mpg123"
#define CMD_SET_VOLUME			"amixer set 'Speaker' %d%% && amixer set 'Headphone' %d%%"

#define CFG_ELEMENT_ETHERNET		"ethernet"
#define CFG_ELEMENT_WIFI		"wifi"
#define CFG_ELEMENT_BLUETOOTH		"bluetooth"

#define CFG_FIELD_DESC			"desc"
#define CFG_FIELD_DNS1			"dns1"
#define CFG_FIELD_DNS2			"dns2"
#define CFG_FIELD_ENABLE		"enable"
#define CFG_FIELD_GATEWAY		"gateway"
#define CFG_FIELD_IP			"ip"
#define CFG_FIELD_MAC			"mac"
#define CFG_FIELD_MUSIC_FILE		"music_file"
#define CFG_FIELD_NAME			"name"
#define CFG_FIELD_NETMASK		"netmask"
#define CFG_FIELD_N_SAMPLE_UPLOAD	"n_dp_upload"
#define CFG_FIELD_PLAY			"play"
#define CFG_FIELD_PSK			"psk"
#define CFG_FIELD_SAMPLE_RATE		"sample_rate"
#define CFG_FIELD_SEC_MODE		"sec_mode"
#define CFG_FIELD_SSID			"ssid"
#define CFG_FIELD_STATUS		"status"
#define CFG_FIELD_TYPE			"type"

#define IPV4_GROUPS			4
#define MAC_GROUPS			6

#define IP_STR_LENGTH 			(4 * IPV4_GROUPS)
#define IP_FORMAT			"%d.%d.%d.%d"
#define MAC_STR_LENGTH			(3 * MAC_GROUPS)
#define MAC_FORMAT			"%02x:%02x:%02x:%02x:%02x:%02x"

#if !(defined UNUSED_ARGUMENT)
#define UNUSED_ARGUMENT(a)	(void)(a)
#endif

#if !(defined ARRAY_SIZE)
#define ARRAY_SIZE(array)	(sizeof(array) / sizeof(array[0]))
#endif

/*
 * log_dr_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_dr_debug(format, ...)				\
	log_debug("%s " format, DREQ_TAG, __VA_ARGS__)

/**
 * log_dr_warning() - Log the given message as warning
 *
 * @format:		Warning message to log.
 * @args:		Additional arguments.
 */
#define log_dr_warning(format, ...)				\
	log_warning("%s " format, DREQ_TAG, __VA_ARGS__)

/*
 * log_dr_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_dr_error(format, ...)				\
	log_error("%s " format, DREQ_TAG, __VA_ARGS__)

typedef struct {
	bool enable;
	uint32_t sample_rate;
	uint32_t n_samples_upload;
} sys_mon_cfg_t;

struct handler_t {
	const char *target;
	cccs_request_data_cb_t data_cb;
	cccs_request_status_cb_t status_cb;
};

static void request_status_cb(char const *const target,
		cccs_buffer_info_t *const resp_buffer,
		int rcv_error, const char *const rcv_error_hint);
static cccs_receive_error_t device_info_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer);
static cccs_receive_error_t get_config_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer);
static cccs_receive_error_t set_config_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer);
static cccs_receive_error_t get_time_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer);
static cccs_receive_error_t update_user_led_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer);
static cccs_receive_error_t play_music_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer);
static cccs_receive_error_t set_volume_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer);

static struct handler_t request_handlers[] = {
	{
		TARGET_DEVICE_INFO,
		device_info_cb,
		request_status_cb
	},
	{
		TARGET_GET_CONFIG,
		get_config_cb,
		request_status_cb
	},
	{
		TARGET_SET_CONFIG,
		set_config_cb,
		request_status_cb
	},
	{
		TARGET_GET_TIME,
		get_time_cb,
		request_status_cb
	},
	{
		TARGET_USER_LED,
		update_user_led_cb,
		request_status_cb
	},
	{
		TARGET_PLAY_MUSIC,
		play_music_cb,
		request_status_cb
	},
	{
		TARGET_SET_VOLUME,
		set_volume_cb,
		request_status_cb
	}
};

/**
 * read_file() - Read the given file and returns its contents
 *
 * @path:	Absolute path of the file to read.
 * @buffer:	Buffer to store the contents of the file.
 * @file_size:	The number of bytes to read.
 *
 * Return: The number of read bytes.
 */
static long read_file(const char *path, char *buffer, long file_size)
{
	FILE *fd = NULL;
	long read_size = -1;

	if ((fd = fopen(path, "rb")) == NULL) {
		log_dr_debug("%s: fopen error: %s", __func__, path);
		return -1;
	}

	read_size = fread(buffer, sizeof(char), file_size, fd);
	if (ferror(fd)) {
		log_dr_debug("%s: fread error: %s", __func__, path);
		goto done;
	}

	buffer[read_size - 1] = '\0';

done:
	fclose(fd);

	return read_size;
}

/**
 * read_file_line() - Read the first line of the file and return its contents
 *
 * @path:		Absolute path of the file to read.
 * @buffer:		Buffer to store the contents of the file.
 * @bytes_to_read:	The number of bytes to read.
 *
 * Return: 0 on success, -1 on error.
 */
static int read_file_line(const char * const path, char *buffer, int bytes_to_read)
{
	FILE *fd = NULL;
	int error = 0;

	if (access(path, F_OK) != 0) {
		log_dr_error("%s: file is not readable: %s", __func__, path);
		return -1;
	}
	if ((fd = fopen(path, "rb")) == NULL) {
		log_dr_error("%s: fopen error: %s", __func__, path);
		return -1;
	}
	if (fgets(buffer, bytes_to_read, fd) == NULL) {
		log_dr_error("%s: fgets error: %s", __func__, path);
		error = -1;
	}
	fclose(fd);

	return error;
}

/**
 * read_dey_version() - Read the DEY version
 *
 * @version:	Buffer to store the DEY version.
 *
 * Return: 0 if success, 1 otherwise.
 */
static int read_dey_version(char *version)
{
	FILE *in = NULL;
	char line[128] = {0};

	if (access(BUILD_FILE, R_OK) != 0)
		goto error;

	in = fopen(BUILD_FILE, "rb");
	if (in == NULL)
		goto error;

	while (fgets(line, sizeof(line), in) != NULL) {
		if (strncmp(line, "DISTRO_VERSION", strlen("DISTRO_VERSION")) == 0) {
			sscanf(line, "%*s %*s %s", version);
			break;
		}
	}
	fclose(in);

	return 0;
error:
	log_dr_error("Error getting DEY version: File '%s' does not exist or not readable", BUILD_FILE);

	return 1;
}

/**
 * get_emmc_size() - Returns the total eMMC storage size
 *
 * Return: total size read.
 */
static long get_emmc_size(void)
{
	char data[MAX_RESPONSE_SIZE] = {0};
	long total_size = 0;

	if (read_file(EMMC_SIZE_FILE, data, MAX_RESPONSE_SIZE) <= 0)
		log_dr_error("Error getting storage size: %s", "Could not read file");
	if (sscanf(data, "%ld", &total_size) < 1)
		log_dr_error("Error getting storage size: %s", "Invalid file contents");

	return total_size * 512 / 1024; /* kB */
}

/**
 * get_nand_size() - Returns the total NAND storage size
 *
 * Return: total size read.
 */
static long get_nand_size(void)
{
	char buffer[MAX_RESPONSE_SIZE] = {0};
	long total_size = 0;
	FILE *fd;

	fd = fopen(NAND_SIZE_FILE, "r");
	if (!fd) {
		log_dr_error("Error getting storage size: %s", "Could not open file");
		return total_size;
	}
	/* Ignore first line */
	if (fgets(buffer, sizeof(buffer), fd) == NULL) {
		log_dr_error("Error getting storage size: %s", "Could not read file");
		fclose(fd);
		return total_size;
	}
	/* Start reading line by line */
	while (fgets(buffer, sizeof(buffer), fd)) {
		char partition_id[20] = {'\0'};
		char partition_name[20] = {'\0'};
		char size_hex[20] = {'\0'};
		char erase_size_hex[20] = {'\0'};
		unsigned long size;

		sscanf(buffer,
			"%s %s %s %s",
			partition_id,
			size_hex,
			erase_size_hex,
			partition_name);

		size = strtol(size_hex, NULL, 16);
		total_size = total_size + size;
	}
	if (ferror(fd))
		log_dr_error("Error getting storage size: %s", "File read error");
	fclose(fd);

	return total_size / 1024; /* kB */
}

/*
 * add_json_element() - Creates and adds a new JSON element with the provided name
 *
 * @name:	Name of the new JSON object.
 * @root:	JSON object to add the created object.
 *
 * Return: The created JSON object.
 */
static json_object *add_json_element(const char *name, json_object **root)
{
	json_object *item = json_object_new_object();

	if (!item || json_object_object_add(*root, name, item) < 0) {
		if (item)
			json_object_put(item);
		return NULL;
	}

	return item;
}

/*
 * add_bt_json() - Adds Bluetooth details to the provided JSON
 *
 * @root:	JSON object to add Bluetooth details.
 * @complete:	True to include enable and name.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t add_bt_json(json_object **root, bool complete)
{
	bt_state_t bt_state;
	char mac[MAC_STR_LENGTH];

	ldx_bt_get_state(0, &bt_state);

	snprintf(mac, sizeof(mac), MAC_FORMAT, bt_state.mac[0], bt_state.mac[1],
		bt_state.mac[2], bt_state.mac[3], bt_state.mac[4], bt_state.mac[5]);

	if (json_object_object_add(*root, "bt-mac", json_object_new_string(mac)) < 0)
		return CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;

	if (complete) {
		if (json_object_object_add(*root, CFG_FIELD_ENABLE, json_object_new_boolean(bt_state.enable)) < 0)
			return CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;

		if (json_object_object_add(*root, CFG_FIELD_NAME, json_object_new_string(bt_state.name)) < 0)
			return CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	}

	return CCCS_RECEIVE_ERROR_NONE;
}

/*
 * add_net_state_json() - Adds network details to the provided JSON
 *
 * @i_state:	Network interface state to add.
 * @iface_item:	JSON object to add network details.
 * @complete:	True to include enable and name.
 *
 * Return: 0 if success, 1 otherwise.
 */
static int add_net_state_json(net_state_t i_state, json_object **iface_item, bool complete)
{
	char mac[MAC_STR_LENGTH], ip[IP_STR_LENGTH];

	snprintf(mac, sizeof(mac), MAC_FORMAT, i_state.mac[0], i_state.mac[1],
		i_state.mac[2], i_state.mac[3], i_state.mac[4], i_state.mac[5]);
	snprintf(ip, sizeof(ip), IP_FORMAT,
		i_state.ipv4[0], i_state.ipv4[1], i_state.ipv4[2], i_state.ipv4[3]);

	if (json_object_object_add(*iface_item, CFG_FIELD_MAC, json_object_new_string(mac)) < 0)
		return 1;

	if (json_object_object_add(*iface_item, CFG_FIELD_IP, json_object_new_string(ip)) < 0)
		return 1;

	if (complete) {
		if (json_object_object_add(*iface_item, CFG_FIELD_ENABLE, json_object_new_boolean(i_state.status == NET_STATUS_CONNECTED)) < 0)
			return 1;

		if (json_object_object_add(*iface_item, CFG_FIELD_TYPE, json_object_new_int(i_state.is_dhcp)) < 0)
			return 1;

		snprintf(ip, sizeof(ip), IP_FORMAT,
			i_state.netmask[0], i_state.netmask[1], i_state.netmask[2], i_state.netmask[3]);
		if (json_object_object_add(*iface_item, CFG_FIELD_NETMASK, json_object_new_string(ip)) < 0)
			return 1;

		snprintf(ip, sizeof(ip), IP_FORMAT,
			i_state.gateway[0], i_state.gateway[1], i_state.gateway[2], i_state.gateway[3]);
		if (json_object_object_add(*iface_item, CFG_FIELD_GATEWAY, json_object_new_string(ip)) < 0)
			return 1;

		snprintf(ip, sizeof(ip), IP_FORMAT,
			i_state.dns1[0], i_state.dns1[1], i_state.dns1[2], i_state.dns1[3]);
		if (json_object_object_add(*iface_item, CFG_FIELD_DNS1, json_object_new_string(ip)) < 0)
			return 1;

		snprintf(ip, sizeof(ip), IP_FORMAT,
			i_state.dns2[0], i_state.dns2[1], i_state.dns2[2], i_state.dns2[3]);
		if (json_object_object_add(*iface_item, CFG_FIELD_DNS2, json_object_new_string(ip)) < 0)
			return 1;
	}

	return 0;
}

/*
 * get_net_iface_json() - Returns a JSON object with the info of the network interface
 *
 * @name:	Network interface name.
 * @complete:	True to include status, type, gateway, netmask, dns1, and dns2.
 *
 * Return: The json object.
 */
static json_object *get_net_iface_json(const char *iface_name, bool complete)
{
	net_state_t i_state;
	json_object *iface_item = NULL;

	iface_item = json_object_new_object();
	if (!iface_item)
		return NULL;

	if (ldx_net_get_iface_state(iface_name, &i_state) != NET_STATE_ERROR_NONE)
		log_dr_warning("Error getting '%s' interface info", iface_name);

	if (add_net_state_json(i_state, &iface_item, complete) != 0) {
		json_object_put(iface_item);
		return NULL;
	}

	return iface_item;
}

/*
 * add_net_ifaces_json() - Adds network interfaces details to the provided JSON
 *
 * @root:	JSON object to add network interfaces details.
 * @complete:	True to include status, type, gateway, netmask, dns1, and dns2.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t add_net_ifaces_json(json_object **root, bool complete)
{
	cccs_receive_error_t ret = CCCS_RECEIVE_ERROR_NONE;
	net_names_list_t list_ifaces;
	int i;

	if (ldx_net_list_available_ifaces(&list_ifaces) < 0) {
		log_dr_error("%s", "Unable to get list of network interfaces");
		if (complete) {
			net_state_error_t err = NET_STATE_ERROR_NO_IFACES;
			if (json_object_object_add(*root, CFG_FIELD_STATUS, json_object_new_int(err)) < 0
				|| json_object_object_add(*root, CFG_FIELD_DESC, json_object_new_string(ldx_net_code_to_str(err))) < 0)
				ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}

		return ret;
	}

	for (i = 0; i < list_ifaces.n_ifaces; i++) {
		if (ldx_wifi_iface_exists(list_ifaces.names[i]))
			continue;

		json_object *i_item = get_net_iface_json(list_ifaces.names[i], complete);

		if (!i_item || json_object_object_add(*root, list_ifaces.names[i], i_item) < 0) {
			if (i_item)
				json_object_put(i_item);
			ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			break;
		}
	}

	return ret;
}

/*
 * get_wifi_iface_json() - Returns a JSON object with the info of the WiFi interface
 *
 * @name:	Network interface name.
 * @complete:	True to include status, type, ssid, security mode, gateway, netmask, dns1, and dns2.
 *
 * Return: The json object.
 */
static json_object *get_wifi_iface_json(const char *iface_name, bool complete)
{
	wifi_state_t i_state;
	json_object *iface_item = NULL;

	iface_item = json_object_new_object();
	if (!iface_item)
		return NULL;

	if (ldx_wifi_get_iface_state(iface_name, &i_state) != WIFI_STATE_ERROR_NONE)
		log_dr_warning("Error getting '%s' interface info", iface_name);

	if (add_net_state_json(i_state.net_state, &iface_item, complete) != 0)
		goto error;

	if (complete) {
		if (json_object_object_add(iface_item, CFG_FIELD_SSID, json_object_new_string(i_state.ssid)) < 0)
			goto error;

		if (json_object_object_add(iface_item, CFG_FIELD_SEC_MODE, json_object_new_int(i_state.sec_mode)) < 0)
			goto error;
	}

	return iface_item;

error:
	json_object_put(iface_item);

	return NULL;
}

/*
 * add_wifi_ifaces_json() - Adds WiFi interfaces details to the provided JSON
 *
 * @root:	JSON object to add WiFi interfaces details.
 * @complete:	True to include status, type, ssid, security mode, gateway, netmask, dns1, and dns2.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t add_wifi_ifaces_json(json_object **root, bool complete)
{
	cccs_receive_error_t ret = CCCS_RECEIVE_ERROR_NONE;
	net_names_list_t list_ifaces;
	int i;

	if (ldx_wifi_list_available_ifaces(&list_ifaces) < 0) {
		log_dr_error("%s", "Unable to get list of Wi-Fi interfaces");
		if (complete) {
			wifi_state_error_t err = WIFI_STATE_ERROR_NO_IFACES;
			if (json_object_object_add(*root, CFG_FIELD_STATUS, json_object_new_int(err)) < 0
				|| json_object_object_add(*root, CFG_FIELD_DESC, json_object_new_string(ldx_wifi_code_to_str(err))) < 0)
				ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		}

		return ret;
	}

	for (i = 0; i < list_ifaces.n_ifaces; i++) {
		json_object *i_item = get_wifi_iface_json(list_ifaces.names[i], complete);

		if (!i_item || json_object_object_add(*root, list_ifaces.names[i], i_item) < 0) {
			if (i_item)
				json_object_put(i_item);
			ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			break;
		}
	}

	return ret;
}

/*
 * device_info_cb() - Data callback for 'device_info' data requests
 *
 * @target:		Target ID of the data request (device_info).
 * @req_buffer:		Buffer containing the data request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t device_info_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer)
{
	json_object *root = NULL;
	cccs_receive_error_t status = CCCS_RECEIVE_ERROR_NONE;

	UNUSED_ARGUMENT(req_buffer);

	log_dr_debug("%s: target='%s'", __func__, target);

	/*
		target "device_info"

		Request: -

		Response:
		{
			"dey_version": "DEY-4.0-r1-20230224201833"
			"kernel_version": "Linux ccimx8mm-dvk 5.15.71+g002ce509df39 #1 SMP PREEMPT Fri Feb 24 20:18:33 UTC 2023 aarch64 aarch64 aarch64 GNU/Linux"
			"uboot_version": "U-Boot dub-2021.10-r2.1-git-00061-gb49ead8bf02 (Feb 17 2023 - 12:17:49 +0000)""
			"serial_number": "000000",
			"device_type": "ccimx8mm-dvk",
			"module_variant": "0x03",
			"board_variant": "0",
			"board_id": "0",
			"mca_hw_version": "1",
			"mca_fw_version": "1.02",
			"total_st": 0,
			"total_mem": 2002120,
			"resolution": "1920x1080p-0",
			"bt-mac": "00:40:9d:7d:1b:8f",
			"lo": {
				"mac": "00:00:00:00:00:00",
				"ip": "127.0.0.1"
			},
			"eth0": {
				"mac": "00:40:9d:ee:b6:96",
				"ip": "192.168.1.44"
			},
			"can0": {
				"mac": "00:00:00:00:00:00",
				"ip": "0.0.0.0"
			},
			"wlan0": {
				"mac": "00:40:9d:dd:bd:13",
				"ip": "0.0.0.0"
			}
		}
	*/

	root = json_object_new_object();
	if (!root) {
		status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto error;
	}

	{
		char version[MAX_RESPONSE_SIZE] = STRING_NA;
		char dey_version[PARAM_LENGTH] = STRING_NA;
		char build_id[PARAM_LENGTH] = STRING_NA;

		if (read_dey_version(dey_version) == 0 && read_file_line("/etc/version", build_id, PARAM_LENGTH) == 0) {
			if (strlen(build_id) > 0)
				build_id[strlen(build_id) - 1] = '\0';  /* Remove the last line feed */

			snprintf(version, MAX_RESPONSE_SIZE, "DEY-%s-%s", dey_version, build_id);
		}

		if (json_object_object_add(root, "dey_version", json_object_new_string(version)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}
	}

	{
		char kernel[MAX_RESPONSE_SIZE] = STRING_NA;
		char *resp = NULL;

		if (ldx_process_execute_cmd("uname -a", &resp, 2) != 0 || resp == NULL) {
			if (resp != NULL)
				log_dr_error("Error getting Kernel version: %s", resp);
			else
				log_dr_error("%s", "Error getting Kernel version");
		} else {
			if (strlen(resp) > 0)
				resp[strlen(resp) - 1] = '\0';  /* Remove the last line feed */

			snprintf(kernel, MAX_RESPONSE_SIZE, "%s", resp);
		}

		if (json_object_object_add(root, "kernel_version", json_object_new_string(kernel)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			free(resp);
			goto error;
		}

		free(resp);
	}

	{
		char uboot[MAX_RESPONSE_SIZE] = STRING_NA;

		if (read_file_line("/proc/device-tree/digi,uboot,version", uboot, MAX_RESPONSE_SIZE) != 0)
			log_dr_error("%s", "Error getting U-Boot version");

		if (json_object_object_add(root, "uboot_version", json_object_new_string(uboot)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}
	}

	{
		char board_sn[PARAM_LENGTH] = STRING_NA;
		char dev_type[PARAM_LENGTH] = STRING_NA;
		char som_variant[PARAM_LENGTH] = STRING_NA;
		char board_variant[PARAM_LENGTH] = STRING_NA;
		char board_id[PARAM_LENGTH] = STRING_NA;

		/* Serial number */
		if (read_file_line("/proc/device-tree/digi,hwid,sn", board_sn, PARAM_LENGTH) != 0)
			log_dr_error("%s", "Error getting serial number");

		if (json_object_object_add(root, "serial_number", json_object_new_string(board_sn)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}

		/* Device type */
		if (read_file_line("/proc/device-tree/digi,machine,name", dev_type, PARAM_LENGTH) != 0)
			log_dr_error("%s", "Error getting device type");

		if (json_object_object_add(root, "device_type", json_object_new_string(dev_type)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}

		/* SOM variant */
		if (read_file_line("/proc/device-tree/digi,hwid,variant", som_variant, PARAM_LENGTH) != 0)
			log_dr_error("%s", "Error getting SOM variant");

		if (json_object_object_add(root, "module_variant", json_object_new_string(som_variant)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}

		/* Board variant */
		if (read_file_line("/proc/device-tree/digi,carrierboard,version", board_variant, PARAM_LENGTH) != 0)
			log_dr_error("%s", "Error getting board variant");

		if (json_object_object_add(root, "board_variant", json_object_new_string(board_variant)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}

		/* Board ID */
		if (read_file_line("/proc/device-tree/digi,carrierboard,id", board_id, PARAM_LENGTH) != 0)
			log_dr_error("%s", "Error getting board ID");

		if (json_object_object_add(root, "board_id", json_object_new_string(board_id)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}
	}

	{
		char path[MAX_RESPONSE_SIZE];
		char fw_version[PARAM_LENGTH] = STRING_NA;
		char hw_version[PARAM_LENGTH] = STRING_NA;
		char *resp = NULL;

		if (ldx_process_execute_cmd("grep -l mca /sys/bus/i2c/devices/*/name | xargs -r grep -lv ioexp | xargs -r dirname | xargs -r basename", &resp, 2) != 0 || resp == NULL) {
			if (resp != NULL)
				log_dr_error("Error getting MCA address: %s", resp);
			else
				log_dr_error("%s", "Error getting MCA address");
		} else {
			if (strlen(resp) > 0)
				resp[strlen(resp) - 1] = '\0';  /* Remove the last line feed */

			/* MCA firmware version */
			sprintf(path, "/sys/bus/i2c/devices/%s/fw_version", resp);
			if (read_file_line(path, fw_version, PARAM_LENGTH) != 0)
				log_dr_error("%s", "Error getting MCA firmware version");
			else if (strlen(fw_version) > 0)
				fw_version[strlen(fw_version) - 1] = '\0';  /* Remove the last line feed */

			/* MCA hardware version */
			sprintf(path, "/sys/bus/i2c/devices/%s/hw_version", resp);
			if (read_file_line(path, hw_version, PARAM_LENGTH) != 0)
				log_dr_error("%s", "Error getting MCA hardware version");
			else if (strlen(hw_version) > 0)
				hw_version[strlen(hw_version) - 1] = '\0';  /* Remove the last line feed */
		}

		free(resp);

		if (json_object_object_add(root, "mca_fw_version", json_object_new_string(fw_version)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}

		if (json_object_object_add(root, "mca_hw_version", json_object_new_string(hw_version)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}
	}

	{
		long total_st = 0;

		/* Check first emmc, because '/proc/mtd' may exists although empty */
		if (access(EMMC_SIZE_FILE, R_OK) == 0)
			total_st = get_emmc_size();
		else if (access(NAND_SIZE_FILE, R_OK) == 0)
			total_st = get_nand_size();
		else
			log_dr_error("Error getting storage size: %s", "File not readable");

		if (json_object_object_add(root, "total_st", json_object_new_int64(total_st)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}
	}

	{
		struct sysinfo s_info;
		long total_mem = -1;

		if (sysinfo(&s_info) != 0)
			log_dr_error("Error getting total memory: %s (%d)", strerror(errno), errno);
		else
			total_mem = s_info.totalram / 1024;

		if (json_object_object_add(root, "total_mem", json_object_new_int64(total_mem)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}
	}

	{
		char data[MAX_RESPONSE_SIZE] = {0};
		char resolution[MAX_RESPONSE_SIZE] = {0};
		char *resolution_file = "";

		if (access(RESOLUTION_FILE, R_OK) == 0)
			resolution_file = RESOLUTION_FILE;
		else if (access(RESOLUTION_FILE_CCMP, R_OK) == 0)
			resolution_file = RESOLUTION_FILE_CCMP;
		else if (access(RESOLUTION_FILE_CCMP_HDMI, R_OK) == 0)
			resolution_file = RESOLUTION_FILE_CCMP_HDMI;

		if (access(resolution_file, R_OK) != 0)
			log_dr_error("Error getting video resolution: %s", "File not readable");
		else if (read_file(resolution_file, data, MAX_RESPONSE_SIZE) <= 0)
			log_dr_error("%s", "Error getting video resolution");
		else if (sscanf(data, "U:%s", resolution) < 1) {
			if (sscanf(data, "%s", resolution) < 1)
				log_dr_error("%s", "Error getting video resolution");
		}

		if (json_object_object_add(root, "resolution", json_object_new_string(resolution)) < 0) {
			status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		}
	}

	status = add_bt_json(&root, false);
	if (status != CCCS_RECEIVE_ERROR_NONE)
		goto error;

	status = add_net_ifaces_json(&root, false);
	if (status != CCCS_RECEIVE_ERROR_NONE)
		goto error;

	status = add_wifi_ifaces_json(&root, false);
	if (status != CCCS_RECEIVE_ERROR_NONE)
		goto error;

	resp_buffer->buffer = strdup(json_object_to_json_string(root));
	if (resp_buffer->buffer == NULL) {
		status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto error;
	}

	resp_buffer->length = strlen(resp_buffer->buffer);

	log_dr_debug("%s: response: %s (len: %zu)", __func__,
		(char *)resp_buffer->buffer, resp_buffer->length);

	goto done;

error:
	log_dr_error("Cannot generate response for target '%s': Out of memory", target);

done:
	if (root)
		json_object_put(root);

	return status;
}

/*
 * get_config_cb() - Data callback for 'get_config' data requests
 *
 * @target:		Target ID of the data request (get_config).
 * @req_buffer:		Buffer containing the data request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t get_config_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer)
{
	char *request = req_buffer->buffer;
	json_object *req = NULL, *json_element = NULL, *resp = NULL;
	cccs_receive_error_t status = CCCS_RECEIVE_ERROR_NONE;
	bool eth_cfg = false, wifi_cfg = false, bt_cfg = false;

	log_dr_debug("%s: target='%s'", __func__, target);

	/*
	target "get_config"

	Request:
	{
		"element": ["ethernet", "wifi"]
	}
	Empty request returns all elements.
	Valid elements: ethernet, wifi, bluetooth

	Response:
	{
		"ethernet": {
			 "eth0":{
				"mac":"00:40:9d:ee:b6:96",
				"ip":"192.168.1.44",
				"enable":true,
				"type":0,
				"netmask":"255.255.255.0",
				"gateway":"192.168.1.1",
				"dns1":"80.58.61.250",
				"dns2":"80.58.61.254"
			},
			...
			"ethN": {
				...
			}
		},
		"wifi": {
			"wlan0":{
				"mac":"00:40:9d:dd:bd:13",
				"ip":"192.168.1.48",
				"enable":true,
				"type":0,
				"netmask":"255.255.255.0",
				"gateway":"192.168.1.1",
				"dns1":"80.58.61.250",
				"dns2":"80.58.61.254",
				"ssid":"MOVISTAR_6EA8",
				"sec_mode":2
			},
			...
			"wlanN": {
				...
			}
		},
		"bluetooth": {
			"bt-mac":"00:40:9d:7d:1b:8f",
			"enable":true,
			"name":"ccimx8mm-dvk"
		}
	}
	Only the requested elements.
	type: 1 (DHCP), 0 (Static)
	sec_mode: -1 (error), Open (0), WPA (1), WPA2 (2), WPA3 (3)
	*/

	if (req_buffer->length == 0) {
		eth_cfg = true;
		wifi_cfg = true;
		bt_cfg = true;
	} else {
		int len, i;

		/* Parse req_buffer */
		request[req_buffer->length] = '\0';
		req = json_tokener_parse(request);
		if (!req)
			goto bad_format;

		if (!json_object_object_get_ex(req, "element", &json_element)
		    || !json_object_is_type(json_element, json_type_array))
			goto bad_format;

		len = json_object_array_length(json_element);

		for (i = 0; i < len; i++) {
			json_object *item = json_object_array_get_idx(json_element, i);

			if (json_object_is_type(item, json_type_string)) {
				const char *element = json_object_get_string(item);

				eth_cfg = eth_cfg || strcmp(element, CFG_ELEMENT_ETHERNET) == 0;
				wifi_cfg = wifi_cfg || strcmp(element, CFG_ELEMENT_WIFI) == 0;
				bt_cfg = bt_cfg || strcmp(element, CFG_ELEMENT_BLUETOOTH) == 0;
			}
		}
	}

	if (!eth_cfg && !wifi_cfg && !bt_cfg)
		goto bad_format;

	resp = json_object_new_object();
	if (!resp)
		goto error;

	if (eth_cfg) {
		json_object *item = add_json_element(CFG_ELEMENT_ETHERNET, &resp);
		if (!item)
			goto error;

		status = add_net_ifaces_json(&item, true);
		if (status != CCCS_RECEIVE_ERROR_NONE)
			goto error;
	}

	if (wifi_cfg) {
		json_object *item = add_json_element(CFG_ELEMENT_WIFI, &resp);
		if (!item)
			goto error;

		status = add_wifi_ifaces_json(&item, true);
		if (status != CCCS_RECEIVE_ERROR_NONE)
			goto error;
	}

	if (bt_cfg) {
		json_object *item = add_json_element(CFG_ELEMENT_BLUETOOTH, &resp);
		if (!item)
			goto error;

		status = add_bt_json(&item, true);
		if (status != CCCS_RECEIVE_ERROR_NONE)
			goto error;
	}

	resp_buffer->buffer = strdup(json_object_to_json_string(resp));
	if (resp_buffer->buffer == NULL)
		goto error;

	goto done;

bad_format:
	resp_buffer->buffer = strdup("Invalid format");
	status = resp_buffer->buffer == NULL ? CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY : CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
	log_dr_error("Cannot parse request for target '%s': Invalid format", target);
	goto done;

error:
	status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	log_dr_error("Cannot generate response for target '%s': Out of memory", target);

done:
	if (resp_buffer->buffer != NULL) {
		resp_buffer->length = strlen(resp_buffer->buffer);

		log_dr_debug("%s: response: %s (len: %zu)", __func__,
			(char *)resp_buffer->buffer, resp_buffer->length);
	}

	if (resp)
		json_object_put(resp);

	json_object_put(req);

	return status;
}

/*
 * get_ip_from_json() - Retrieves the IP value from the given JSON object field
 *
 * @json_item:	JSON object.
 * @key:	Field name.
 * @ip:		A pointer to store the IP value.
 *
 * Return: 0 if the field is not found, 1 if success, -1 if bad format.
 */
static int get_ip_from_json(json_object *json_item, const char *key,  uint8_t (*ip)[IPV4_GROUPS])
{
	json_object *cfg_field = NULL;
	const char *ip_str = NULL;
	int segments;

	memset(ip, 0, IPV4_GROUPS);

	if (!json_object_object_get_ex(json_item, key, &cfg_field))
		return 0;

	if (!json_object_is_type(cfg_field, json_type_string))
		return -1;

	ip_str = json_object_get_string(cfg_field);
	segments = sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", *ip, *ip+1, *ip+2, *ip+3);
	if (segments != 4) {
		return -1;
	}

	log_dr_debug("  %s: %hhu.%hhu.%hhu.%hhu", key, (*ip)[0], (*ip)[1], (*ip)[2], (*ip)[3]);

	return 1;
}

/*
 * get_net_cfg_from_json() - Retrieves the network configuration from the JSON object
 *
 * @json_item:	JSON object.
 * @iface_name: Interface name.
 * @net_cfg:	A pointer to store the network configuration.
 *
 * Return: Number of valid fields if success, -1 if fails.
 */
static int get_net_cfg_from_json(json_object *json_item, const char *iface_name, net_config_t *net_cfg)
{
	json_object *cfg_field = NULL;
	int valid_fields = 0, ret;

	strncpy(net_cfg->name, iface_name, sizeof(net_cfg->name) - 1);

	if (json_object_object_get_ex(json_item, CFG_FIELD_ENABLE, &cfg_field)) {
		if (!json_object_is_type(cfg_field, json_type_boolean))
			return -1;
		net_cfg->status = json_object_get_boolean(cfg_field) ? NET_STATUS_CONNECTED : NET_STATUS_DISCONNECTED;
		valid_fields++;
		log_dr_debug("  %s: %s", CFG_FIELD_ENABLE, net_cfg->status == NET_STATUS_CONNECTED ? "true" : "false");
	}

	if (json_object_object_get_ex(json_item, CFG_FIELD_TYPE, &cfg_field)) {
		int type = -1;

		if (!json_object_is_type(cfg_field, json_type_int))
			return -1;

		type = json_object_get_int(cfg_field);
		if (type < 0 || type > 1)
			return -1;

		net_cfg->is_dhcp = type == 1 ? NET_ENABLED : NET_DISABLED;
		valid_fields++;

		log_dr_debug("  %s: %s", CFG_FIELD_TYPE, type == 1 ? "DHCP" : "Static");
	}

	ret = get_ip_from_json(json_item, CFG_FIELD_IP, &net_cfg->ipv4);
	net_cfg->set_ip = (ret == 1);
	if (ret < 0)
		return -1;
	valid_fields += ret;

	ret = get_ip_from_json(json_item, CFG_FIELD_NETMASK, &net_cfg->netmask);
	net_cfg->set_netmask = (ret == 1);
	if (ret < 0)
		return -1;
	valid_fields += ret;

	ret = get_ip_from_json(json_item, CFG_FIELD_GATEWAY, &net_cfg->gateway);
	net_cfg->set_gateway = (ret == 1);
	if (ret < 0)
		return -1;
	valid_fields += ret;

	ret = get_ip_from_json(json_item, CFG_FIELD_DNS1, &net_cfg->dns1);
	if (ret < 0)
		return -1;
	net_cfg->n_dns = (ret == 1 ? net_cfg->n_dns + 1 : net_cfg->n_dns);
	valid_fields += ret;

	ret = get_ip_from_json(json_item, CFG_FIELD_DNS2, &net_cfg->dns2);
	if (ret < 0)
		return -1;
	net_cfg->n_dns = (ret == 1 ? net_cfg->n_dns + 1 : net_cfg->n_dns);
	valid_fields += ret;

	return valid_fields;
}

/*
 * get_wifi_cfg_from_json() - Retrieves the WiFi configuration from the JSON object
 *
 * @json_item:	JSON object.
 * @iface_name: Interface name.
 * @wifi_cfg:	A pointer to store the WiFi configuration.
 *
 * Return: 0 if success, 1 otherwise.
 */
static int get_wifi_cfg_from_json(json_object *json_item, const char *iface_name, wifi_config_t *wifi_cfg)
{
	json_object *cfg_field = NULL;
	int valid_fields = 0;

	strncpy(wifi_cfg->name, iface_name, sizeof(wifi_cfg->name) - 1);

	valid_fields = get_net_cfg_from_json(json_item, iface_name, &wifi_cfg->net_config);
	if (valid_fields < 0)
		return 1;

	valid_fields++;

	wifi_cfg->set_ssid = false;
	if (json_object_object_get_ex(json_item, CFG_FIELD_SSID, &cfg_field)) {
		if (!json_object_is_type(cfg_field, json_type_string))
			return 1;
		wifi_cfg->set_ssid = true;
		strncpy(wifi_cfg->ssid, json_object_get_string(cfg_field), IW_ESSID_MAX_SIZE - 1);
		valid_fields++;
		log_dr_debug("  %s: %s", CFG_FIELD_SSID, wifi_cfg->ssid);
	}

	if (json_object_object_get_ex(json_item, CFG_FIELD_SEC_MODE, &cfg_field)) {
		int sec_mode = -1;

		if (!json_object_is_type(cfg_field, json_type_int))
			return 1;

		sec_mode = json_object_get_int(cfg_field);
		if (sec_mode < WIFI_SEC_MODE_OPEN || sec_mode > WIFI_SEC_MODE_WPA3)
			return 1;

		wifi_cfg->sec_mode = sec_mode;
		valid_fields++;

		log_dr_debug("  %s: %s", CFG_FIELD_SEC_MODE, ldx_wifi_sec_mode_to_str(sec_mode));
	}

	if (json_object_object_get_ex(json_item, CFG_FIELD_PSK, &cfg_field)) {
		if (!json_object_is_type(cfg_field, json_type_string))
			return 1;
		wifi_cfg->psk = (char *)json_object_get_string(cfg_field);
		valid_fields++;
		log_dr_debug("  %s: %s", CFG_FIELD_PSK, wifi_cfg->psk);
	}

	return valid_fields > 0 ? 0 : 1;
}

/*
 * get_wifi_config() - Retrieves the WiFi configurations from the JSON object
 *
 * @req:	Request JSON object.
 * @wifi_cfgs:	Pointer to store configurations.
 * @resp:	Response JSON object.
 *
 * Return: The number of interfaces to configure, -1 for bad format, -2 for out of memory.
 */
static int get_wifi_config(json_object *req, wifi_config_t **wifi_cfgs, json_object **resp)
{
	int n_ifaces = 0, ret = 0;
	wifi_config_t *cfgs = NULL;
	json_object *item = NULL;
	struct json_object_iterator it = json_object_iter_begin(req);
	struct json_object_iterator it_end = json_object_iter_end(req);

	if (json_object_object_length(req) <= 0)
		return -1; /* Bad format */

	item = add_json_element(CFG_ELEMENT_WIFI, resp);
	if (item == NULL) {
		ret = -2; /* Out of memory */
		goto error;
	}

	while (!json_object_iter_equal(&it, &it_end)) {
		wifi_config_t *tmp = NULL;
		const char *iface_name = json_object_iter_peek_name(&it);
		json_object *json_iface = json_object_iter_peek_value(&it);

		if (!ldx_wifi_iface_exists(iface_name)) {
			json_object *iface_item = add_json_element(iface_name, &item);

			wifi_state_error_t err = WIFI_STATE_ERROR_NO_EXIST;
			if (iface_item == NULL
				|| json_object_object_add(iface_item, CFG_FIELD_STATUS, json_object_new_int(err)) < 0
				|| json_object_object_add(iface_item, CFG_FIELD_DESC, json_object_new_string(ldx_wifi_code_to_str(err))) < 0) {
				ret = -2;
				goto error;
			}
			json_object_iter_next(&it);
			continue;
		}

		n_ifaces++;

		tmp = realloc(cfgs, n_ifaces * sizeof(*cfgs));
		if (tmp == NULL) {
			ret = -2;
			goto error;
		}

		cfgs = tmp;

		memset(&cfgs[n_ifaces - 1], 0, sizeof(*cfgs));
		cfgs[n_ifaces - 1].sec_mode = WIFI_SEC_MODE_ERROR;
		cfgs[n_ifaces - 1].net_config.status = NET_STATUS_UNKNOWN;
		cfgs[n_ifaces - 1].net_config.is_dhcp = NET_ENABLED_ERROR;

		log_dr_debug("'%s' new configuration: ", iface_name);
		if (get_wifi_cfg_from_json(json_iface, iface_name, &cfgs[n_ifaces - 1]) != 0) {
			ret = -1;
			goto error;
		}

		json_object_iter_next(&it);
	}

	*wifi_cfgs = cfgs;

	return n_ifaces;

error:
	free(cfgs);

	return ret;
}

/*
 * get_eth_config() - Retrieves the Ethernet configurations from the JSON object
 *
 * @req:	Request JSON object.
 * @wifi_cfgs:	Pointer to store configurations.
 * @resp:	Response JSON object.
 *
 * Return: The number of interfaces to configure, -1 for bad format, -2 for out of memory.
 */
static int get_eth_config(json_object *req, net_config_t **net_cfgs, json_object **resp)
{
	int n_ifaces = 0, ret = 0;
	net_config_t *cfgs = NULL;
	json_object *item = NULL;
	struct json_object_iterator it = json_object_iter_begin(req);
	struct json_object_iterator it_end = json_object_iter_end(req);

	if (json_object_object_length(req) <= 0)
		return -1; /* Bad format */

	item = add_json_element(CFG_ELEMENT_ETHERNET, resp);
	if (item == NULL) {
		ret = -2; /* Out of memory */
		goto error;
	}

	while (!json_object_iter_equal(&it, &it_end)) {
		net_config_t *tmp = NULL;
		const char *iface_name = json_object_iter_peek_name(&it);
		json_object *json_iface = json_object_iter_peek_value(&it);

		if (!ldx_net_iface_exists(iface_name)) {
			json_object *iface_item = add_json_element(iface_name, &item);

			net_state_error_t err = NET_STATE_ERROR_NO_EXIST;
			if (iface_item == NULL
				|| json_object_object_add(iface_item, CFG_FIELD_STATUS, json_object_new_int(err)) < 0
				|| json_object_object_add(iface_item, CFG_FIELD_DESC, json_object_new_string(ldx_net_code_to_str(err))) < 0) {
				ret = -2;
				goto error;
			}
			json_object_iter_next(&it);
			continue;
		}

		n_ifaces++;

		tmp = realloc(cfgs, n_ifaces * sizeof(*cfgs));
		if (tmp == NULL) {
			ret = -2;
			goto error;
		}

		cfgs = tmp;

		memset(&cfgs[n_ifaces - 1], 0, sizeof(*cfgs));
		cfgs[n_ifaces - 1].status = NET_STATUS_UNKNOWN;
		cfgs[n_ifaces - 1].is_dhcp = NET_ENABLED_ERROR;

		log_dr_debug("'%s' new configuration: ", iface_name);
		if (get_net_cfg_from_json(json_iface, iface_name, &cfgs[n_ifaces - 1]) < 0) {
			ret = -1;
			goto error;
		}
		json_object_iter_next(&it);
	}

	*net_cfgs = cfgs;

	return n_ifaces;

error:
	free(cfgs);

	return ret;
}

/*
 * get_bt_config() - Retrieves the Bluetooth from the JSON object
 *
 * @req:		Request JSON object.
 * @bt_config_t:	Pointer to store the configuration.
 * @resp:		Response JSON object.
 *
 * Return: 0 if success, -1 for bad format, -2 for out of memory.
 */
static int get_bt_config(json_object *bt_req, bt_config_t *bt_cfg, json_object **resp)
{
	int valid_fields = 0;
	json_object *cfg_field = NULL;
	json_object *bt_item = add_json_element(CFG_ELEMENT_BLUETOOTH, resp);

	if (bt_item == NULL)
		return -2; /* Out of memory */

	if (json_object_object_get_ex(bt_req, CFG_FIELD_ENABLE, &cfg_field)) {
		if (!json_object_is_type(cfg_field, json_type_boolean))
			return -1; /* Bad format */
		bt_cfg->enable = json_object_get_boolean(cfg_field) ? BT_ENABLED : BT_DISABLED;
		valid_fields++;
	}

	if (json_object_object_get_ex(bt_req, CFG_FIELD_NAME, &cfg_field)) {
		if (!json_object_is_type(cfg_field, json_type_string))
			return -1; /* Bad format */

		bt_cfg->set_name = true;
		strncpy(bt_cfg->name, json_object_get_string(cfg_field), BT_NAME_MAX_LEN);
		valid_fields++;
	}

	return valid_fields > 0 ? 0 : -1;
}

/*
 * set_config_cb() - Data callback for 'set_config' data requests
 *
 * @target:		Target ID of the data request (set_config).
 * @req_buffer:		Buffer containing the data request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t set_config_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer)
{
	char *request = req_buffer->buffer;
	json_object *req = NULL, *json_element = NULL, *resp = NULL;
	cccs_receive_error_t status = CCCS_RECEIVE_ERROR_NONE;
	int valid_fields = 0, bt_devs = 0, n_eth_ifaces = 0, n_wifi_ifaces = 0, i;
	net_config_t *net_cfgs = NULL;
	wifi_config_t *wifi_cfgs = NULL;
	bt_config_t bt_cfg = {
		.dev_id = 0,
		.enable = BT_ENABLED_ERROR,
		.set_name = false,
		.name = {0},
	};

	log_dr_debug("%s: target='%s'", __func__, target);

	resp_buffer->buffer  = NULL;

	/*
	target "set_config"

	Request:
	{
		"ethernet": {
			 "eth0":{
				"ip":"192.168.1.44",
				"enable":true,
				"type":1,
				"netmask":"255.255.255.0",
				"gateway":"192.168.1.1",
				"dns1":"80.58.61.250",
				"dns2":"80.58.61.254"
			},
			...
			"ethN": {
				...
			}
		},
		"wifi": {
			"wlan0":{
				"ip":"192.168.1.48",
				"enable":true,
				"type":0,
				"ssid":"MOVISTAR_6EA8"
				"sec_mode":3,
				"psk":"password",
			},
			...
			"wlanN": {
				...
			}
		},
		"bluetooth": {
			"enable":true,
			"name":"ccimx8mm-dvk"
		}
	}
	Valid elements: ethernet, wifi, bluetooth
	type: 1 (DHCP), 0 (Static)
	sec_mode: 0 (open), 1 (wpa), 2 (wpa2), 3 (wpa3)

	Response:
	{
		"ethernet": {
			"eth0": {
				"status": 0
			}
		}
	}
	*/

	if (req_buffer->length == 0)
		goto bad_format;

	request[req_buffer->length] = '\0';
	req = json_tokener_parse(request);
	if (!req || json_object_get_type(req) != json_type_object
		|| json_object_object_length(req) == 0)
		goto bad_format;

	resp = json_object_new_object();
	if (!resp)
		goto error;

	if (json_object_object_get_ex(req, CFG_ELEMENT_ETHERNET, &json_element)) {
		n_eth_ifaces = get_eth_config(json_element, &net_cfgs, &resp);
		if (n_eth_ifaces == -1)
			goto bad_format;
		if (n_eth_ifaces == -2)
			goto error;
		valid_fields++;
	}

	if (json_object_object_get_ex(req, CFG_ELEMENT_WIFI, &json_element)) {
		n_wifi_ifaces = get_wifi_config(json_element, &wifi_cfgs, &resp);
		if (n_wifi_ifaces == -1)
			goto bad_format;
		if (n_wifi_ifaces == -2)
			goto error;
		valid_fields++;
	}

	if (json_object_object_get_ex(req, CFG_ELEMENT_BLUETOOTH, &json_element)) {
		int ret_bt = get_bt_config(json_element, &bt_cfg, &resp);
		if (ret_bt == -1)
			goto bad_format;
		if (ret_bt == -2)
			goto error;

		bt_cfg.dev_id = 0;
		bt_devs = 1;
		valid_fields++;
	}

	if (!valid_fields)
		goto bad_format;

	/* Configure Bluetooth */
	if (bt_devs) {
		json_object *bt_item = NULL;
		bt_state_error_t err = ldx_bt_set_config(bt_cfg);

		if (!json_object_object_get_ex(resp, CFG_ELEMENT_BLUETOOTH, &bt_item))
			goto bad_format; /* Should not occur */

		if (json_object_object_add(bt_item, CFG_FIELD_STATUS, json_object_new_int(err)) < 0
			|| json_object_object_add(bt_item, CFG_FIELD_DESC, json_object_new_string(ldx_bt_code_to_str(err))) < 0)
			goto error;
	}

	/* Configure Ethernet */
	for (i = 0; i < n_eth_ifaces; i++) {
		net_state_error_t err;
		json_object *eth_item = NULL, *iface_item = NULL;

		if (net_cfgs[i].name == NULL)
			continue;

		err = ldx_net_set_config(net_cfgs[i]);

		if (!json_object_object_get_ex(resp, CFG_ELEMENT_ETHERNET, &eth_item))
			goto bad_format; /* Should not occur */

		iface_item = add_json_element(net_cfgs[i].name, &eth_item);
		if (iface_item == NULL
			|| json_object_object_add(iface_item, CFG_FIELD_STATUS, json_object_new_int(err)) < 0
			|| json_object_object_add(iface_item, CFG_FIELD_DESC, json_object_new_string(ldx_net_code_to_str(err))) < 0)
			goto error;
	}

	/* Configure WiFi */
	for (i = 0; i < n_wifi_ifaces; i++) {
		wifi_state_error_t err;
		json_object *wifi_item = NULL, *iface_item = NULL;

		if (wifi_cfgs[i].name == NULL)
			continue;

		err = ldx_wifi_set_config(wifi_cfgs[i]);

		if (!json_object_object_get_ex(resp, CFG_ELEMENT_WIFI, &wifi_item))
			goto bad_format; /* Should not occur */

		iface_item = add_json_element(wifi_cfgs[i].name, &wifi_item);
		if (iface_item == NULL
			|| json_object_object_add(iface_item, CFG_FIELD_STATUS, json_object_new_int(err)) < 0
			|| json_object_object_add(iface_item, CFG_FIELD_DESC, json_object_new_string(ldx_wifi_code_to_str(err))) < 0)
			goto error;
	}

	resp_buffer->buffer = strdup(json_object_to_json_string(resp));
	if (resp_buffer->buffer == NULL)
		goto error;

	goto done;

bad_format:
	if (resp_buffer->buffer != NULL)
		free(resp_buffer->buffer);
	resp_buffer->buffer = strdup("Invalid format");
	status = resp_buffer->buffer == NULL ? CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY : CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
	log_dr_error("Cannot parse request for target '%s': Invalid format", target);
	goto done;

error:
	if (resp_buffer->buffer != NULL)
		free(resp_buffer->buffer);
	resp_buffer->buffer = strdup("Out of memory");
	status = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	log_dr_error("Cannot process request for target '%s': Out of memory", target);

done:
	if (resp_buffer->buffer != NULL) {
		resp_buffer->length = strlen(resp_buffer->buffer);

		log_dr_debug("%s: response: %s (len: %zu)", __func__,
			(char *)resp_buffer->buffer, resp_buffer->length);
	}

	free(net_cfgs);

	free(wifi_cfgs);

	if (resp)
		json_object_put(resp);

	/* It may happen that the parser function returns an string, the same that
	   is trying to parse. In that case do not free it, leave the connector
	   to free it */
	if (req && !json_object_is_type(req, json_type_string))
		json_object_put(req);

	return status;
}

/*
 * get_time_cb() - Data callback for 'get_time' data requests
 *
 * @target:		Target ID of the data request (get_time).
 * @req_buffer:		Buffer containing the data request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t get_time_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer)
{
	UNUSED_ARGUMENT(req_buffer);

	log_dr_debug("%s: target='%s'", __func__, target);

	resp_buffer->buffer = calloc(MAX_RESPONSE_SIZE + 1, sizeof(char));
	if (resp_buffer->buffer == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		return CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	}

	time_t t = time(NULL);
	resp_buffer->length = snprintf(resp_buffer->buffer,
			MAX_RESPONSE_SIZE, "Time: %s", ctime(&t));

	return CCCS_RECEIVE_ERROR_NONE;
}

/*
 * update_user_led_cb() - Data callback for 'user_led' data requests
 *
 * @target:		Target ID of the data request (user_led).
 * @req_buffer:		Buffer containing the data request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t update_user_led_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer)
{
	cccs_receive_error_t ret = CCCS_RECEIVE_ERROR_NONE;
	char *val = NULL, *error_msg = NULL;
	gpio_t *led = NULL;
	gpio_value_t led_value = GPIO_LOW;

	log_dr_debug("%s: target='%s'", __func__, target);

	val = calloc(req_buffer->length + 1, sizeof(char));
	if (val == NULL) {
		error_msg = "Out of memory";
		ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto done;
	}

	strncpy(val, req_buffer->buffer, req_buffer->length);
	log_dr_debug("%s=%s", target, val);

	if (strcmp(val, "true") == 0 || strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
		led_value = GPIO_HIGH;
	} else if (strcmp(val, "false") == 0 || strcmp(val, "off") == 0 || strcmp(val, "0") == 0) {
		led_value = GPIO_LOW;
	} else {
		error_msg = "Unknown LED status";
		ret = CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
		goto done;
	}

	/* Request User LED GPIO */
	led = ldx_gpio_request_by_alias(USER_LED_ALIAS, GPIO_OUTPUT_LOW, REQUEST_SHARED);
	if (led == NULL) {
		error_msg = "Failed to initialize LED";
		ret = CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
		goto done;
	}

	if (ldx_gpio_set_value(led, led_value) != EXIT_SUCCESS) {
		error_msg = "Failed to set LED";
		ret = CCCS_RECEIVE_ERROR_STATUS_SESSION_ERROR;
		goto done;
	}

done:
	resp_buffer->length = 2; /* 'OK' length */
	if (ret != CCCS_RECEIVE_ERROR_NONE) {
		resp_buffer->length = snprintf(NULL, 0, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	}

	resp_buffer->buffer = calloc(resp_buffer->length + 1, sizeof(char));
	if (resp_buffer->buffer == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto exit;
	}

	if (ret != CCCS_RECEIVE_ERROR_NONE) {
		resp_buffer->length = sprintf(resp_buffer->buffer, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	} else {
		resp_buffer->length = sprintf(resp_buffer->buffer, "OK");
	}

exit:
	ldx_gpio_free(led);
	free(val);

	return ret;
}

/*
 * play_music_cb() - Data callback for 'play_music' data requests
 *
 * @target:		Target ID of the data request (play_music).
 * @req_buffer:		Buffer containing the data request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t play_music_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer)
{
	char *request = req_buffer->buffer, *error_msg = NULL, *resp = NULL, *music_file = NULL;
	json_object *req = NULL, *json_element = NULL;
	cccs_receive_error_t ret = CCCS_RECEIVE_ERROR_NONE;
	bool play = false;

	log_dr_debug("%s: target='%s'", __func__, target);

	if (req_buffer->length == 0)
		goto bad_format;

	request[req_buffer->length] = '\0';
	req = json_tokener_parse(request);
	if (!req)
		goto bad_format;

	/* Read the "play" value. */
	if (json_object_object_get_ex(req, CFG_FIELD_PLAY, &json_element)) {
		if (!json_object_is_type(json_element, json_type_boolean))
			goto bad_format; /* Must be a boolean field. */
		play = json_object_get_boolean(json_element);
	} else {
		goto bad_format; /* Required field. */
	}

	/* Read the "music_file" value. */
	if (play) {
		if (json_object_object_get_ex(req, CFG_FIELD_MUSIC_FILE, &json_element)) {
			if (!json_object_is_type(json_element, json_type_string))
				goto bad_format; /* Must be a string field. */
			music_file = (char *)json_object_get_string(json_element);
		} else {
			goto bad_format; /* Required field. */
		}
	}

	/* Stop any mpg123 process. Do not check for error because it will not return 0 if no music was playing. */
	ldx_process_execute_cmd(CMD_STOP_MUSIC, &resp, 2);

	/* If music is set to play, reproduce the sound. */
	if (play) {
		char *cmd = NULL;
		int cmd_len = 0;

		/* Verify that music file exists. */
		if (access(music_file, F_OK) != 0) {
			error_msg = "File does not exist";
			ret = CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
			goto done;
		}
		/* Build play command. */
		cmd_len = snprintf(NULL, 0, CMD_PLAY_MUSIC, music_file);
		cmd = calloc(cmd_len + 1, sizeof(char));
		if (cmd == NULL) {
			error_msg = "Out of memory";
			ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		} else {
			sprintf(cmd, CMD_PLAY_MUSIC, music_file);
			/* Do not check for error because 'setsid' always returns -15. */
			ldx_process_execute_cmd(cmd, &resp, 2);
			free(cmd);
		}
	}

	goto done;

bad_format:
	error_msg = "Invalid format";
	ret = CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
	log_dr_error("Cannot parse request for target '%s': Invalid request format", target);

done:
	resp_buffer->length = 2; /* 'OK' length */
	if (ret != CCCS_RECEIVE_ERROR_NONE) {
		resp_buffer->length = snprintf(NULL, 0, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	}

	resp_buffer->buffer = calloc(resp_buffer->length + 1, sizeof(char));
	if (resp_buffer->buffer == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto exit;
	}

	if (ret != CCCS_RECEIVE_ERROR_NONE) {
		resp_buffer->length = sprintf(resp_buffer->buffer, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	} else {
		resp_buffer->length = sprintf(resp_buffer->buffer, "OK");
	}

exit:
	/* Free resources. */
	free(resp);
	if (req && !json_object_is_type(req, json_type_string))
		json_object_put(req);

	return ret;
}

/*
 * set_volume_cb() - Data callback for 'set_audio_volume' data requests
 *
 * @target:		Target ID of the data request (set_audio_volume).
 * @req_buffer:		Buffer containing the data request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: CCCS_RECEIVE_ERROR_NONE if success, any other code otherwise.
 */
static cccs_receive_error_t set_volume_cb(char const *const target,
		cccs_buffer_info_t const *const req_buffer,
		cccs_buffer_info_t *const resp_buffer)
{
	cccs_receive_error_t ret = CCCS_RECEIVE_ERROR_NONE;
	char *cmd = NULL, *error_msg = NULL, *resp = NULL, *val = NULL;
	uint16_t volume, cmd_len = 0;

	log_dr_debug("%s: target='%s'", __func__, target);

	val = calloc(req_buffer->length + 1, sizeof(char));
	if (val == NULL) {
		ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto done;
	}

	strncpy(val, req_buffer->buffer, req_buffer->length);
	log_dr_debug("%s=%s", target, val);

	/* Verify value is an integer. */
	volume = atoi(val);
	if (strlen(val) != (uint16_t)snprintf(NULL, 0, "%d", volume)) {
		error_msg = "Volume value must be an integer";
		log_dr_error("Argument for target '%s' is not an integer: '%s'", target, val);
		ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto done;
	}

	/* Execute command. */
	cmd_len = snprintf(NULL, 0, CMD_SET_VOLUME, volume, volume);
	cmd = calloc(cmd_len + 1, sizeof(char));
	if (cmd == NULL) {
		error_msg = "Out of memory";
		log_dr_error("Cannot change volume: %s", error_msg);
		ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto done;
	}
	sprintf(cmd, CMD_SET_VOLUME, volume, volume);
	if (ldx_process_execute_cmd(cmd, &resp, 2) != 0 || resp == NULL) {
		error_msg = "Error setting audio volume";
		ret = CCCS_RECEIVE_ERROR_INVALID_DATA_CB;
		if (resp != NULL)
			log_dr_error("%s: %s", error_msg, resp);
		else
			log_dr_error("%s", error_msg);
	}

done:
	resp_buffer->length = 2; /* 'OK' length */
	if (ret != CCCS_RECEIVE_ERROR_NONE) {
		resp_buffer->length = snprintf(NULL, 0, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	}

	resp_buffer->buffer = calloc(resp_buffer->length + 1, sizeof(char));
	if (resp_buffer->buffer == NULL) {
		log_dr_error("Cannot generate response for target '%s': Out of memory", target);
		ret = CCCS_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
		goto exit;
	}

	if (ret != CCCS_RECEIVE_ERROR_NONE) {
		resp_buffer->length = sprintf(resp_buffer->buffer, "ERROR: %s", error_msg);
		log_dr_error("Cannot process request for target '%s': %s", target, error_msg);
	} else {
		resp_buffer->length = sprintf(resp_buffer->buffer, "OK");
	}

exit:
	free(val);
	free(cmd);
	free(resp);

	return ret;
}

/*
 * request_status_cb() - Status callback for application data requests
 *
 * @target:		Target ID of the data request.
 * @resp_buffer:	Buffer containing the response data.
 * @rcv_error:		The error status of the receive process.
 * @rcv_error_hint:	The error hint from the connector daemon.
 *
 * This callback is executed when the receive process has finished. It doesn't
 * matter if everything worked or there was an error during the process.
 *
 * Cleans and frees the response buffer.
 */
static void request_status_cb(char const *const target,
		cccs_buffer_info_t *const resp_buffer,
		int rcv_error, const char *const rcv_error_hint)
{
	log_dr_debug(
			"%s: target='%s' - error='%d' - error-hint='%s'", __func__,
			target, rcv_error, rcv_error_hint);

	/* Free the response buffer */
	if (resp_buffer != NULL)
		free(resp_buffer->buffer);
}

int register_custom_data_requests(void)
{
	unsigned int i;
	cccs_comm_error_t ret;

	for (i = 0; i < ARRAY_SIZE(request_handlers); i++) {
		const struct handler_t *handler = &request_handlers[i];
		cccs_resp_t resp;

		ret = cccs_add_request_target(handler->target,
			handler->data_cb, handler->status_cb, &resp);

		if (ret != CCCS_SEND_ERROR_NONE) {
			log_dr_error("Cannot register target '%s': CCCSD error %d",
				handler->target, ret);
		} else if (resp.code != 0) {
			if (resp.hint)
				log_dr_error("Cannot register target '%s': CCCSD error, %s (%d)",
					handler->target, resp.hint, resp.code);
			else
				log_dr_error("Cannot register target '%s': CCCSD error, %d",
					handler->target, resp.code);
		}

		free(resp.hint);
	}

	return ret;
}

void unregister_custom_data_requests(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(request_handlers); i++) {
		const struct handler_t *handler = &request_handlers[i];
		cccs_resp_t resp;
		cccs_comm_error_t ret = cccs_remove_request_target(handler->target, &resp);

		if (ret != CCCS_SEND_ERROR_NONE) {
			log_dr_error("Cannot unregister target '%s': CCCSD error %d",
				handler->target, ret);
		} else if (resp.code != 0) {
			if (resp.hint)
				log_dr_error("Cannot unregister target '%s': CCCSD error, %s (%d)",
					handler->target, resp.hint, resp.code);
			else
				log_dr_error("Cannot unregister target '%s': CCCSD error, %d",
					handler->target, resp.code);
		}

		free(resp.hint);
	}
}