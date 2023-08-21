/*
 * Copyright (c) 2017-2022 Digi International Inc.
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

#ifndef CC_CONFIG_H_
#define CC_CONFIG_H_

#include <confuse.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ccimp/ccimp_types.h"

#define FS_SERVICE		(1 << 0)
#define SYS_MONITOR_SERVICE	(1 << 1)

#define LOG_LEVEL_ERROR		LOG_ERR
#define LOG_LEVEL_INFO		LOG_INFO
#define LOG_LEVEL_DEBUG		LOG_DEBUG

/**
 * struct vdir_t - Virtual directory configuration type
 *
 * @name:	Name of the virtual directory
 * @path:	Local path where the virtual directory is mapped
 */
typedef struct {
	char *name;
	char *path;
} vdir_t;

/**
 * struct cc_cfg_t - Cloud Connector configuration type
 *
 * @vendor_id:				Identifier of the Remote Manager user account
 * @device_type:			Name of the device running Cloud Connector
 * @fw_version_src:			Source of the firmware version
 * @fw_version:				Version of the firmware running Cloud Connector
 * @description:			Description of the device
 * @contact:				Contact information of the device
 * @location:				Location of the device (not GPS location)
 * @url:				Remote Manager URL
 * @client_cert_path:			Client certificate path
 * @enable_reconnect:			Enabled reconnection when connection is lost
 * @reconnect_time:			Number of seconds to reconnect
 * @keepalive_rx:			Keepalive receiving frequency (seconds)
 * @keepalive_tx:			Keepalive transmitting frequency (seconds)
 * @wait_count:				Number of lost keepalives to consider the connection lost
 * @services:				Enabled services
 * @vdirs:				List of virtual directories
 * @n_vdirs:				Number of virtual directories in the list
 * @fw_download_path			Absolute path to download firmware files
 * @sys_mon_sample_rate:		Frequency at which gather system information
 * @sys_mon_num_samples_upload:		Number of samples of each channel to gather before uploading
 * @sys_mon_metrics:			List of metrics and interfaces to measure and upload to Remote Manager
 * @n_sys_mon_metrics:			Number of system monitor metrics and interfaces to measure
 * @sys_mon_all_metrics:		Whether all system monitor metrics should be measured or not
 * @use_static_location			If true, use static location as GPS value
 * @latitude				Latitude value for static location
 * @longitude				Longitude value for static location
 * @altitude				Altitude value for static location
 * @log_level:				Level of messaging to log
 * @log_console:			Enable messages logging to the console
 * @on_the_fly:				Enable on-the-fly firmware download support
 *
 */
typedef struct {
	uint32_t vendor_id;
	char *device_type;
	char *fw_version_src;
	char *fw_version;
	char *description;
	char *contact;
	char *location;

	char *url;
	char *client_cert_path;
	ccapi_bool_t enable_reconnect;
	uint16_t reconnect_time;
	uint16_t keepalive_rx;
	uint16_t keepalive_tx;
	uint16_t wait_count;

	uint8_t services;

	vdir_t *vdirs;
	unsigned int n_vdirs;

	char *fw_download_path;

	uint32_t sys_mon_sample_rate;
	uint32_t sys_mon_num_samples_upload;
	char **sys_mon_metrics;
	unsigned int n_sys_mon_metrics;
	ccapi_bool_t sys_mon_all_metrics;

	ccapi_bool_t use_static_location;
	float latitude;
	float longitude;
	float altitude;

	int log_level;
	ccapi_bool_t log_console;
	ccapi_bool_t on_the_fly;
} cc_cfg_t;

/*
 * parse_configuration() - Parse and save the settings of a configuration file
 *
 * @filename:	Name of the file containing the configuration settings.
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the
 * 		settings parsed from the configuration file are saved.
 *
 * Read the provided configuration file and save the settings in the given
 * cc_cfg_t struct. If the file does not exist or cannot be read, the
 * configuration struct is initialized with the default settings.
 *
 * Return: 0 if the file is parsed successfully, -1 if there is an error
 *         parsing the file.
 */
int parse_configuration(const char *const filename, cc_cfg_t *cc_cfg);

/*
 * close_configuration() - Close configuration and free internal vars
 *
 * Note that after calling this method, the configuration must be parsed again
 * from the configuration file using 'parse_configuration()' method before
 * trying to use any other configuration function.
 */
void close_configuration(void);

/*
 * free_configuration() - Release the configuration var
 *
 * @cc_cfg:	General configuration struct (cc_cfg_t) holding the
 * 		current connector configuration.
 */
void free_configuration(cc_cfg_t *const config);

/*
 * get_configuration() - Retrieve current connector configuration
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) that will hold
 * 		the current connector configuration.
 *
 * Return: 0 if the configuration is retrieved successfully, -1 otherwise.
 */
int get_configuration(cc_cfg_t *cc_cfg);

/*
 * get_confuse_configuration() - Retrieve current confuse connector configuration
 *
 * Return: Struct (cfg_t) that holds the current connector configuration.
 */
cfg_t *get_confuse_configuration(void);

/*
 * save_configuration() - Save the given connector configuration
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) containing
 *		the connector settings to save.
 *
 * Return: 0 if the configuration is saved successfully, -1 otherwise.
 */
int save_configuration(cc_cfg_t *cc_cfg);

/*
 * apply_configuration() - Apply provided configuration
 *
 * Return: 0 if success,
 *	   1 if there was any error with the provided values,
 *	   2 if there was an error writing to the file.
 */
int apply_configuration(cc_cfg_t *cc_cfg);

/*
 * get_client_cert_path() - Return the client certificate path in the config file.
 *
 * Return:	Path file or NULL if error.
 */
char *get_client_cert_path(void);

int import_devicerequests(const char *file_path);
int dump_devicerequests(const char *file_path);

#endif /* CC_CONFIG_H_ */
