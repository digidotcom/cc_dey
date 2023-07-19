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

#include <confuse.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ccapi/ccapi.h"
#include "cc_config.h"
#include "cc_logging.h"
#include "utils.h"

/*------------------------------------------------------------------------------
                             D E F I N I T I O N S
------------------------------------------------------------------------------*/
#define GROUP_VIRTUAL_DIRS			"virtual-dirs"
#define GROUP_VIRTUAL_DIR			"vdir"

#define ENABLE_FS_SERVICE			"enable_file_system"

#define ENABLE_SYSTEM_MONITOR		"enable_system_monitor"

#define SETTING_VENDOR_ID			"vendor_id"
#define SETTING_VENDOR_ID_MAX		0xFFFFFFFFUL
#define SETTING_DEVICE_TYPE			"device_type"
#define SETTING_DEVICE_TYPE_MAX			255
#define SETTING_FW_VERSION			"firmware_version"
#define SETTING_DESCRIPTION			"description"
#define SETTING_DESCRIPTION_MIN		0
#define SETTING_DESCRIPTION_MAX		63
#define SETTING_CONTACT				"contact"
#define SETTING_CONTACT_MIN			0
#define SETTING_CONTACT_MAX			63
#define SETTING_LOCATION			"location"
#define SETTING_LOCATION_MIN		0
#define SETTING_LOCATION_MAX		63

#define SETTING_RM_URL				"url"
#define SETTING_CLIENT_CERT_PATH	"client_cert_path"
#define SETTING_ENABLE_RECONNECT	"enable_reconnect"
#define SETTING_RECONNECT_TIME		"reconnect_time"
#define SETTING_RECONNECT_TIME_MIN	30
#define SETTING_RECONNECT_TIME_MAX	32767
#define SETTING_KEEPALIVE_TX		"keep_alive_time"
#define SETTING_KEEPALIVE_RX		"server_keep_alive_time"
#define SETTING_WAIT_TIMES			"wait_times"

#define SETTING_NAME				"name"
#define SETTING_PATH				"path"

#define SETTING_FW_DOWNLOAD_PATH	"firmware_download_path"

#define SETTING_SYS_MON_METRICS		"system_monitor_metrics"
#define SETTING_SYS_MON_SAMPLE_RATE	"system_monitor_sample_rate"
#define SETTING_SYS_MON_SAMPLE_RATE_MIN		1
#define SETTING_SYS_MON_SAMPLE_RATE_MAX		365 * 24 * 60 * 60UL /* A year */
#define SETTING_SYS_MON_UPLOAD_SIZE	"system_monitor_upload_samples_size"
#define SETTING_SYS_MON_UPLOAD_SIZE_MIN		1
#define SETTING_SYS_MON_UPLOAD_SIZE_MAX		250

#define SETTING_USE_STATIC_LOCATION "static_location"
#define SETTING_LATITUDE			"latitude"
#define SETTING_LATITUDE_MIN		(-90.0)
#define SETTING_LATITUDE_MAX		(90.0)
#define SETTING_LONGITUDE			"longitude"
#define SETTING_LONGITUDE_MIN		(-180.0)
#define SETTING_LONGITUDE_MAX		(180.0)
#define SETTING_ALTITUDE			"altitude"
#define SETTING_ON_THE_FLY			"on_the_fly"

#define SETTING_LOG_LEVEL			"log_level"
#define SETTING_LOG_CONSOLE			"log_console"

#define SETTING_UNKNOWN				"__unknown"

#define FW_VERSION_FILE_PREFIX		"file://"
#define FW_VERSION_FILE_DEFAULT		"/etc/sw-versions"

#define LOG_LEVEL_ERROR_STR			"error"
#define LOG_LEVEL_INFO_STR			"info"
#define LOG_LEVEL_DEBUG_STR			"debug"

#define ALL_METRICS			"*"

/*------------------------------------------------------------------------------
                    F U N C T I O N  D E C L A R A T I O N S
------------------------------------------------------------------------------*/
static int fill_connector_config(cc_cfg_t *cc_cfg);
static int set_connector_config(cc_cfg_t *cc_cfg);
static void conf_error_func(cfg_t *cfg, const char *format, va_list args);
static int check_cfg(void);
static int cfg_check_vendor_id(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_device_type(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_fw_version(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_rm_url(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_cert_path(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_reconnect_time(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_keepalive_rx(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_keepalive_tx(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_range(cfg_t *cfg, cfg_opt_t *opt, uint32_t min, uint32_t max);
static int cfg_check_float_range(cfg_t *cfg, cfg_opt_t *opt, float min, float max);
static int cfg_check_wait_times(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_sys_mon_sample_rate(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_sys_mon_upload_size(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_sys_mon_metrics(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_latitude(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_longitude(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_description(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_contact(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_location(cfg_t *cfg, cfg_opt_t *opt);
static int cfg_check_string_length(cfg_t *cfg, cfg_opt_t *opt, uint16_t min, uint16_t max);
static int cfg_check_fw_download_path(cfg_t *cfg, cfg_opt_t *opt);
static void get_virtual_directories(cfg_t *const cfg, cc_cfg_t *const cc_cfg);
static int get_log_level(void);
static void get_sys_mon_metrics(cfg_t *const cfg, cc_cfg_t *const cc_cfg);

/*------------------------------------------------------------------------------
                         G L O B A L  V A R I A B L E S
------------------------------------------------------------------------------*/
static cfg_t *cfg;
static const char *cfg_path;

/*------------------------------------------------------------------------------
                     F U N C T I O N  D E F I N I T I O N S
------------------------------------------------------------------------------*/
/*
 * parse_configuration() - Parse and save the settings of a configuration file
 *
 * @filename:	Name of the file containing the configuration settings.
 * @cc_cfg:		Connector configuration struct (cc_cfg_t) where the
 * 				settings parsed from the configuration file are saved.
 *
 * Read the provided configuration file and save the settings in the given
 * cc_cfg_t struct. If the file does not exist or cannot be read, the
 * configuration struct is initialized with the default settings.
 *
 * Return: 0 if the file is parsed successfully, -1 if there is an error
 *         parsing the file.
 */
int parse_configuration(const char *const filename, cc_cfg_t *cc_cfg)
{
	/* Virtual directory settings. */
	static cfg_opt_t vdir_opts[] = {
			/* ------------------------------------------------------------ */
			/*|  TYPE   |   SETTING NAME    |  DEFAULT VALUE   |   FLAGS   |*/
			/* ------------------------------------------------------------ */
			CFG_STR		(SETTING_NAME,			"/",			CFGF_NONE),
			CFG_STR		(SETTING_PATH,			"/",			CFGF_NONE),

			/* Needed for unknown settings. */
			CFG_STR 	(SETTING_UNKNOWN,		NULL,			CFGF_NONE),
			CFG_END()
	};

	/* Virtual directories settings. */
	static cfg_opt_t virtual_dirs_opts[] = {
			/* ------------------------------------------------------------ */
			/*|  TYPE   |   SETTING NAME    |  DEFAULT VALUE   |   FLAGS   |*/
			/* ------------------------------------------------------------ */
			CFG_SEC (GROUP_VIRTUAL_DIR,			vdir_opts,		CFGF_MULTI),

			/* Needed for unknown settings. */
			CFG_STR (SETTING_UNKNOWN,			NULL,			CFGF_NONE),
			CFG_END()
	};

	/* Overall structure of the settings. */
	static cfg_opt_t opts[] = {
			/* ------------------------------------------------------------ */
			/*|  TYPE   |   SETTING NAME    |  DEFAULT VALUE   |   FLAGS   |*/
			/* ------------------------------------------------------------ */
			/* General settings. */
			CFG_STR		(SETTING_VENDOR_ID,		NULL,			CFGF_NODEFAULT),
			CFG_STR		(SETTING_DEVICE_TYPE,	"DEY device",	CFGF_NONE),
			CFG_STR		(SETTING_FW_VERSION,	FW_VERSION_FILE_PREFIX FW_VERSION_FILE_DEFAULT,CFGF_NONE),
			CFG_STR		(SETTING_DESCRIPTION,	"",				CFGF_NONE),
			CFG_STR		(SETTING_CONTACT,		"",				CFGF_NONE),
			CFG_STR		(SETTING_LOCATION,		"",				CFGF_NONE),

			/* Connection settings. */
			CFG_STR		(SETTING_RM_URL, "edp12.devicecloud.com", CFGF_NONE),
			CFG_STR		(SETTING_CLIENT_CERT_PATH, "/etc/ssl/certs/drm_cert.pem", CFGF_NONE),
			CFG_BOOL	(SETTING_ENABLE_RECONNECT, cfg_true,	CFGF_NONE),
			CFG_INT		(SETTING_RECONNECT_TIME,		30,		CFGF_NONE),
			CFG_INT		(SETTING_KEEPALIVE_TX,			75,		CFGF_NONE),
			CFG_INT		(SETTING_KEEPALIVE_RX,			75,		CFGF_NONE),
			CFG_INT		(SETTING_WAIT_TIMES,			5,		CFGF_NONE),

			/* Services settings. */
			CFG_BOOL	(ENABLE_FS_SERVICE,		cfg_true,		CFGF_NONE),
			CFG_STR		(SETTING_FW_DOWNLOAD_PATH, NULL,		CFGF_NODEFAULT),
			CFG_BOOL	(SETTING_ON_THE_FLY,	cfg_false,		CFGF_NONE),

			/* File system settings. */
			CFG_SEC		(GROUP_VIRTUAL_DIRS, virtual_dirs_opts, CFGF_NONE),

			/* System monitor settings. */
			CFG_BOOL	(ENABLE_SYSTEM_MONITOR,		cfg_true,	CFGF_NONE),
			CFG_INT		(SETTING_SYS_MON_SAMPLE_RATE,	5,		CFGF_NONE),
			CFG_INT		(SETTING_SYS_MON_UPLOAD_SIZE,	10,		CFGF_NONE),
			CFG_STR_LIST(SETTING_SYS_MON_METRICS,	"{*}",		CFGF_NONE),

			/* Static location settings */
			CFG_BOOL	(SETTING_USE_STATIC_LOCATION,	cfg_true,	CFGF_NONE),
			CFG_FLOAT	(SETTING_LATITUDE,		0.0,		CFGF_NONE),
			CFG_FLOAT	(SETTING_LONGITUDE,		0.0,		CFGF_NONE),
			CFG_FLOAT	(SETTING_ALTITUDE,		0.0,		CFGF_NONE),
			/* Logging settings. */
			CFG_STR		(SETTING_LOG_LEVEL,	LOG_LEVEL_ERROR_STR,CFGF_NONE),
			CFG_BOOL	(SETTING_LOG_CONSOLE,	cfg_false,		CFGF_NONE),

			/* Needed for unknown settings. */
			CFG_STR		(SETTING_UNKNOWN,		NULL,			CFGF_NONE),
			CFG_END()
	};

	if (!file_exists(filename)) {
		log_error("File '%s' does not exist.", filename);
		return -1;
	}

	if (!file_readable(filename)) {
		log_error("File '%s' cannot be read.", filename);
		return -1;
	}

	cfg_path = filename;
	cfg = cfg_init(opts, CFGF_IGNORE_UNKNOWN);
	if (!cfg) {
		log_error("Failed initializing configuration file parser: %s (%d)",
			strerror(errno), errno);
		return -1;
	}

	/* Custom logging, rather than default Confuse stderr logging */
	cfg_set_error_function(cfg, conf_error_func);

	cfg_set_validate_func(cfg, SETTING_VENDOR_ID, cfg_check_vendor_id);
	cfg_set_validate_func(cfg, SETTING_DEVICE_TYPE, cfg_check_device_type);
	cfg_set_validate_func(cfg, SETTING_FW_VERSION, cfg_check_fw_version);
	cfg_set_validate_func(cfg, SETTING_DESCRIPTION, cfg_check_description);
	cfg_set_validate_func(cfg, SETTING_CONTACT, cfg_check_contact);
	cfg_set_validate_func(cfg, SETTING_LOCATION, cfg_check_location);
	cfg_set_validate_func(cfg, SETTING_RM_URL, cfg_check_rm_url);
	cfg_set_validate_func(cfg, SETTING_CLIENT_CERT_PATH, cfg_check_cert_path);
	cfg_set_validate_func(cfg, SETTING_RECONNECT_TIME, cfg_check_reconnect_time);
	cfg_set_validate_func(cfg, SETTING_KEEPALIVE_RX, cfg_check_keepalive_rx);
	cfg_set_validate_func(cfg, SETTING_KEEPALIVE_TX, cfg_check_keepalive_tx);
	cfg_set_validate_func(cfg, SETTING_WAIT_TIMES, cfg_check_wait_times);
	cfg_set_validate_func(cfg, SETTING_FW_DOWNLOAD_PATH, cfg_check_fw_download_path);
	cfg_set_validate_func(cfg, SETTING_SYS_MON_SAMPLE_RATE,
			cfg_check_sys_mon_sample_rate);
	cfg_set_validate_func(cfg, SETTING_SYS_MON_UPLOAD_SIZE,
			cfg_check_sys_mon_upload_size);
	cfg_set_validate_func(cfg, SETTING_SYS_MON_METRICS, cfg_check_sys_mon_metrics);
	cfg_set_validate_func(cfg, SETTING_LATITUDE, cfg_check_latitude);
	cfg_set_validate_func(cfg, SETTING_LONGITUDE, cfg_check_longitude);

	/* Parse the configuration file. */
	switch (cfg_parse(cfg, filename)) {
		case CFG_FILE_ERROR:
			log_error("Configuration file '%s' could not be read: %s\n", filename,
					strerror(errno));
			return -1;
		case CFG_SUCCESS:
			break;
		case CFG_PARSE_ERROR:
			log_error("Error parsing configuration file '%s'\n", filename);
			return -1;
	}

	return fill_connector_config(cc_cfg);
}

/*
 * close_configuration() - Close configuration and free internal vars
 *
 * Note that after calling this method, the configuration must be parsed again
 * from the configuration file using 'parse_configuration()' method before
 * trying to use any other configuration function.
 */
void close_configuration(void)
{
	cfg_free(cfg);
}

/*
 * free_configuration() - Release the configuration var
 *
 * @cc_cfg:	General configuration struct (cc_cfg_t) holding the
 * 			current connector configuration.
 */
void free_configuration(cc_cfg_t *cc_cfg)
{
	if (cc_cfg != NULL) {
		unsigned int i;

		free(cc_cfg->device_type);
		cc_cfg->device_type = NULL;
		free(cc_cfg->fw_version_src);
		cc_cfg->fw_version_src = NULL;
		free(cc_cfg->fw_version);
		cc_cfg->fw_version = NULL;
		free(cc_cfg->description);
		cc_cfg->description = NULL;
		free(cc_cfg->contact);
		cc_cfg->contact = NULL;
		free(cc_cfg->location);
		cc_cfg->location = NULL;
		free(cc_cfg->url);
		cc_cfg->url = NULL;
		free(cc_cfg->client_cert_path);
		cc_cfg->client_cert_path = NULL;

		for (i = 0; i < cc_cfg->n_vdirs; i++) {
			cc_cfg->vdirs[i].name = NULL;
			cc_cfg->vdirs[i].path = NULL;
		}
		free(cc_cfg->vdirs);
		cc_cfg->vdirs = 0;

		free(cc_cfg->fw_download_path);
		cc_cfg->fw_download_path = NULL;

		for (i = 0; i < cc_cfg->n_sys_mon_metrics; i++) {
			free(cc_cfg->sys_mon_metrics[i]);
		}
		free(cc_cfg->sys_mon_metrics);

		free(cc_cfg);
		cc_cfg = NULL;
	}
}

/*
 * get_configuration() - Retrieve current connector configuration
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) that will hold
 * 			the current connector configuration.
 *
 * Return: 0 if the configuration is retrieved successfully, -1 otherwise.
 */
int get_configuration(cc_cfg_t *cc_cfg)
{
	/* Check if configuration is initialized. */
	if (cfg == NULL) {
		log_error("%s", "Configuration is not initialized");
		return -1;
	}

	return fill_connector_config(cc_cfg);
}

/*
 * get_confuse_configuration() - Retrieve current confuse connector configuration
 *
 * Return: Struct (cfg_t) that holds the current connector configuration.
 */
cfg_t *get_confuse_configuration(void)
{
	return cfg;
}

/*
 * apply_configuration() - Apply provided configuration
 *
 * Return: 0 if success,
 *	   1 if there was any error with the provided values,
 *	   2 if there was an error writing to the file.
 */
int apply_configuration(cc_cfg_t *cc_cfg)
{
	if (fill_connector_config(cc_cfg) != 0)
		return 1;

	if (save_configuration(cc_cfg) != 0)
		return 2;

	return 0;
}

/*
 * save_configuration() - Save the given connector configuration
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) containing
 *			the connector settings to save.
 *
 * Return: 0 if the configuration is saved successfully, -1 otherwise.
 */
int save_configuration(cc_cfg_t *cc_cfg)
{
	FILE *fp;

	/* Check if configuration is initialized. */
	if (cfg == NULL) {
		log_error("%s", "Configuration is not initialized");
		goto error;
	}

	/* Set the current configuration. */
	if (set_connector_config(cc_cfg)) {
		log_error("%s", "Error setting configuration values");
		goto error;
	}

	/* Write configuration to file. */
	fp = fopen(cfg_path, "w+");
	if (fp == NULL) {
		log_error("Error opening configuration file to write '%s'", cfg_path);
		goto error;
	}
	cfg_print(cfg, fp);
	fclose(fp);

	return 0;

error:
	return -1;
}

static char *get_fw_version(const char *const value) {
	char data[256] = {0};
	const char *path = NULL;

	if (value == NULL || strlen(value) == 0)
		path = FW_VERSION_FILE_DEFAULT;
	else if (!strncmp(value, FW_VERSION_FILE_PREFIX, strlen(FW_VERSION_FILE_PREFIX)))
		path = value + strlen(FW_VERSION_FILE_PREFIX);

	/* If a version number is specified, just return it */
	if (!path)
		return strdup(value);

	if (read_file_line(path, data, sizeof(data)) != 0) {
		/* Return if we already read from default location */
		if (value == NULL || strlen(value) == 0)
			return NULL;
		/* Try to read from default location */
		if (read_file_line(FW_VERSION_FILE_DEFAULT, data, sizeof(data)) <= 0)
			return NULL;
	}

	data[strlen(data) - 1] = 0;

	{
		regex_t regex;
		char msgbuf[100];
		char *tmp = NULL;
		int ret, version_group = 2, version_len;
		regmatch_t groups[version_group + 1];

		ret = regcomp(&regex, "^([A-Za-z0-9_-]+[ =]{1})?([0-9\\.]+)$", REG_EXTENDED);
		if (ret != 0) {
			regerror(ret, &regex, msgbuf, sizeof(msgbuf));
			log_error("Could not compile regex: %s (%d)", msgbuf, ret);
			goto done;
		}
		ret = regexec(&regex, data, version_group + 1, groups, 0);
		if (ret != 0) {
			regerror(ret, &regex, msgbuf, sizeof(msgbuf));
			log_error("Invalid firmware version format '%s': %s (%d)", data, msgbuf, ret);
			goto done;
		}

		if (groups[version_group].rm_so == -1) {
			log_error("Invalid firmware version format '%s'", data);
			goto done;
		}

		version_len = groups[version_group].rm_eo - groups[version_group].rm_so;

		tmp = calloc(version_len + 1, sizeof(*tmp));
		if (!tmp) {
			log_error("Cannot get firmware version: %s", "Out of memory");
			goto done;
		}

		strncpy(tmp, data + groups[version_group].rm_so, version_len);
done:
		regfree(&regex);

		return tmp;
	}
}

/*
 * fill_connector_config() - Fill the connector configuration struct
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the
 * 			settings parsed from the configuration will be saved.
 *
 * Return: 0 if the configuration is filled successfully, -1 otherwise.
 */
static int fill_connector_config(cc_cfg_t *cc_cfg)
{
	if (check_cfg())
		return -1;

	/* Fill general settings. */
	cc_cfg->vendor_id = strtoul(cfg_getstr(cfg, SETTING_VENDOR_ID), NULL, 16);
	cc_cfg->device_type = strdup(cfg_getstr(cfg, SETTING_DEVICE_TYPE));
	cc_cfg->fw_version_src = strdup(cfg_getstr(cfg, SETTING_FW_VERSION));
	free(cc_cfg->fw_version);
	cc_cfg->fw_version = get_fw_version(cc_cfg->fw_version_src);
	log_debug("Firmware version: %s", cc_cfg->fw_version);

	cc_cfg->description = strdup(cfg_getstr(cfg, SETTING_DESCRIPTION));
	cc_cfg->contact = strdup(cfg_getstr(cfg, SETTING_CONTACT));
	cc_cfg->location = strdup(cfg_getstr(cfg, SETTING_LOCATION));

	/* Fill connection settings. */
	cc_cfg->url = strdup(cfg_getstr(cfg, SETTING_RM_URL));
	cc_cfg->client_cert_path = strdup(cfg_getstr(cfg, SETTING_CLIENT_CERT_PATH));
	cc_cfg->enable_reconnect = (ccapi_bool_t) cfg_getbool(cfg, SETTING_ENABLE_RECONNECT);
	cc_cfg->reconnect_time = cfg_getint(cfg, SETTING_RECONNECT_TIME);
	cc_cfg->keepalive_rx = cfg_getint(cfg, SETTING_KEEPALIVE_RX);
	cc_cfg->keepalive_tx = cfg_getint(cfg, SETTING_KEEPALIVE_TX);
	cc_cfg->wait_count = cfg_getint(cfg, SETTING_WAIT_TIMES);

	/* Fill services settings. */
	cc_cfg->services = 0;
	if (cfg_getbool(cfg, ENABLE_FS_SERVICE)) {
		cc_cfg->services = cc_cfg->services | FS_SERVICE;
		get_virtual_directories(cfg, cc_cfg);
	}

	if (cfg_getbool(cfg, ENABLE_SYSTEM_MONITOR))
		cc_cfg->services = cc_cfg->services | SYS_MONITOR_SERVICE;

	cc_cfg->fw_download_path = strdup(cfg_getstr(cfg, SETTING_FW_DOWNLOAD_PATH));

	/* Fill On the fly setting */
	cc_cfg->on_the_fly = (ccapi_bool_t) cfg_getbool(cfg, SETTING_ON_THE_FLY);

	/* Fill system monitor settings. */
	cc_cfg->sys_mon_sample_rate = cfg_getint(cfg, SETTING_SYS_MON_SAMPLE_RATE);
	cc_cfg->sys_mon_num_samples_upload = cfg_getint(cfg, SETTING_SYS_MON_UPLOAD_SIZE);
	get_sys_mon_metrics(cfg, cc_cfg);

	/* Fill static location settings. */
	cc_cfg->use_static_location = (ccapi_bool_t) cfg_getbool(cfg, SETTING_USE_STATIC_LOCATION);
	cc_cfg->latitude = (float) cfg_getfloat(cfg, SETTING_LATITUDE);
	cc_cfg->longitude = (float) cfg_getfloat(cfg, SETTING_LONGITUDE);
	cc_cfg->altitude = (float) cfg_getfloat(cfg, SETTING_ALTITUDE);

	/* Fill logging settings. */
	cc_cfg->log_level = get_log_level();
	cc_cfg->log_console = (ccapi_bool_t) cfg_getbool(cfg, SETTING_LOG_CONSOLE);

	return 0;
}

/*
 * set_connector_config() - Sets the connector configuration as current
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) containing the
 * 			connector configuration.
 *
 * Return: 0 if the configuration is set successfully, -1 otherwise.
 */
static int set_connector_config(cc_cfg_t *cc_cfg)
{
	unsigned int i;
	char vid_str[11]; /* "0x" + 8 chars + '\0' */

	/* Set general settings. */
	snprintf(vid_str, sizeof vid_str, "0x%08"PRIX32, cc_cfg->vendor_id);
	cfg_setstr(cfg, SETTING_VENDOR_ID, vid_str);
	cfg_setstr(cfg, SETTING_DEVICE_TYPE, cc_cfg->device_type);
	cfg_setstr(cfg, SETTING_FW_VERSION, cc_cfg->fw_version_src);
	cfg_setstr(cfg, SETTING_DESCRIPTION, cc_cfg->description);
	cfg_setstr(cfg, SETTING_CONTACT, cc_cfg->contact);
	cfg_setstr(cfg, SETTING_LOCATION, cc_cfg->location);

	/* Fill connection settings. */
	cfg_setstr(cfg, SETTING_RM_URL, cc_cfg->url);
	cfg_setstr(cfg, SETTING_CLIENT_CERT_PATH, cc_cfg->client_cert_path);
	cfg_setbool(cfg, SETTING_ENABLE_RECONNECT, (cfg_bool_t) cc_cfg->enable_reconnect);
	cfg_setint(cfg, SETTING_RECONNECT_TIME, cc_cfg->reconnect_time);
	cfg_setint(cfg, SETTING_KEEPALIVE_RX, cc_cfg->keepalive_rx);
	cfg_setint(cfg, SETTING_KEEPALIVE_TX, cc_cfg->keepalive_tx);
	cfg_setint(cfg, SETTING_WAIT_TIMES, cc_cfg->wait_count);

	/* Fill services settings. */
	cfg_setbool(cfg, ENABLE_FS_SERVICE, cc_cfg->services & FS_SERVICE ? cfg_true : cfg_false);
	cfg_setbool(cfg, ENABLE_SYSTEM_MONITOR, cc_cfg->services & SYS_MONITOR_SERVICE ? cfg_true : cfg_false);
	cfg_setstr(cfg, SETTING_FW_DOWNLOAD_PATH, cc_cfg->fw_download_path);
	/* TODO: Set virtual directories */

	/* Fill system monitor settings. */
	cfg_setint(cfg, SETTING_SYS_MON_SAMPLE_RATE, cc_cfg->sys_mon_sample_rate);
	cfg_setint(cfg, SETTING_SYS_MON_UPLOAD_SIZE, cc_cfg->sys_mon_num_samples_upload);
	for (i = 0; i < cc_cfg->n_sys_mon_metrics; i++)
		cfg_setnstr(cfg, SETTING_SYS_MON_METRICS, cc_cfg->sys_mon_metrics[i], i);

	/* Fill static location settings. */
	cfg_setbool(cfg, SETTING_USE_STATIC_LOCATION, (cfg_bool_t) cc_cfg->use_static_location);
	cfg_setfloat(cfg, SETTING_LATITUDE, cc_cfg->latitude);
	cfg_setfloat(cfg, SETTING_LONGITUDE, cc_cfg->longitude);
	cfg_setfloat(cfg, SETTING_ALTITUDE, cc_cfg->altitude);

	/* Fill logging settings. */
	switch (cc_cfg->log_level) {
	case LOG_LEVEL_DEBUG:
		cfg_setstr(cfg, SETTING_LOG_LEVEL, LOG_LEVEL_DEBUG_STR);
		break;
	case LOG_LEVEL_INFO:
		cfg_setstr(cfg, SETTING_LOG_LEVEL, LOG_LEVEL_INFO_STR);
		break;
	default:
		cfg_setstr(cfg, SETTING_LOG_LEVEL, LOG_LEVEL_ERROR_STR);
		break;
	}
	cfg_setbool(cfg, SETTING_LOG_CONSOLE, (cfg_bool_t) cc_cfg->log_console);

	return 0;
}

/**
 * conf_error_func() - Error reporting function to send error to syslog
 *
 * @cfg:	The configuration with an error.
 * @format:	The format of the error to log.
 * @args:	Arguments of the error to log.
 */
static void conf_error_func(cfg_t *cfg, const char *format, va_list args)
{
	char fmt[256];

	if (cfg && cfg->filename && cfg->line)
		snprintf(fmt, sizeof(fmt), "[ERROR] %s:%d: %s", cfg->filename, cfg->line, format);
	else if (cfg && cfg->filename)
		snprintf(fmt, sizeof(fmt), "[ERROR] %s: %s", cfg->filename, format);
	else
		snprintf(fmt, sizeof(fmt), "[ERROR] %s", format);

	vsyslog(LOG_ERR, fmt, args);
}

/*
 * check_cfg() - Checks whether the parsed configuration is valid
 *
 * Return: 0 if the configuration is valid, -1 otherwise.
 */
static int check_cfg(void)
{
	/* Check general settings. */
	if (cfg_check_vendor_id(cfg, cfg_getopt(cfg, SETTING_VENDOR_ID)) != 0)
		return -1;
	if (cfg_check_device_type(cfg, cfg_getopt(cfg, SETTING_DEVICE_TYPE)) != 0)
		return -1;
	if (cfg_check_fw_version(cfg, cfg_getopt(cfg, SETTING_FW_VERSION)) != 0)
		return -1;
	if (cfg_check_description(cfg, cfg_getopt(cfg, SETTING_DESCRIPTION)) != 0)
		return -1;
	if (cfg_check_contact(cfg, cfg_getopt(cfg, SETTING_CONTACT)) != 0)
		return -1;
	if (cfg_check_location(cfg, cfg_getopt(cfg, SETTING_LOCATION)) != 0)
		return -1;

	/* Check connection settings. */
	if (cfg_check_rm_url(cfg, cfg_getopt(cfg, SETTING_RM_URL)) != 0)
		return -1;
	if (cfg_check_cert_path(cfg, cfg_getopt(cfg, SETTING_CLIENT_CERT_PATH)) != 0)
		return -1;
	if (cfg_check_reconnect_time(cfg, cfg_getopt(cfg, SETTING_RECONNECT_TIME)) != 0)
		return -1;
	if (cfg_check_keepalive_rx(cfg, cfg_getopt(cfg, SETTING_KEEPALIVE_RX)) != 0)
		return -1;
	if (cfg_check_keepalive_tx(cfg, cfg_getopt(cfg, SETTING_KEEPALIVE_TX)) != 0)
		return -1;
	if (cfg_check_wait_times(cfg, cfg_getopt(cfg, SETTING_WAIT_TIMES)) != 0)
		return -1;

	/* Check services settings. */
	if (cfg_check_fw_download_path(cfg, cfg_getopt(cfg, SETTING_FW_DOWNLOAD_PATH)) != 0)
		return -1;

	/* Check system monitor settings. */
	if (cfg_check_sys_mon_sample_rate(cfg, cfg_getopt(cfg, SETTING_SYS_MON_SAMPLE_RATE)) != 0)
		return -1;
	if (cfg_check_sys_mon_upload_size(cfg, cfg_getopt(cfg, SETTING_SYS_MON_UPLOAD_SIZE)) != 0)
		return -1;
	if (cfg_check_sys_mon_metrics(cfg, cfg_getopt(cfg, SETTING_SYS_MON_METRICS)) != 0)
		return -1;

	/* Check static location settings. */
	if (cfg_check_latitude(cfg, cfg_getopt(cfg, SETTING_LATITUDE)) != 0)
		return -1;
	if (cfg_check_longitude(cfg, cfg_getopt(cfg, SETTING_LONGITUDE)) != 0)
		return -1;
	if (cfg_check_float_range(cfg, cfg_getopt(cfg, SETTING_ALTITUDE), -100000, 100000) != 0)
		return -1;

	return 0;
}

/*
 * cfg_check_vendor_id() - Validate vendor_id in the configuration file
 *
 * @cfg:	The section where the vendor_id is defined.
 * @opt:	The vendor_id option.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_vendor_id(cfg_t *cfg, cfg_opt_t *opt)
{
	unsigned long value;
	char *endptr = NULL;
	char *val = cfg_opt_getnstr(opt, 0);

	if (val == NULL || strlen(val) == 0) {
		cfg_error(cfg, "Invalid %s: cannot be empty", opt->name);
		return -1;
	}

	value = strtoul(val, &endptr, 16);
	switch (errno) {
		case 0:
			if (*endptr != 0) {
				cfg_error(cfg, "Invalid %s (%s): value contains invalid characters",
						opt->name, val);
				return -1;
			}
			if (value == 0 || value >= SETTING_VENDOR_ID_MAX) {
				cfg_error(cfg, "Invalid %s (%s): value must be between 0 and 0x%08lX",
						opt->name, val, SETTING_VENDOR_ID_MAX);
				return -1;
			}
			break;
		case ERANGE:
			cfg_error(cfg, "Invalid %s (%s): value out of range", opt->name, val);
			return -1;
		default:
			break;
	}

	return 0;
}

/*
 * cfg_check_device_type() - Validate device_type in the configuration file
 *
 * @cfg:	The section where the device_type is defined.
 * @opt:	The device_type option.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_device_type(cfg_t *cfg, cfg_opt_t *opt)
{
	char *val = cfg_opt_getnstr(opt, 0);

	if (val == NULL || strlen(val) == 0) {
		cfg_error(cfg, "Invalid %s (%s): cannot be empty", opt->name, val);
		return -1;
	}
	if (strlen(val) > SETTING_DEVICE_TYPE_MAX) {
		cfg_error(cfg, "Invalid %s (%s): maximum length %d", opt->name, val, SETTING_DEVICE_TYPE_MAX);
		return -1;
	}

	return 0;
}

/*
 * cfg_check_fw_version() - Validate firmware_version in the configuration file
 *
 * @cfg:	The section where the firmware_version is defined.
 * @opt:	The firmware_version option.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_fw_version(cfg_t *cfg, cfg_opt_t *opt)
{
	regex_t regex;
	char msgbuf[100];
	int error = 0;
	char *version_str = NULL;
	char *val = cfg_opt_getnstr(opt, 0);

	version_str = get_fw_version(val);
	if (version_str == NULL) {
		if (val == NULL || strlen(val) == 0)
			cfg_error(cfg, "Invalid %s (%s): cannot be empty", opt->name, val);
		else
			cfg_error(cfg, "Invalid %s (%s): Cannot get firmware version from file", opt->name, val);
		return -1;
	}

	error = regcomp(&regex, "^([0-9]+\\.){0,3}[0-9]+$", REG_EXTENDED);
	if (error != 0) {
		regerror(error, &regex, msgbuf, sizeof(msgbuf));
		cfg_error(cfg, "Could not compile regex: %s (%d)", msgbuf, error);
		error = -1;
		goto done;
	}
	error = regexec(&regex, version_str, 0, NULL, 0);
	if (error != 0) {
		regerror(error, &regex, msgbuf, sizeof(msgbuf));
		cfg_error(cfg, "Invalid %s (%s): %s (%d)", opt->name, val, msgbuf, error);
		error = -1;
	}

done:
	free(version_str);
	regfree(&regex);

	return error;
}

/*
 * cfg_check_rm_url() - Validate url in the configuration file
 *
 * @cfg:	The section where the url is defined.
 * @opt:	The url option.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_rm_url(cfg_t *cfg, cfg_opt_t *opt)
{
	char *val = cfg_opt_getnstr(opt, 0);
	if (val == NULL || strlen(val) == 0) {
		cfg_error(cfg, "Invalid %s (%s): cannot be empty", opt->name, val);
		return -1;
	}

	return 0;
}

/*
 * cfg_check_cert_path() - Validate certification path in the configuration file
 *
 * @cfg:	The section where the url is defined.
 * @opt:	The certification path option.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_cert_path(cfg_t *cfg, cfg_opt_t *opt)
{
	char *val = cfg_opt_getnstr(opt, 0);
	char *directory = NULL, *cert_path = NULL;
	int ret = 0;

	if (val == NULL || strlen(val) == 0) {
		cfg_error(cfg, "Invalid %s (%s): cannot be empty", opt->name, val);
		return -1;
	}

	cert_path = strdup(val);
	directory = dirname(cert_path);

	if (access(directory, R_OK | W_OK) < 0) {
		cfg_error(cfg,
				"Invalid %s (%s): directory does not exist or do not have R/W access",
				opt->name, directory);
		ret = -1;
	}

	free(cert_path);

	return ret;
}

/*
 * cfg_check_reconnect_time() - Check reconnect time is between 1 and 32767
 *
 * @cfg:	The section where the reconnect_time is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_reconnect_time(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_range(cfg, opt, SETTING_RECONNECT_TIME_MIN, SETTING_RECONNECT_TIME_MAX);
}

/*
 * cfg_check_keepalive_rx() - Check RX keep alive value is between 5 and 7200
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_keepalive_rx(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_range(cfg, opt, CCAPI_KEEPALIVES_RX_MIN, CCAPI_KEEPALIVES_RX_MAX);
}

/*
 * cfg_check_keepalive_tx() - Check TX keep alive value is between 5 and 7200
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_keepalive_tx(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_range(cfg, opt, CCAPI_KEEPALIVES_TX_MIN, CCAPI_KEEPALIVES_TX_MAX);
}

/*
 * cfg_check_wait_times() - Check wait time value is between 2 and 64
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_wait_times(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_range(cfg, opt, CCAPI_KEEPALIVES_WCNT_MIN, CCAPI_KEEPALIVES_WCNT_MAX);
}

/*
 * cfg_check_sys_mon_sample_rate() - Check system monitor sample rate value is between 1s and a year
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_sys_mon_sample_rate(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_range(cfg, opt, SETTING_SYS_MON_SAMPLE_RATE_MIN, SETTING_SYS_MON_SAMPLE_RATE_MAX);
}

/*
 * cfg_check_sys_mon_upload_size() - Check system monitor samples to store value is between 1 and 250
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_sys_mon_upload_size(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_range(cfg, opt, SETTING_SYS_MON_UPLOAD_SIZE_MIN, SETTING_SYS_MON_UPLOAD_SIZE_MAX);
}

/*
 * cfg_check_sys_mon_metrics() - Check system monitor metrics list
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_sys_mon_metrics(cfg_t *cfg, cfg_opt_t *opt)
{
	if (cfg_opt_size(opt) < 1) {
		cfg_error(cfg, "Invalid %s: list cannot be empty", opt->name);
		return -1;
	}

	return 0;
}

/*
 * cfg_check_latitude() - Check latitude value is between -90.0 and 90.0
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_latitude(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_float_range(cfg, opt, SETTING_LATITUDE_MIN, SETTING_LATITUDE_MAX);
}

/*
 * cfg_check_longitude() - Check longitude value is between -180.0 and 180.0
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_longitude(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_float_range(cfg, opt, SETTING_LONGITUDE_MIN, SETTING_LONGITUDE_MAX);
}

/*
 * cfg_check_range() - Check a parameter value is between given range
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 * @min:	Minimum value of the parameter.
 * @max:	Maximum value of the parameter.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_range(cfg_t *cfg, cfg_opt_t *opt, uint32_t min, uint32_t max)
{
	unsigned long val = cfg_opt_getnint(opt, 0);

	if (val > max || val < min) {
		cfg_error(cfg, "Invalid %s (%d): value must be between %d and %d", opt->name, val, min, max);
		return -1;
	}

	return 0;
}

/*
 * cfg_check_float_range() - Check a parameter float value is between given range
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 * @min:	Minimum value of the parameter.
 * @max:	Maximum value of the parameter.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_float_range(cfg_t *cfg, cfg_opt_t *opt, float min, float max)
{
	float val = cfg_opt_getnfloat(opt, 0);

	if (val > max || val < min) {
		cfg_error(cfg, "Invalid %s (%f): value must be between %f and %f", opt->name, val, min, max);
		return -1;
	}

	return 0;
}

/*
 * cfg_check_description() - Check description value length is in range
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_description(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_string_length(cfg, opt, SETTING_DESCRIPTION_MIN, SETTING_DESCRIPTION_MAX);
}

/*
 * cfg_check_contact() - Check contact value length is in range
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_contact(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_string_length(cfg, opt, SETTING_CONTACT_MIN, SETTING_CONTACT_MAX);
}

/*
 * cfg_check_location() - Check location value length is in range
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_location(cfg_t *cfg, cfg_opt_t *opt)
{
	return cfg_check_string_length(cfg, opt, SETTING_LOCATION_MIN, SETTING_LOCATION_MAX);
}

/*
 * cfg_check_string_length() - Check the length of a string is in range
 *
 * @cfg:	The section where the option is defined.
 * @opt:	The option to check.
 * @min: 	The string minimum length.
 * @max:	The string maximum length. 0 to unlimited.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_string_length(cfg_t *cfg, cfg_opt_t *opt, uint16_t min, uint16_t max)
{
	char *val = cfg_opt_getnstr(opt, 0);

	if ((val == NULL) || ((strlen(val) == 0) && (min > 0))) {
		cfg_error(cfg, "Invalid %s (%s): cannot be empty", opt->name, val);
		return -1;
	}
	if (strlen(val) < min) {
		cfg_error(cfg, "Invalid %s (%s): cannot be shorter than %d character(s)", opt->name, val, min);
		return -1;
	}
	if (max != 0 && strlen(val) > max) {
		cfg_error(cfg, "Invalid %s (%s): cannot be longer than %d character(s)", opt->name, val, max);
		return -1;
	}

	return 0;
}

/*
 * cfg_check_fw_download_path() - Check firmware download path is an existing dir
 *
 * @cfg:	The section were the option is defined.
 * @opt:	The option to check.
 *
 * @Return: 0 on success, any other value otherwise.
 */
static int cfg_check_fw_download_path(cfg_t *cfg, cfg_opt_t *opt)
{
	char *val = cfg_opt_getnstr(opt, 0);

	if (val == NULL || strlen(val) == 0) {
		cfg_error(cfg, "Invalid %s (%s): cannot be empty", opt->name, val);
		return -1;
	}

	if (access(val, R_OK | W_OK) < 0) {
		cfg_error(cfg,
				"Invalid %s (%s): directory does not exist or do not have R/W access",
				opt->name, val);
		return -1;
	}

	return 0;
}

/*
 * get_virtual_directories() - Get the list of virtual directories
 *
 * @cfg:	Configuration struct from config file to read the virtual directories
 * @cc_cfg:	Cloud Connector configuration to store the virtual directories
 *
 * @Return: 0 on success, any other value otherwise.
 */
static void get_virtual_directories(cfg_t *const cfg, cc_cfg_t *const cc_cfg)
{
	unsigned int i;
	cfg_t *virtual_dir_cfg = cfg_getsec(cfg, GROUP_VIRTUAL_DIRS);

	free(cc_cfg->vdirs);

	cc_cfg->n_vdirs = cfg_size(virtual_dir_cfg, GROUP_VIRTUAL_DIR);

	cc_cfg->vdirs = calloc(cc_cfg->n_vdirs, sizeof(*cc_cfg->vdirs));
	if (cc_cfg->vdirs == NULL) {
		log_info("%s", "Cannot initialize virtual directories");
		cc_cfg->n_vdirs = 0;

		return;
	}

	for (i = 0; i < cc_cfg->n_vdirs; i++) {
		cfg_t *vdir_cfg = cfg_getnsec(virtual_dir_cfg, GROUP_VIRTUAL_DIR, i);

		cc_cfg->vdirs[i].name = cfg_getstr(vdir_cfg, SETTING_NAME);
		cc_cfg->vdirs[i].path = cfg_getstr(vdir_cfg, SETTING_PATH);
	}
}

/*
 * get_log_level() - Get the log level setting value
 *
 * @Return: The log level value.
 */
static int get_log_level(void)
{
	char *level = cfg_getstr(cfg, SETTING_LOG_LEVEL);

	if (level == NULL || strlen(level) == 0)
		return LOG_LEVEL_ERROR;
	if (strcmp(level, LOG_LEVEL_DEBUG_STR) == 0)
		return LOG_LEVEL_DEBUG;
	if (strcmp(level, LOG_LEVEL_INFO_STR) == 0)
		return LOG_LEVEL_INFO;

	return LOG_LEVEL_ERROR;
}

/*
 * get_sys_mon_metrics() - Get the list of system monitor metrics
 *
 * @cfg:	Configuration struct from config file to read the system monitor metrics
 * @cc_cfg:	Cloud Connector configuration to store the system monitor metrics
 */
static void get_sys_mon_metrics(cfg_t *const cfg, cc_cfg_t *const cc_cfg)
{
	unsigned int i;

	for (i = 0; i < cc_cfg->n_sys_mon_metrics; i++)
		free(cc_cfg->sys_mon_metrics[i]);
	free(cc_cfg->sys_mon_metrics);

	cc_cfg->n_sys_mon_metrics = cfg_size(cfg, SETTING_SYS_MON_METRICS);
	cc_cfg->sys_mon_metrics = calloc(cc_cfg->n_sys_mon_metrics, sizeof(*cc_cfg->sys_mon_metrics));
	if (cc_cfg->sys_mon_metrics == NULL) {
		log_info("%s", "Cannot initialize system monitor metrics");
		cc_cfg->n_sys_mon_metrics = 0;

		return;
	}

	for (i = 0; i < cc_cfg->n_sys_mon_metrics; i++) {
		cc_cfg->sys_mon_metrics[i] = strdup(cfg_getnstr(cfg, SETTING_SYS_MON_METRICS, i));
		if (cc_cfg->sys_mon_metrics[i] == NULL) {
			log_info("%s", "Cannot initialize system monitor metric");
			cc_cfg->n_sys_mon_metrics = i;

			return;
		}
		if (strcmp(ALL_METRICS, cc_cfg->sys_mon_metrics[i]) == 0) {
			cc_cfg->sys_mon_all_metrics = true;
		}
	}
}
