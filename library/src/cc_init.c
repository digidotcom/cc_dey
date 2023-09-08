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
#include <libdigiapix/network.h>
#include <libdigiapix/wifi.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "cc_firmware_update.h"
#include "cc_init.h"
#include "cc_logging.h"
#include "cc_system_monitor.h"
#include "network_utils.h"
#include "service_data_request.h"
#include "services.h"
#include "_utils.h"

#define DEVICE_ID_FORMAT	"%02hhX%02hhX%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX"

#define CCCS_CONFIG_FILE	"/etc/cccs.conf"

#define CONNECT_TIMEOUT		30

#define MAX_INC_TIME		5

static ccapi_tcp_start_error_t initialize_tcp_transport(const cc_cfg_t *const cc_cfg);

#ifdef ENABLE_RCI
extern ccapi_rci_service_t rci_service;
extern connector_remote_config_data_t rci_internal_data;
#endif /* ENABLE_RCI */
extern ccapi_receive_service_t receive_service;
extern ccapi_streaming_cli_service_t streaming_cli_service;

static volatile cc_status_t connection_status = CC_STATUS_DISCONNECTED;
static pthread_t reconnect_thread;
static bool reconnect_thread_valid;
static volatile bool stop_requested;
cc_cfg_t *cc_cfg = NULL;
#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
bool edp_cert_downloaded = false;
#endif /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */

/*
 * get_device_id_from_mac() - Generate a Device ID from a given MAC address
 *
 * @device_id:	Pointer to store the generated Device ID.
 * @mac_addr:	MAC address to generate the Device ID.
 *
 * Return: 0 on success, -1 otherwise.
 */
static int get_device_id_from_mac(uint8_t *const device_id, const uint8_t *const mac_addr)
{
	const char *const deviceid_file = "/etc/cccs.did";
	unsigned int const device_id_length = 16;
	FILE *fp = NULL;
	unsigned int n_items;

	memset(device_id, 0x00, device_id_length);

	fp = fopen(deviceid_file, "rb");
	if (fp != NULL) {
		n_items = fscanf(fp, DEVICE_ID_FORMAT, &device_id[0], &device_id[1],
				&device_id[2], &device_id[3], &device_id[4], &device_id[5],
				&device_id[6], &device_id[7], &device_id[8], &device_id[9],
				&device_id[10], &device_id[11], &device_id[12], &device_id[13],
				&device_id[14], &device_id[15]);
		fclose(fp);
		if (n_items == device_id_length)
			return 0;
	}

	if (mac_addr == NULL)
		return -1;

	device_id[8] = mac_addr[0];
	device_id[9] = mac_addr[1];
	device_id[10] = mac_addr[2];
	device_id[11] = 0xFF;
	device_id[12] = 0xFF;
	device_id[13] = mac_addr[3];
	device_id[14] = mac_addr[4];
	device_id[15] = mac_addr[5];

	fp = fopen(deviceid_file, "wb+");
	if (fp != NULL) {
		n_items = fprintf(fp, DEVICE_ID_FORMAT, device_id[0], device_id[1],
				device_id[2], device_id[3], device_id[4], device_id[5],
				device_id[6], device_id[7], device_id[8], device_id[9],
				device_id[10], device_id[11], device_id[12], device_id[13],
				device_id[14], device_id[15]);
		fclose(fp);
		if (n_items != device_id_length * 2 + 3)
			log_debug("%s", "Could not store Device ID");
	}

	return 0;
}

/**
 * fw_string_to_int() - Convert firmware version string into uint32_t
 *
 * @fw_wstring:		Firmware version string
 *
 * Return: The firmware version as a uint32_t
 */
static uint32_t fw_string_to_int(const char *fw_string)
{
	unsigned int fw_version[4] = {0};
	uint32_t fw_int = 0;
	int num_parts = sscanf(fw_string, "%u.%u.%u.%u", &fw_version[0],
			&fw_version[1], &fw_version[2], &fw_version[3]);

	if (num_parts == 0 || num_parts > 4)
		fw_int = 0;
	else
		fw_int = (fw_version[0] << 24) |
			 (fw_version[1] << 16) |
			 (fw_version[2] << 8)  |
			  fw_version[3];

	return fw_int;
}

/**
 * free_ccapi_start_struct() - Release the ccapi_start_t struct
 *
 * @ccapi_start:	CCAPI start struct (ccapi_start_t) to be released.
 */
static void free_ccapi_start_struct(ccapi_start_t *ccapi_start)
{
	if (ccapi_start == NULL)
		return;

	if (ccapi_start->service.firmware != NULL)
		free(ccapi_start->service.firmware->target.item);

	free(ccapi_start->service.firmware);
	free(ccapi_start->service.file_system);
	free(ccapi_start);
}

/*
 * create_ccapi_start_struct() - Create a ccapi_start_t struct from the given config
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the
 * 		settings parsed from the configuration file are stored.
 *
 * Return: The created ccapi_start_t struct with the data read from the
 * 	   configuration file.
 */
static ccapi_start_t *create_ccapi_start_struct(const cc_cfg_t *const cc_cfg)
{
	uint8_t mac_address[6];
	ccapi_start_t *start = calloc(1, sizeof(*start));

	if (start == NULL) {
		log_error("Error initializing Cloud connection: %s", "Out of memory");
		return NULL;
	}

	start->device_cloud_url = cc_cfg->url;
	start->device_type = cc_cfg->device_type;
	start->vendor_id = cc_cfg->vendor_id;
	start->status = NULL;
	if (get_device_id_from_mac(start->device_id, get_primary_mac_address(mac_address)) != 0) {
		log_error("Error initializing Cloud connection: %s", "Cannot calculate Device ID");
		goto error;
	}

	/* Initialize CLI service. */
	start->service.cli = NULL;

	/* Initialize Streaming CLI */
	start->service.streaming_cli = &streaming_cli_service,

	/* Initialize RCI service. */
	start->service.rci = NULL;
#ifdef ENABLE_RCI
	start->service.rci = &rci_service;
	rci_internal_data.firmware_target_zero_version = fw_string_to_int(cc_cfg->fw_version);
	rci_internal_data.vendor_id = cc_cfg->vendor_id;
	rci_internal_data.device_type = cc_cfg->device_type;
#endif /* ENABLE_RCI */

	/* Initialize data request service. */
	start->service.receive = &receive_service;

	/* Initialize short messaging. */
	start->service.sm = NULL;

	/* Initialize file system service. */
	if (cc_cfg->services & FS_SERVICE) {
		ccapi_filesystem_service_t *fs_service = calloc(1, sizeof(*fs_service));
		if (fs_service == NULL) {
			log_error("%s", "Cannot allocate memory to register File system service");
			goto error;
		}
		fs_service->access = NULL;
		fs_service->changed = NULL;
		start->service.file_system = fs_service;
	}

	/* Initialize firmware service. */
	if (init_fw_service(cc_cfg->fw_version, &start->service.firmware) != 0)
		goto error;

	return start;

error:
	free_ccapi_start_struct(start);
	return NULL;
}

/*
 * initialize_ccapi() - Initialize CCAPI layer
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the settings parsed
 *		from the configuration file are stored.
 *
 * Return: CCAPI_START_ERROR_NONE on success, any other ccapi_start_error_t
 * 	   otherwise.
 */
static ccapi_start_error_t initialize_ccapi(const cc_cfg_t *const cc_cfg)
{
	ccapi_start_error_t error;
	ccapi_start_t *start_st = create_ccapi_start_struct(cc_cfg);

	if (start_st == NULL)
		return CCAPI_START_ERROR_NULL_PARAMETER;

	error = ccapi_start(start_st);
	if (error != CCAPI_START_ERROR_NONE)
		log_debug("Error initializing Cloud connection: %d", error);

	free_ccapi_start_struct(start_st);

	return error;
}

/**
 * setup_virtual_dirs() - Add defined virtual directories
 *
 * @vdirs:	List of virtual directories
 * @n_vdirs:	Number of elements in the list
 *
 * Return: 0 on success, 1 otherwise.
 */
static int setup_virtual_dirs(const vdir_t *const vdirs, int n_vdirs)
{
	int error = 0;
	int i;

	for (i = 0; i < n_vdirs; i++) {
		const vdir_t *v_dir = vdirs + i;
		ccapi_fs_error_t fs_error = ccapi_fs_add_virtual_dir(v_dir->name, v_dir->path);

		switch (fs_error) {
			case CCAPI_FS_ERROR_NONE:
				log_info("New virtual directory '%s' (%s)", v_dir->name, v_dir->path);
				break;
			case CCAPI_FS_ERROR_ALREADY_MAPPED:
				log_debug("Virtual directory '%s' (%s) already mapped", v_dir->name, v_dir->path);
				break;
			case CCAPI_FS_ERROR_INVALID_PATH:
			case CCAPI_FS_ERROR_NOT_A_DIR:
				log_warning("Error adding virtual directory '%s' (%s) does not exist or is not a directory (%d)", v_dir->name, v_dir->path, fs_error);
				break;
			default:
				error = 1;
				log_error("Error adding virtual directory '%s' (%s), error %d", v_dir->name, v_dir->path, fs_error);
				break;
		}
	}

	return error;
}

cc_init_error_t init_cloud_connection(const char *config_file)
{
	int log_options = LOG_CONS | LOG_NDELAY | LOG_PID;
	ccapi_start_error_t ccapi_error;
	cc_init_error_t ret = CC_INIT_ERROR_NONE;

	stop_requested = false;

	cc_cfg = calloc(1, sizeof(cc_cfg_t));
	if (cc_cfg == NULL) {
		log_error("Cannot allocate memory for configuration (errno %d: %s)",
				errno, strerror(errno));
		return CC_INIT_ERROR_INSUFFICIENT_MEMORY;
	}

	if (parse_configuration(config_file ? config_file : CCCS_CONFIG_FILE, cc_cfg) != 0) {
		ret = CC_INIT_ERROR_PARSE_CONFIGURATION;
		goto error;
	}

	closelog();
	if (cc_cfg->log_console)
		log_options = log_options | LOG_PERROR;
	if (init_logger(cc_cfg->log_level, log_options, NULL)) {
		log_error("%s", "Failed to initialize logging");
		ret = CC_INIT_ERROR_UNKOWN;
		goto error;
	}

	ccapi_error = initialize_ccapi(cc_cfg);
	switch(ccapi_error) {
		case CCAPI_START_ERROR_NONE:
			break;
		case CCAPI_START_ERROR_NULL_PARAMETER:
			ret = CC_INIT_CCAPI_START_ERROR_NULL_PARAMETER;
			goto error;
		case CCAPI_START_ERROR_INVALID_VENDORID:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_VENDORID;
			goto error;
		case CCAPI_START_ERROR_INVALID_DEVICEID:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_DEVICEID;
			goto error;
		case CCAPI_START_ERROR_INVALID_URL:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_URL;
			goto error;
		case CCAPI_START_ERROR_INVALID_DEVICETYPE:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_DEVICETYPE;
			goto error;
		case CCAPI_START_ERROR_INVALID_CLI_REQUEST_CALLBACK:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_CLI_REQUEST_CALLBACK;
			goto error;
		case CCAPI_START_ERROR_INVALID_RCI_REQUEST_CALLBACK:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_RCI_REQUEST_CALLBACK;
			goto error;
		case CCAPI_START_ERROR_INVALID_FIRMWARE_INFO:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_FIRMWARE_INFO;
			goto error;
		case CCAPI_START_ERROR_INVALID_FIRMWARE_DATA_CALLBACK:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_FIRMWARE_DATA_CALLBACK;
			goto error;
		case CCAPI_START_ERROR_INVALID_SM_ENCRYPTION_CALLBACK:
			ret = CC_INIT_CCAPI_START_ERROR_INVALID_SM_ENCRYPTION_CALLBACK;
			goto error;
		case CCAPI_START_ERROR_INSUFFICIENT_MEMORY:
			ret = CC_INIT_CCAPI_START_ERROR_INSUFFICIENT_MEMORY;
			goto error;
		case CCAPI_START_ERROR_THREAD_FAILED:
			ret = CC_INIT_CCAPI_START_ERROR_THREAD_FAILED;
			goto error;
		case CCAPI_START_ERROR_LOCK_FAILED:
			ret = CC_INIT_CCAPI_START_ERROR_LOCK_FAILED;
			goto error;
		case CCAPI_START_ERROR_ALREADY_STARTED:
			ret = CC_INIT_CCAPI_START_ERROR_ALREADY_STARTED;
			goto error;
		default:
			ret = CC_INIT_ERROR_UNKOWN;
			goto error;
	}

	if (register_builtin_requests() != CCAPI_RECEIVE_ERROR_NONE) {
		ret = CC_INIT_ERROR_REG_BUILTIN_REQUESTS;
		goto error;
	}

	if (setup_virtual_dirs(cc_cfg->vdirs, cc_cfg->n_vdirs) != 0) {
		ret = CC_INIT_ERROR_ADD_VIRTUAL_DIRECTORY;
		goto error;
	}

	return CC_INIT_ERROR_NONE;

error:
	free_configuration(cc_cfg);
	cc_cfg = NULL;

	return ret;
}

/*
 * set_cloud_connection_status() - Configure the status of the connection
 *
 * @status:	The new connection status.
 */
static void set_cloud_connection_status(cc_status_t status)
{
	connection_status = status;
}

/**
 * calculate_reconnect_time() - Calculates the reconnect time.
 *
 * This function calculates the reconnect time based on the configured value,
 * and adding a random value between 0 and MAX_INC_TIME.
 *
 * Returns: The calculated time.
 */
static int calculate_reconnect_time(void)
{
	int reconnect_time = cc_cfg->reconnect_time;
	int increment;

	do {
		increment = rand() / (RAND_MAX / (MAX_INC_TIME + 1));
	} while (increment > MAX_INC_TIME);

	return reconnect_time + increment;
}

/*
 * reconnect_threaded() - Perform a manual reconnection in a new thread
 *
 * @unused:	Unused parameter.
 */
static void *reconnect_threaded(void *unused)
{
	int reconnect_time = calculate_reconnect_time();

	UNUSED_ARGUMENT(unused);

#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
	if (edp_cert_downloaded) {
		log_info("%s", "Downloaded certificate, reconnecting...");
		edp_cert_downloaded = false;
	} else
#endif /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */
	{
		log_info("Disconnected, attempting to reconnect in %d seconds", reconnect_time);
		sleep(reconnect_time);
	}

	initialize_tcp_transport(cc_cfg);

	return NULL;
}

/**
 * tcp_reconnect_cb() - Callback to tell if Cloud Connector should reconnect
 *
 * @cause:	Reason of the disconnection (disconnection, redirection, missing
 * 		keep alive, or any other data error).
 *
 * Return: CCAPI_TRUE to reconnect immediately, CCAPI_FALSE otherwise.
 */
static ccapi_bool_t tcp_reconnect_cb(ccapi_tcp_close_cause_t cause)
{
	pthread_attr_t attr;
	int error;

	log_debug("Reconnection, cause %d", cause);

	if (cause == CCAPI_TCP_CLOSE_REDIRECTED)
		return CCAPI_TRUE;

	log_info("%s", "Disconnected from Remote Manager");

	if (reconnect_thread_valid) {
		pthread_cancel(reconnect_thread);
		pthread_join(reconnect_thread, NULL);
	}

	reconnect_thread_valid = false;

#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
	/*
	 * Retry a connection if:
	 *   * reconnect is enabled
	 *   * client certificate path has just been downloaded
	 */
	if (!cc_cfg->enable_reconnect && !edp_cert_downloaded) {
#else /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */
	if (!cc_cfg->enable_reconnect) {
#endif /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */
		set_cloud_connection_status(CC_STATUS_DISCONNECTED);
		return CCAPI_FALSE;
	}

	set_cloud_connection_status(CC_STATUS_CONNECTING);

	/* Always return CCAPI_FALSE, to "manually" start the connection again
	 * in another thread after the configured timeout.
	 * Do not return CCAPI_TRUE, it will immediately and automatically
	 * connect again (without any kind of timeout).
	 */
	error = pthread_attr_init(&attr);
	if (error != 0) {
		/* On Linux this function always succeeds. */
		log_error("Unable to reconnect, cannot create reconnect thread: pthread_attr_init() error %d",
				error);
		return CCAPI_FALSE;
	}

	reconnect_thread_valid = pthread_create(&reconnect_thread, NULL, reconnect_threaded, NULL);
	if (reconnect_thread_valid != 0) {
		log_error("Unable to reconnect, cannot create reconnect thread: pthread_create() error %d",
				error);
		goto error;
	}

	return CCAPI_FALSE;

error:
	pthread_attr_destroy(&attr);

	return CCAPI_FALSE;
}

/**
 * is_zero_array() - Checks if an array is all zeros
 *
 * @array:	Array to be checked
 * @size:	Size of the array in bytes
 *
 * Return: 1 if the array is all zeros, 0 otherwise.
 */
static int is_zero_array(const uint8_t *array, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		if (array[i] != 0)
			return 0;

	return 1;
}

/*
 * create_ccapi_tcp_start_info_struct() - Generate a ccapi_tcp_info_t struct
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the
 * 		settings parsed from the configuration file are stored.
 *
 * @tcp_info:	A ccapi_start_t struct to fill with the read data from the
 *		configuration file.
 *
 * Return: 0 on success, 1 otherwise.
 */
static int create_ccapi_tcp_start_info_struct(const cc_cfg_t *const cc_cfg, ccapi_tcp_info_t *tcp_info)
{
	net_state_t active_interface;

	tcp_info->callback.close = NULL;
	tcp_info->callback.close = tcp_reconnect_cb;

	tcp_info->callback.keepalive = NULL;
	tcp_info->connection.max_transactions = CCAPI_MAX_TRANSACTIONS_UNLIMITED;
	tcp_info->connection.password = NULL;
	tcp_info->connection.start_timeout = CONNECT_TIMEOUT;
	tcp_info->connection.ip.type = CCAPI_IPV4;

	if (get_main_iface_info(cc_cfg->url, &active_interface) != 0)
		return 1;

	/*
	 * Some interfaces return a null MAC address (like ppp used by some
	 * cellular modems). In those cases assume a WAN connection
	 */
	if (is_zero_array(active_interface.mac, sizeof(active_interface.mac))) {
		tcp_info->connection.type = CCAPI_CONNECTION_WAN;
		tcp_info->connection.info.wan.link_speed = 0;
		tcp_info->connection.info.wan.phone_number = "*99#";
	} else {
		tcp_info->connection.type = CCAPI_CONNECTION_LAN;
		if (ldx_wifi_iface_exists(active_interface.name))
			tcp_info->connection.type = CCAPI_CONNECTION_WIFI;
		memcpy(tcp_info->connection.info.lan.mac_address,
				active_interface.mac,
				sizeof(tcp_info->connection.info.lan.mac_address));
	}
	memcpy(tcp_info->connection.ip.address.ipv4, active_interface.ipv4,
			sizeof(tcp_info->connection.ip.address.ipv4));

	tcp_info->keepalives.rx = cc_cfg->keepalive_rx;
	tcp_info->keepalives.tx = cc_cfg->keepalive_tx;
	tcp_info->keepalives.wait_count = cc_cfg->wait_count;

	return 0;
}

/*
 * initialize_tcp_transport() - Start TCP transport
 *
 * @cc_cfg:	Connector configuration struct (cc_cfg_t) where the settings parsed
 * 		from the configuration file are stored.
 *
 * Return: CCAPI_TCP_START_ERROR_NONE on success, any other
 * 	   capi_tcp_start_error_t otherwise.
 */
static ccapi_tcp_start_error_t initialize_tcp_transport(
		const cc_cfg_t *const cc_cfg)
{
	ccapi_tcp_info_t tcp_info = {{ 0 }};
	ccapi_tcp_start_error_t error = CCAPI_TCP_START_ERROR_TIMEOUT;
	bool retry = false;

	set_cloud_connection_status(CC_STATUS_CONNECTING);
	do {
		if (retry) {
			int reconnect_time = calculate_reconnect_time();
			log_info("Failed to connect (%d), retrying in %d seconds", error, reconnect_time);
			sleep(reconnect_time);
		}

		if (create_ccapi_tcp_start_info_struct(cc_cfg, &tcp_info) == 0)
			error = ccapi_start_transport_tcp(&tcp_info);

		retry = cc_cfg->enable_reconnect
				&& error != CCAPI_TCP_START_ERROR_NONE
				&& error != CCAPI_TCP_START_ERROR_ALREADY_STARTED;
	} while (retry && !stop_requested);

	if (error != CCAPI_TCP_START_ERROR_NONE && error != CCAPI_TCP_START_ERROR_ALREADY_STARTED) {
		log_debug("%s: failed with error %d", __func__, error);
		if (error != CCAPI_TCP_START_ERROR_ALREADY_STARTED)
			set_cloud_connection_status(CC_STATUS_DISCONNECTED);
	} else {
		set_cloud_connection_status(CC_STATUS_CONNECTED);
	}

	return error;
}

/**
 * signal_handler() - Manage signal received.
 *
 * @signum:	Received signal.
 */
static void signal_handler(int signum)
{
	log_debug("%s: Received signal %d", __func__, signum);
	stop_requested = true;
}

/*
 * setup_signal_handler() - Setup process signals
 *
 * Return: 0 on success, 1 otherwise.
 */
static int setup_signal_handler(struct sigaction *orig_action)
{
	struct sigaction new_action;

	memset(&new_action, 0, sizeof(new_action));
	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction(SIGINT, NULL, orig_action);
	if (orig_action->sa_handler != SIG_IGN) {
		if (sigaction(SIGINT, &new_action, NULL)) {
			log_error("Failed to install signal handler: %s (%d)", strerror(errno), errno);
			return 1;
		}
	}

	return 0;
}

cc_start_error_t start_cloud_connection(void)
{
	ccapi_tcp_start_error_t tcp_start_error;
	struct sigaction orig_action;
	int ret;

	if (cc_cfg == NULL) {
		log_error("%s", "Initialize the connection before starting");
		return CC_START_ERROR_NOT_INITIALIZE;
	}

	srand(time(NULL));

	/* Set a signal handler to be able to cancel while trying to connect */
	ret = setup_signal_handler(&orig_action);
	tcp_start_error = initialize_tcp_transport(cc_cfg);
	/* Restore the original signal handler */
	if (!ret)
		sigaction(SIGINT, &orig_action, NULL);

	if (tcp_start_error != CCAPI_TCP_START_ERROR_NONE)
		log_error("Error initializing TCP transport: error %d", tcp_start_error);
	switch(tcp_start_error) {
		case CCAPI_TCP_START_ERROR_NONE:
			break;
		case CCAPI_TCP_START_ERROR_ALREADY_STARTED:
			return CC_START_CCAPI_TCP_START_ERROR_ALREADY_STARTED;
		case CCAPI_TCP_START_ERROR_CCAPI_STOPPED:
			return CC_START_CCAPI_TCP_START_ERROR_CCAPI_STOPPED;
		case CCAPI_TCP_START_ERROR_NULL_POINTER:
			return CC_START_CCAPI_TCP_START_ERROR_NULL_POINTER;
		case CCAPI_TCP_START_ERROR_INSUFFICIENT_MEMORY:
			return CC_START_CCAPI_TCP_START_ERROR_INSUFFICIENT_MEMORY;
		case CCAPI_TCP_START_ERROR_KEEPALIVES:
			return CC_START_CCAPI_TCP_START_ERROR_KEEPALIVES;
		case CCAPI_TCP_START_ERROR_IP:
			return CC_START_CCAPI_TCP_START_ERROR_IP;
		case CCAPI_TCP_START_ERROR_INVALID_MAC:
			return CC_START_CCAPI_TCP_START_ERROR_INVALID_MAC;
		case CCAPI_TCP_START_ERROR_PHONE:
			return CC_START_CCAPI_TCP_START_ERROR_PHONE;
		case CCAPI_TCP_START_ERROR_INIT:
			return CC_START_CCAPI_TCP_START_ERROR_INIT;
		case CCAPI_TCP_START_ERROR_TIMEOUT:
			return CC_START_CCAPI_TCP_START_ERROR_TIMEOUT;
		default:
			return CC_START_ERROR_NOT_INITIALIZE;
	}

	if (start_system_monitor(cc_cfg) != CC_SYS_MON_ERROR_NONE)
		return CC_START_ERROR_SYSTEM_MONITOR;

	start_listening_for_local_requests(cc_cfg);

	log_info("%s", "Cloud connection started");

	return CC_START_ERROR_NONE;
}

cc_stop_error_t stop_cloud_connection(void)
{
	cc_stop_error_t stop_error = CC_STOP_ERROR_NONE;
	ccapi_stop_error_t ccapi_error;

	stop_listening_for_local_requests();

	stop_requested = true;
	if (reconnect_thread_valid) {
		reconnect_thread_valid = false;
		pthread_cancel(reconnect_thread);
		pthread_join(reconnect_thread, NULL);
	}

	stop_system_monitor();

	{
		ccapi_tcp_stop_t tcp_stop = { .behavior = CCAPI_TRANSPORT_STOP_GRACEFULLY };
		ccapi_stop_transport_tcp(&tcp_stop);
	}

#ifdef CCIMP_SMS_TRANSPORT_ENABLED
	{
		ccapi_sms_stop_t sms_stop = { .behavior = CCAPI_TRANSPORT_STOP_GRACEFULLY };
		ccapi_stop_transport_sms(&sms_stop);
	}
#endif
#ifdef CCIMP_UDP_TRANSPORT_ENABLED
	{
		ccapi_udp_stop_t udp_stop = { .behavior = CCAPI_TRANSPORT_STOP_GRACEFULLY };
		ccapi_stop_transport_udp(&udp_stop);
	}
#endif

	/*
	 * Wait some time to properly stop transports.
	 * Required not to get locked during the stop process
	 */
	sleep(1);

	ccapi_error = ccapi_stop(CCAPI_STOP_GRACEFULLY);
	if (ccapi_error == CCAPI_STOP_ERROR_NONE) {
		log_info("%s", "Cloud connection stopped");
	} else {
		log_error("Error stopping Cloud connection: error %d", ccapi_error);
		stop_error = CC_STOP_CCAPI_STOP_ERROR_NOT_STARTED;
	}

	set_cloud_connection_status(CC_STATUS_DISCONNECTED);

	free_configuration(cc_cfg);
	cc_cfg = NULL;

	deinit_logger();

	return stop_error;
}

cc_status_t get_cloud_connection_status(void)
{
	return connection_status;
}

char *get_client_cert_path(void)
{
	if (!cc_cfg)
		return NULL;

	return cc_cfg->client_cert_path;
}
