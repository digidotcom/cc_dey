/*
 * Copyright (c) 2017 Digi International Inc.
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
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */

#include <stdio.h>
#include "rci_state_device_info.h"
#include "cc_logging.h"
#include "file_utils.h"

#define STRING_MAX_LENGTH		256
#define PARAM_LENGTH			25
#define STRING_NA				"N/A"
#define KERNEL_VERSION_CMD		"uname -a"
#define DEY_VERSION_NAME		"DISTRO_VERSION"
#define BUILD_FILE				"/etc/build"
#define BUILD_ID_FILE			"/etc/version"
#define UBOOT_VERSION_FILE		"/proc/device-tree/digi,uboot,version"
#define MACHINE_FILE			"/proc/device-tree/digi,machine,name"
#define BOARD_SN_FILE			"/proc/device-tree/digi,hwid,sn"
#define BOARD_VARIANT_FILE		"/proc/device-tree/digi,hwid,variant"
#define BOARD_VERSION_FILE		"/proc/device-tree/digi,carrierboard,version"
#define BOARD_ID_FILE			"/proc/device-tree/digi,carrierboard,id"
#define MCA_FW_VERSION_FILE		"/sys/bus/i2c/devices/0-007e/fw_version"
#define MCA_HW_VERSION_FILE		"/sys/bus/i2c/devices/0-007e/hw_version"
#define DEY_VERSION_TEMPLATE	"DEY-%s-%s"
#define HARDWARE_TEMPLATE		"SN=%s MACHINE=%s VARIANT=%s SBC_VARIANT=%s BOARD_ID=%s"
#define MCA_TEMPLATE			"HW_VERSION=%s FW_VERSION=%s"

#define min(a, b) (((a) < (b)) ? (a) : (b))

static int get_cmd_output(const char *cmd, char *out);
static int read_dey_version(char *version);

typedef struct {
	char dey_version_state[STRING_MAX_LENGTH];
	char kernel_version_state[STRING_MAX_LENGTH];
	char uboot_version_state[STRING_MAX_LENGTH];
	char hardware_state[STRING_MAX_LENGTH];
	char kinetis_state[STRING_MAX_LENGTH];
} device_info_t;

static device_info_t *device_info;

ccapi_state_device_information_error_id_t rci_state_device_information_start(
		ccapi_rci_info_t * const info)
{
	ccapi_state_device_information_error_id_t ret = CCAPI_STATE_DEVICE_INFORMATION_ERROR_NONE;
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	device_info = calloc(1, sizeof (device_info_t));
	if (device_info == NULL) {
		ret = CCAPI_STATE_DEVICE_INFORMATION_ERROR_MEMORY_FAIL;
	}

	return ret;
}

ccapi_state_device_information_error_id_t rci_state_device_information_end(
		ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	free(device_info);
	device_info = NULL;

	return CCAPI_STATE_DEVICE_INFORMATION_ERROR_NONE;
}

ccapi_state_device_information_error_id_t rci_state_device_information_dey_version_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	ccapi_state_device_information_error_id_t ret = CCAPI_STATE_DEVICE_INFORMATION_ERROR_NONE;
	char dey_version[PARAM_LENGTH] = STRING_NA;
	char build_id[PARAM_LENGTH] = STRING_NA;

	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	read_dey_version(dey_version);
	read_file_line(BUILD_ID_FILE, build_id, PARAM_LENGTH);

	snprintf(device_info->dey_version_state, STRING_MAX_LENGTH, DEY_VERSION_TEMPLATE, dey_version, build_id);
	*value = device_info->dey_version_state;

	return ret;
}

ccapi_state_device_information_error_id_t rci_state_device_information_kernel_version_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	ccapi_state_device_information_error_id_t ret = CCAPI_STATE_DEVICE_INFORMATION_ERROR_NONE;

	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (get_cmd_output(KERNEL_VERSION_CMD, device_info->kernel_version_state) != 0)
		snprintf(device_info->kernel_version_state, STRING_MAX_LENGTH, "%s", STRING_NA);
	*value = device_info->kernel_version_state;

	return ret;
}

ccapi_state_device_information_error_id_t rci_state_device_information_uboot_version_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	ccapi_state_device_information_error_id_t ret = CCAPI_STATE_DEVICE_INFORMATION_ERROR_NONE;

	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	if (read_file_line(UBOOT_VERSION_FILE, device_info->uboot_version_state, STRING_MAX_LENGTH) != 0)
		snprintf(device_info->uboot_version_state, STRING_MAX_LENGTH, "%s", STRING_NA);
	*value = device_info->uboot_version_state;

	return ret;
}

ccapi_state_device_information_error_id_t rci_state_device_information_hardware_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	ccapi_state_device_information_error_id_t ret = CCAPI_STATE_DEVICE_INFORMATION_ERROR_NONE;
	char board_sn[PARAM_LENGTH] = STRING_NA;
	char machine[PARAM_LENGTH] = STRING_NA;
	char board_variant[PARAM_LENGTH] = STRING_NA;
	char board_version[PARAM_LENGTH] = STRING_NA;
	char board_id[PARAM_LENGTH] = STRING_NA;

	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	read_file_line(BOARD_SN_FILE, board_sn, PARAM_LENGTH);
	read_file_line(MACHINE_FILE, machine, PARAM_LENGTH);
	read_file_line(BOARD_VARIANT_FILE, board_variant, PARAM_LENGTH);
	read_file_line(BOARD_VERSION_FILE, board_version, PARAM_LENGTH);
	read_file_line(BOARD_ID_FILE, board_id, PARAM_LENGTH);

	snprintf(device_info->hardware_state, STRING_MAX_LENGTH, HARDWARE_TEMPLATE, board_sn, machine, board_variant, board_version, board_id);
	*value = device_info->hardware_state;

	return ret;
}

ccapi_state_device_information_error_id_t rci_state_device_information_kinetis_get(
		ccapi_rci_info_t * const info, char const * * const value)
{
	ccapi_state_device_information_error_id_t ret = CCAPI_STATE_DEVICE_INFORMATION_ERROR_NONE;
	char fw_version[PARAM_LENGTH] = STRING_NA;
	char hw_version[PARAM_LENGTH] = STRING_NA;

	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	read_file_line(MCA_FW_VERSION_FILE, fw_version, PARAM_LENGTH);
	read_file_line(MCA_HW_VERSION_FILE, hw_version, PARAM_LENGTH);

	snprintf(device_info->kinetis_state, STRING_MAX_LENGTH, MCA_TEMPLATE, hw_version, fw_version);
	*value = device_info->kinetis_state;

	return ret;
}

/**
 * get_cmd_output() - Execute the given command
 *
 * @cmd:		Command to be executed.
 * @out:		Output of the command execution.
 *
 * Return: 0 if success, error code otherwise.
 */
static int get_cmd_output(const char *cmd, char *out)
{
	FILE *in;
	char line[STRING_MAX_LENGTH] = {0};
	int error = 0;

	in = popen(cmd, "r");
	if (!in) {
		error = -1;
		log_error("%s: popen", __func__);
		goto done;
	}

	if (fgets(line, sizeof(line), in) != NULL) {
		strcpy(out, line);
		/* remove new line char */
		if (out[strlen(out)-1] == '\n')
			out[strlen(out)-1] = 0;
	}
	error = pclose(in);
	if (error < 0) {
		log_error("%s: pclose", __func__);
	} else if (WIFEXITED(error)) {
		error = WEXITSTATUS(error) ? -1 : WEXITSTATUS(error);
	}

done:
	return error;
}

/**
 * read_dey_version() - Read the DEY version
 *
 * @version:	Buffer to store the DEY version.
 *
 * Return: 0 if success, -1 otherwise.
 */
static int read_dey_version(char *version)
{
	FILE *in;
	char line[128] = {0};
	int ret = 0;

	if (!file_readable(BUILD_FILE)) {
		log_error("%s: DEY version file does not exist (%s)", __func__, BUILD_FILE);
		ret = -1;
		goto done;
	}
	if ((in = fopen(BUILD_FILE, "rb")) == NULL) {
		log_error("%s: fopen error: %s", __func__, BUILD_FILE);
		ret = -1;
		goto done;
	}
	while (fgets(line, sizeof(line), in) != NULL) {
		if (strncmp(line, DEY_VERSION_NAME, strlen(DEY_VERSION_NAME)) == 0) {
			sscanf(line, "%*s %*s %s", version);
			break;
		}
	}
	fclose(in);

done:
	return ret;
}
