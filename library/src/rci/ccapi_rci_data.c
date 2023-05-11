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

#include "ccapi/ccapi.h"
#include "cc_logging.h"
#include "ccapi_rci_functions.h"


static unsigned int start_group(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s', Group '%s'", __func__, info->group.name);

	if (info->group.name != NULL) {
		if (strcmp(info->group.name, "device_state") == 0)
			rci_state_device_state_start(info);
		else if (strcmp(info->group.name, "primary_interface") == 0)
			rci_state_primary_interface_start(info);
		else if (strcmp(info->group.name, "gps_stats") == 0)
			rci_state_gps_stats_start(info);
		else if (strcmp(info->group.name, "device_information") == 0)
			rci_state_device_information_start(info);
		else if (strcmp(info->group.name, "ethernet") == 0)
			rci_setting_ethernet_start(info);
		else if (strcmp(info->group.name, "wifi") == 0)
			rci_setting_wifi_start(info);
		else if (strcmp(info->group.name, "static_location") == 0)
			rci_setting_static_location_start(info);
		else if (strcmp(info->group.name, "system_monitor") == 0)
			rci_setting_system_monitor_start(info);
		else if (strcmp(info->group.name, "system") == 0)
			rci_setting_system_start(info);
		else
			log_debug("    Unknown Group '%s'", info->group.name);
	}

	return connector_success;
}

static unsigned int end_group(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s', Group '%s'", __func__, info->group.name);

	if (info->group.name != NULL) {
		if (strcmp(info->group.name, "device_state") == 0)
			rci_state_device_state_end(info);
		else if (strcmp(info->group.name, "primary_interface") == 0)
			rci_state_primary_interface_end(info);
		else if (strcmp(info->group.name, "gps_stats") == 0)
			rci_state_gps_stats_end(info);
		else if (strcmp(info->group.name, "device_information") == 0)
			rci_state_device_information_end(info);
		else if (strcmp(info->group.name, "ethernet") == 0)
			rci_setting_ethernet_end(info);
		else if (strcmp(info->group.name, "wifi") == 0)
			rci_setting_wifi_end(info);
		else if (strcmp(info->group.name, "static_location") == 0)
			rci_setting_static_location_end(info);
		else if (strcmp(info->group.name, "system_monitor") == 0)
			rci_setting_system_monitor_end(info);
		else if (strcmp(info->group.name, "system") == 0)
			rci_setting_system_end(info);
		else
			log_debug("    Unknown Group '%s'", info->group.name);
	}

	return connector_success;
}

static unsigned int lock_group_instances(ccapi_rci_info_t * const info, ccapi_response_item_t * const item)
{
	UNUSED_PARAMETER(info);
	UNUSED_PARAMETER(item);
	log_debug("    Called '%s', Group '%s'", __func__, info->group.name);

	return connector_success;
}

static unsigned int set_group_instances(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s', Group '%s'", __func__, info->group.name);

	return connector_success;
}

static unsigned int remove_group_instance(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s', Group '%s'", __func__, info->group.name);


	return connector_success;
}

static unsigned int unlock_group_instances(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s', Group '%s'", __func__, info->group.name);

	return connector_success;
}

static unsigned int start_list(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return connector_success;
}

static unsigned int end_list(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return connector_success;
}

static unsigned int lock_list_instances(ccapi_rci_info_t * const info, ccapi_response_item_t * const item)
{
	UNUSED_PARAMETER(info);
	UNUSED_PARAMETER(item);
	log_debug("    Called '%s'", __func__);

	return connector_success;
}

static unsigned int set_list_instances(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return connector_success;
}

static unsigned int remove_list_instance(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return connector_success;
}

static unsigned int unlock_list_instances(ccapi_rci_info_t * const info)
{
	UNUSED_PARAMETER(info);
	log_debug("    Called '%s'", __func__);

	return connector_success;
}

static unsigned int get_element(ccapi_rci_info_t * const info, ccapi_element_value_t * const element)
{
	unsigned int ret = connector_success;
	log_debug("    Called '%s', Group '%s' , Element '%s'", __func__, info->group.name, info->element.name);

	/* group state device_state  "Device State" */
	if (strcmp(info->group.name, "device_state") == 0) {
		if (strcmp(info->element.name, "system_up_time") == 0)
			ret = rci_state_device_state_system_up_time_get(info, &element->unsigned_integer_value);
	}

	/* group state device_information "Device information" */
	if (strcmp(info->group.name, "device_information") == 0) {
		if (strcmp(info->element.name, "dey_version") == 0)
			ret = rci_state_device_information_dey_version_get(info, &element->string_value);
		else if (strcmp(info->element.name, "kernel_version") == 0)
			ret = rci_state_device_information_kernel_version_get(info, &element->string_value);
		else if (strcmp(info->element.name, "uboot_version") == 0)
			ret = rci_state_device_information_uboot_version_get(info, &element->string_value);
		else if (strcmp(info->element.name, "hardware") == 0)
			ret = rci_state_device_information_hardware_get(info, &element->string_value);
		else if (strcmp(info->element.name, "kinetis") == 0)
			ret = rci_state_device_information_kinetis_get(info, &element->string_value);
	}

	/* group state primary_interface "Primary interface" */
	if (strcmp(info->group.name, "primary_interface") == 0) {
		if (strcmp(info->element.name, "connection_type") == 0)
			ret = rci_state_primary_interface_connection_type_get(info, &element->string_value);
		else if (strcmp(info->element.name, "ip_addr") == 0)
			ret = rci_state_primary_interface_ip_addr_get(info, &element->string_value);
	}

	/* group state gps_stats "GPS" */
	if (strcmp(info->group.name, "gps_stats") == 0) {
		if (strcmp(info->element.name, "latitude") == 0)
			ret = rci_state_gps_stats_latitude_get(info, &element->string_value);
		else if (strcmp(info->element.name, "longitude") == 0)
			ret = rci_state_gps_stats_longitude_get(info, &element->string_value);
	}

	/* group setting ethernet 2 "Ethernet" */
	if (strcmp(info->group.name, "ethernet") == 0) {
		if (strcmp(info->element.name, "iface_name") == 0)
			ret = rci_setting_ethernet_iface_name_get(info, &element->string_value);
		else if (strcmp(info->element.name, "enabled") == 0)
			ret = rci_setting_ethernet_enabled_get(info, &element->on_off_value);
		else if (strcmp(info->element.name, "conn_type") == 0)
#if (defined RCI_ENUMS_AS_STRINGS)
			ret = rci_setting_ethernet_conn_type_get(info, &element->string_value);
#else
			ret = rci_setting_ethernet_conn_type_get(info, &element->enum_value);
#endif /* RCI_ENUMS_AS_STRINGS */
		else if (strcmp(info->element.name, "ipaddr") == 0)
			ret = rci_setting_ethernet_ipaddr_get(info, &element->string_value);
		else if (strcmp(info->element.name, "netmask") == 0)
			ret = rci_setting_ethernet_netmask_get(info, &element->string_value);
		else if (strcmp(info->element.name, "dns1") == 0)
			ret = rci_setting_ethernet_dns1_get(info, &element->string_value);
		else if (strcmp(info->element.name, "dns2") == 0)
			ret = rci_setting_ethernet_dns2_get(info, &element->string_value);
		else if (strcmp(info->element.name, "gateway") == 0)
			ret = rci_setting_ethernet_gateway_get(info, &element->string_value);
		else if (strcmp(info->element.name, "mac_addr") == 0)
			ret = rci_setting_ethernet_mac_addr_get(info, &element->string_value);
	}

	/* group setting wifi "Wi-Fi" */
	if (strcmp(info->group.name, "wifi") == 0) {
		if (strcmp(info->element.name, "iface_name") == 0)
			ret = rci_setting_wifi_iface_name_get(info, &element->string_value);
		else if (strcmp(info->element.name, "enabled") == 0)
			ret = rci_setting_wifi_enabled_get(info, &element->on_off_value);
		else if (strcmp(info->element.name, "ssid") == 0)
			ret = rci_setting_wifi_ssid_get(info, &element->string_value);
		else if (strcmp(info->element.name, "wpa_status") == 0)
			ret = rci_setting_wifi_wpa_status_get(info, &element->string_value);
		else if (strcmp(info->element.name, "conn_type") == 0)
#if (defined RCI_ENUMS_AS_STRINGS)
			ret = rci_setting_wifi_conn_type_get(info, &element->string_value);
#else
			ret = rci_setting_wifi_conn_type_get(info, &element->enum_value);
#endif /* RCI_ENUMS_AS_STRINGS */
		else if (strcmp(info->element.name, "ipaddr") == 0)
			ret = rci_setting_wifi_ipaddr_get(info, &element->string_value);
		else if (strcmp(info->element.name, "netmask") == 0)
			ret = rci_setting_wifi_netmask_get(info, &element->string_value);
		else if (strcmp(info->element.name, "dns1") == 0)
			ret = rci_setting_wifi_dns1_get(info, &element->string_value);
		else if (strcmp(info->element.name, "dns2") == 0)
			ret = rci_setting_wifi_dns2_get(info, &element->string_value);
		else if (strcmp(info->element.name, "gateway") == 0)
			ret = rci_setting_wifi_gateway_get(info, &element->string_value);
		else if (strcmp(info->element.name, "mac_addr") == 0)
			ret = rci_setting_wifi_mac_addr_get(info, &element->string_value);
	}

	/* group setting static_location "Static location" */
	if (strcmp(info->group.name, "static_location") == 0) {
		if (strcmp(info->element.name, "use_static_location") == 0)
			ret = rci_setting_static_location_use_static_location_get(info, &element->on_off_value);
		else if (strcmp(info->element.name, "latitude") == 0)
			ret = rci_setting_static_location_latitude_get(info, &element->float_value);
		else if (strcmp(info->element.name, "longitude") == 0)
			ret = rci_setting_static_location_longitude_get(info, &element->float_value);
		else if (strcmp(info->element.name, "altitude") == 0)
			ret = rci_setting_static_location_altitude_get(info, &element->float_value);
	}

	/* group setting system_monitor "System monitor" */
	if (strcmp(info->group.name, "system_monitor") == 0) {
		if (strcmp(info->element.name, "enable_sysmon") == 0)
			ret = rci_setting_system_monitor_enable_sysmon_get(info, &element->on_off_value);
		else if (strcmp(info->element.name, "sample_rate") == 0)
			ret = rci_setting_system_monitor_sample_rate_get(info, &element->unsigned_integer_value);
		else if (strcmp(info->element.name, "n_dp_upload") == 0)
			ret = rci_setting_system_monitor_n_dp_upload_get(info, &element->unsigned_integer_value);
	}

	/* group setting system "System" */
	if (strcmp(info->group.name, "system") == 0) {
		if (strcmp(info->element.name, "description") == 0)
			ret = rci_setting_system_description_get(info, &element->string_value);
		else if (strcmp(info->element.name, "contact") == 0)
			ret = rci_setting_system_contact_get(info, &element->string_value);
		else if (strcmp(info->element.name, "location") == 0)
			ret = rci_setting_system_location_get(info, &element->string_value);
	}

	return ret;
}


static unsigned int set_element(ccapi_rci_info_t * const info, ccapi_element_value_t * const element)
{
	unsigned int ret = connector_success;
	log_debug("    Called '%s', Group '%s' , Element '%s'", __func__, info->group.name, info->element.name);

	/* group setting static_location "Static location" */
	if (strcmp(info->group.name, "static_location") == 0) {
		if (strcmp(info->element.name, "use_static_location") == 0)
			ret = rci_setting_static_location_use_static_location_set(info, &element->on_off_value);
		else if (strcmp(info->element.name, "latitude") == 0)
			ret = rci_setting_static_location_latitude_set(info, &element->float_value);
		else if (strcmp(info->element.name, "longitude") == 0)
			ret = rci_setting_static_location_longitude_set(info, &element->float_value);
		else if (strcmp(info->element.name, "altitude") == 0)
			ret = rci_setting_static_location_altitude_set(info, &element->float_value);
	}

	/* group setting system_monitor "System monitor" */
	if (strcmp(info->group.name, "system_monitor") == 0) {
		if (strcmp(info->element.name, "enable_sysmon") == 0)
			ret = rci_setting_system_monitor_enable_sysmon_set(info, &element->on_off_value);
		else if (strcmp(info->element.name, "sample_rate") == 0)
			ret = rci_setting_system_monitor_sample_rate_set(info, &element->unsigned_integer_value);
		else if (strcmp(info->element.name, "n_dp_upload") == 0)
			ret = rci_setting_system_monitor_n_dp_upload_set(info, &element->unsigned_integer_value);
	}

	/* group setting system "System" */
	if (strcmp(info->group.name, "system") == 0) {
		if (strcmp(info->element.name, "description") == 0)
			ret = rci_setting_system_description_set(info, element->string_value);
		else if (strcmp(info->element.name, "contact") == 0)
			ret = rci_setting_system_contact_set(info, element->string_value);
		else if (strcmp(info->element.name, "location") == 0)
			ret = rci_setting_system_location_set(info, element->string_value);
	}

	return ret;
}

static unsigned int set_and_transform_element(ccapi_rci_info_t * const info, ccapi_element_value_t * const element, char const ** const transformed_value)
{
	UNUSED_PARAMETER(info);
	UNUSED_PARAMETER(element);
	UNUSED_PARAMETER(transformed_value);
	log_debug("    Called '%s', Group '%s' , Element '%s'", __func__, info->group.name, info->element.name);

	return connector_success;
}

extern connector_remote_config_data_t const rci_internal_data;
static ccapi_rci_data_t const ccapi_rci_data =
{
	.callback.start_session = rci_session_start_cb,
	.callback.end_session = rci_session_end_cb,
	.callback.start_action = rci_action_start_cb,
	.callback.end_action = rci_action_end_cb,

	.callback.start_group = start_group,
	.callback.end_group = end_group,
	.callback.lock_group_instances = lock_group_instances,
	.callback.set_group_instances = set_group_instances,
	.callback.remove_group_instance = remove_group_instance,
	.callback.unlock_group_instances = unlock_group_instances,

	.callback.start_list = start_list,
	.callback.end_list = end_list,
	.callback.lock_list_instances = lock_list_instances,
	.callback.set_list_instances = set_list_instances,
	.callback.remove_list_instance = remove_list_instance,
	.callback.unlock_list_instances = unlock_list_instances,

	.callback.get_element = get_element,
	.callback.set_element = set_element,
	.callback.set_and_transform_element = set_and_transform_element,

	.callback.do_command = rci_do_command_cb,
	.callback.set_factory_defaults = rci_set_factory_defaults_cb,
	.callback.reboot = rci_reboot_cb,

	.rci_desc = &rci_internal_data
};

ccapi_rci_service_t rci_service = {
	.rci_data = &ccapi_rci_data
};
