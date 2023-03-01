/*
 * Copyright (c) 2018-2022 Digi International Inc.
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



#include "connector_api.h"



#define CONST const 
#define CONNECTOR_FATAL_PROTOCOL_ERROR_BAD_COMMAND (connector_remote_all_strings+0)
#define CONNECTOR_FATAL_PROTOCOL_ERROR_BAD_DESCRIPTOR (connector_remote_all_strings+12)
#define CONNECTOR_FATAL_PROTOCOL_ERROR_BAD_VALUE (connector_remote_all_strings+30)
#define CONNECTOR_PROTOCOL_ERROR_BAD_VALUE (connector_remote_all_strings+40)
#define CONNECTOR_PROTOCOL_ERROR_INVALID_INDEX (connector_remote_all_strings+50)
#define CONNECTOR_PROTOCOL_ERROR_INVALID_NAME (connector_remote_all_strings+64)
#define CONNECTOR_PROTOCOL_ERROR_MISSING_NAME (connector_remote_all_strings+77)
#define CONNECTOR_GLOBAL_ERROR_LOAD_FAIL (connector_remote_all_strings+90)
#define CONNECTOR_GLOBAL_ERROR_SAVE_FAIL (connector_remote_all_strings+100)
#define CONNECTOR_GLOBAL_ERROR_MEMORY_FAIL (connector_remote_all_strings+110)
#define CONNECTOR_GLOBAL_ERROR_NOT_IMPLEMENTED (connector_remote_all_strings+130)

static char CONST connector_remote_all_strings[] = {
 11,'B','a','d',' ','c','o','m','m','a','n','d',
 17,'B','a','d',' ','c','o','n','f','i','g','u','r','a','t','i','o','n',
 9,'B','a','d',' ','v','a','l','u','e',
 9,'B','a','d',' ','v','a','l','u','e',
 13,'I','n','v','a','l','i','d',' ','i','n','d','e','x',
 12,'I','n','v','a','l','i','d',' ','n','a','m','e',
 12,'M','i','s','s','i','n','g',' ','n','a','m','e',
 9,'L','o','a','d',' ','f','a','i','l',
 9,'S','a','v','e',' ','f','a','i','l',
 19,'I','n','s','u','f','f','i','c','i','e','n','t',' ','m','e','m','o','r','y',
 15,'N','o','t',' ','i','m','p','l','e','m','e','n','t','e','d'
};

static char const * const connector_global_errors[] = {
 CONNECTOR_FATAL_PROTOCOL_ERROR_BAD_COMMAND,/* bad_command */
 CONNECTOR_FATAL_PROTOCOL_ERROR_BAD_DESCRIPTOR,/* bad_descriptor */
 CONNECTOR_FATAL_PROTOCOL_ERROR_BAD_VALUE,/* bad_value */
 CONNECTOR_PROTOCOL_ERROR_BAD_VALUE,/* bad_value */
 CONNECTOR_PROTOCOL_ERROR_INVALID_INDEX,/* invalid_index */
 CONNECTOR_PROTOCOL_ERROR_INVALID_NAME,/* invalid_name */
 CONNECTOR_PROTOCOL_ERROR_MISSING_NAME,/* missing_name */
 CONNECTOR_GLOBAL_ERROR_LOAD_FAIL,/* load_fail */
 CONNECTOR_GLOBAL_ERROR_SAVE_FAIL,/* save_fail */
 CONNECTOR_GLOBAL_ERROR_MEMORY_FAIL,/* memory_fail */
 CONNECTOR_GLOBAL_ERROR_NOT_IMPLEMENTED/* not_implemented */
};

static connector_element_enum_t CONST setting_ethernet__conn_type_enum[] = {
    {"DHCP"},
    {"static"}
};

static connector_element_t CONST setting_ethernet__iface_name_element = {
    "iface_name",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_ethernet__enabled_element = {
    "enabled",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_ethernet__conn_type_element = {
    "conn_type",
    NULL,
    connector_element_access_read_only,
    { ARRAY_SIZE(setting_ethernet__conn_type_enum), setting_ethernet__conn_type_enum}, 
};

static connector_element_t CONST setting_ethernet__ipaddr_element = {
    "ipaddr",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_ethernet__netmask_element = {
    "netmask",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_ethernet__dns1_element = {
    "dns1",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_ethernet__dns2_element = {
    "dns2",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_ethernet__gateway_element = {
    "gateway",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_ethernet__mac_addr_element = {
    "mac_addr",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_item_t CONST setting_ethernet_items[] = {
{ connector_element_type_string, { .element = &setting_ethernet__iface_name_element } },
{ connector_element_type_on_off, { .element = &setting_ethernet__enabled_element } },
{ connector_element_type_enum, { .element = &setting_ethernet__conn_type_element } },
{ connector_element_type_string, { .element = &setting_ethernet__ipaddr_element } },
{ connector_element_type_string, { .element = &setting_ethernet__netmask_element } },
{ connector_element_type_string, { .element = &setting_ethernet__dns1_element } },
{ connector_element_type_string, { .element = &setting_ethernet__dns2_element } },
{ connector_element_type_string, { .element = &setting_ethernet__gateway_element } },
{ connector_element_type_string, { .element = &setting_ethernet__mac_addr_element } }
};

static connector_element_enum_t CONST setting_wifi__conn_type_enum[] = {
    {"DHCP"},
    {"static"}
};

static connector_element_t CONST setting_wifi__iface_name_element = {
    "iface_name",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__enabled_element = {
    "enabled",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__ssid_element = {
    "ssid",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__wpa_status_element = {
    "wpa_status",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__conn_type_element = {
    "conn_type",
    NULL,
    connector_element_access_read_only,
    { ARRAY_SIZE(setting_wifi__conn_type_enum), setting_wifi__conn_type_enum}, 
};

static connector_element_t CONST setting_wifi__ipaddr_element = {
    "ipaddr",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__netmask_element = {
    "netmask",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__dns1_element = {
    "dns1",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__dns2_element = {
    "dns2",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__gateway_element = {
    "gateway",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST setting_wifi__mac_addr_element = {
    "mac_addr",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_item_t CONST setting_wifi_items[] = {
{ connector_element_type_string, { .element = &setting_wifi__iface_name_element } },
{ connector_element_type_on_off, { .element = &setting_wifi__enabled_element } },
{ connector_element_type_string, { .element = &setting_wifi__ssid_element } },
{ connector_element_type_string, { .element = &setting_wifi__wpa_status_element } },
{ connector_element_type_enum, { .element = &setting_wifi__conn_type_element } },
{ connector_element_type_string, { .element = &setting_wifi__ipaddr_element } },
{ connector_element_type_string, { .element = &setting_wifi__netmask_element } },
{ connector_element_type_string, { .element = &setting_wifi__dns1_element } },
{ connector_element_type_string, { .element = &setting_wifi__dns2_element } },
{ connector_element_type_string, { .element = &setting_wifi__gateway_element } },
{ connector_element_type_string, { .element = &setting_wifi__mac_addr_element } }
};

static connector_element_t CONST setting_static_location__use_static_location_element = {
    "use_static_location",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_element_t CONST setting_static_location__latitude_element = {
    "latitude",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_element_t CONST setting_static_location__longitude_element = {
    "longitude",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_element_t CONST setting_static_location__altitude_element = {
    "altitude",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_item_t CONST setting_static_location_items[] = {
{ connector_element_type_on_off, { .element = &setting_static_location__use_static_location_element } },
{ connector_element_type_float, { .element = &setting_static_location__latitude_element } },
{ connector_element_type_float, { .element = &setting_static_location__longitude_element } },
{ connector_element_type_float, { .element = &setting_static_location__altitude_element } }
};

static connector_element_t CONST setting_system_monitor__enable_sysmon_element = {
    "enable_sysmon",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_element_t CONST setting_system_monitor__sample_rate_element = {
    "sample_rate",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_element_t CONST setting_system_monitor__n_dp_upload_element = {
    "n_dp_upload",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_item_t CONST setting_system_monitor_items[] = {
{ connector_element_type_on_off, { .element = &setting_system_monitor__enable_sysmon_element } },
{ connector_element_type_uint32, { .element = &setting_system_monitor__sample_rate_element } },
{ connector_element_type_uint32, { .element = &setting_system_monitor__n_dp_upload_element } }
};

static connector_element_t CONST setting_system__description_element = {
    "description",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_element_t CONST setting_system__contact_element = {
    "contact",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_element_t CONST setting_system__location_element = {
    "location",
    NULL,
    connector_element_access_read_write,
    { 0, NULL }, 
};

static connector_item_t CONST setting_system_items[] = {
{ connector_element_type_string, { .element = &setting_system__description_element } },
{ connector_element_type_string, { .element = &setting_system__contact_element } },
{ connector_element_type_string, { .element = &setting_system__location_element } }
};

static connector_group_t CONST connector_setting_groups[] = {
{
    {
        "ethernet",
        connector_collection_type_fixed_array,
        { 2 /* instances */ },
        { 9, setting_ethernet_items }, 
    },
    { 0, NULL }
},

{
    {
        "wifi",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 11, setting_wifi_items }, 
    },
    { 0, NULL }
},

{
    {
        "static_location",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 4, setting_static_location_items }, 
    },
    { 0, NULL }
},

{
    {
        "system_monitor",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 3, setting_system_monitor_items },
    },
    { 0, NULL }
},

{
    {
        "system",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 3, setting_system_items }, 
    },
    { 0, NULL }
}

};

static connector_element_t CONST state_device_state__system_up_time_element = {
    "system_up_time",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_item_t CONST state_device_state_items[] = {
{ connector_element_type_uint32, { .element = &state_device_state__system_up_time_element } }
};

static connector_element_t CONST state_primary_interface__connection_type_element = {
    "connection_type",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST state_primary_interface__ip_addr_element = {
    "ip_addr",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_item_t CONST state_primary_interface_items[] = {
{ connector_element_type_string, { .element = &state_primary_interface__connection_type_element } },
{ connector_element_type_string, { .element = &state_primary_interface__ip_addr_element } }
};

static connector_element_t CONST state_gps_stats__latitude_element = {
    "latitude",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST state_gps_stats__longitude_element = {
    "longitude",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_item_t CONST state_gps_stats_items[] = {
{ connector_element_type_string, { .element = &state_gps_stats__latitude_element } },
{ connector_element_type_string, { .element = &state_gps_stats__longitude_element } }
};

static connector_element_t CONST state_device_information__dey_version_element = {
    "dey_version",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST state_device_information__kernel_version_element = {
    "kernel_version",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST state_device_information__uboot_version_element = {
    "uboot_version",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST state_device_information__hardware_element = {
    "hardware",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_element_t CONST state_device_information__kinetis_element = {
    "kinetis",
    NULL,
    connector_element_access_read_only,
    { 0, NULL }, 
};

static connector_item_t CONST state_device_information_items[] = {
{ connector_element_type_string, { .element = &state_device_information__dey_version_element } },
{ connector_element_type_string, { .element = &state_device_information__kernel_version_element } },
{ connector_element_type_string, { .element = &state_device_information__uboot_version_element } },
{ connector_element_type_string, { .element = &state_device_information__hardware_element } },
{ connector_element_type_string, { .element = &state_device_information__kinetis_element } }
};

static connector_group_t CONST connector_state_groups[] = {
{
    {
        "device_state",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 1, state_device_state_items }, 
    },
    { 0, NULL }
},

{
    {
        "primary_interface",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 2, state_primary_interface_items }, 
    },
    { 0, NULL }
},

{
    {
        "gps_stats",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 2, state_gps_stats_items }, 
    },
    { 0, NULL }
},

{
    {
        "device_information",
        connector_collection_type_fixed_array,
        { 1 /* instances */ },
        { 5, state_device_information_items }, 
    },
    { 0, NULL }
}

};

static connector_remote_group_table_t CONST connector_group_table[] =
{
    { connector_setting_groups, ARRAY_SIZE(connector_setting_groups) },
    { connector_state_groups, ARRAY_SIZE(connector_state_groups) }
};


connector_remote_config_data_t rci_internal_data = {
    connector_group_table,
    connector_global_errors,
    11,
    0x1,
    0xFE080003,
    "DEY device"
};

connector_remote_config_data_t * const rci_descriptor_data = &rci_internal_data;
