/*
 * This is an auto-generated file - DO NOT EDIT! 
 * This is a C file generated by RCI Generator tool.
 * This file was generated on: 2015/01/20 19:43:24 
 * The command line arguments were: "spastor1:*****-url=test.idigi.com  "Linux Application" 1.0.0.0-ccapiStub  config.rci-noBackup "
 * The version of RCI Generator tool was: 2.0.0.0 */

#include  <stdio.h>
#include  "ccapi/ccapi.h"
#include  "ccapi_rci_functions.h"

unsigned int th_rci_called_function(char const * const function_name, ccapi_rci_info_t * const info);
void th_set_value_ptr(void const * const value);

ccapi_global_error_id_t rci_session_start_cb(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_global_error_id_t rci_session_end_cb(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_global_error_id_t rci_action_start_cb(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_global_error_id_t rci_action_end_cb(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_global_error_id_t rci_do_command_cb(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_global_error_id_t rci_set_factory_defaults_cb(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_global_error_id_t rci_reboot_cb(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_start(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_end(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_enum_get(ccapi_rci_info_t * const info, ccapi_setting_group_1_el_enum_id_t * const value)
{
    *value = CCAPI_SETTING_GROUP_1_EL_ENUM_THREE;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_enum_set(ccapi_rci_info_t * const info, ccapi_setting_group_1_el_enum_id_t const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_uint32_get(ccapi_rci_info_t * const info, uint32_t * const value)
{
    *value = 5;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_uint32_set(ccapi_rci_info_t * const info, uint32_t const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_on_off_get(ccapi_rci_info_t * const info, ccapi_on_off_t * const value)
{
    *value = CCAPI_ON;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_on_off_set(ccapi_rci_info_t * const info, ccapi_on_off_t const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_hex_get(ccapi_rci_info_t * const info, uint32_t * const value)
{
    *value = 0x20101010;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_hex_set(ccapi_rci_info_t * const info, uint32_t const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_0xhex_get(ccapi_rci_info_t * const info, uint32_t * const value)
{
    *value = 0x20101010;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_0xhex_set(ccapi_rci_info_t * const info, uint32_t const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_signed_get(ccapi_rci_info_t * const info, int32_t * const value)
{
    *value = -100;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_signed_set(ccapi_rci_info_t * const info, int32_t const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_bool_get(ccapi_rci_info_t * const info, ccapi_bool_t * const value)
{
    *value = CCAPI_TRUE;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_bool_set(ccapi_rci_info_t * const info, ccapi_bool_t const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_float_get(ccapi_rci_info_t * const info, float * const value)
{
    *value = 1.2;
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_1_error_id_t rci_setting_group_1_el_float_set(ccapi_rci_info_t * const info, float const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_3_error_id_t rci_setting_group_3_start(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_3_error_id_t rci_setting_group_3_end(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_3_error_id_t rci_setting_group_3_el_string_get(ccapi_rci_info_t * const info, char const * * const value)
{
    *value = "String";
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_3_error_id_t rci_setting_group_3_el_string_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_3_error_id_t rci_setting_group_3_el_multiline_get(ccapi_rci_info_t * const info, char const * * const value)
{
    *value = "Multiline\nString";
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_3_error_id_t rci_setting_group_3_el_multiline_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_setting_group_3_error_id_t rci_setting_group_3_el_password_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_start(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_end(ccapi_rci_info_t * const info)
{
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_ip_get(ccapi_rci_info_t * const info, char const * * const value)
{
    *value = "192.168.1.1";
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_ip_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_fqdnv4_get(ccapi_rci_info_t * const info, char const * * const value)
{
    *value = "www.digi.com";
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_fqdnv4_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_fqdnv6_get(ccapi_rci_info_t * const info, char const * * const value)
{
    *value = "2001:0db8:85a3:0042:1000:8a2e:0370:7334";
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_fqdnv6_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_mac_get(ccapi_rci_info_t * const info, char const * * const value)
{
    *value = "00:04:9D:AB:CD:EF";
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_mac_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_datetime_get(ccapi_rci_info_t * const info, char const * * const value)
{
    *value = "2002-05-30T09:30:10-0600";
    return th_rci_called_function(__FUNCTION__, info);
}

ccapi_state_group_2_error_id_t rci_state_group_2_el_datetime_set(ccapi_rci_info_t * const info, char const * const value)
{
    th_set_value_ptr(value);
    return th_rci_called_function(__FUNCTION__, info);
}
