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

#include <json_object_iterator.h>
#include <json_object.h>
#include <json_tokener.h>
#include <json_util.h>

#include "device_request.h"

#define TARGET_CC_GET_CONFIG		"cc_get_config"
#define TARGET_CC_SET_CONFIG		"cc_set_config"

#define IS_FLAG_SET(flag, flags_set)	(((flag) & (flags_set)) == (flags_set))

static json_object *convert_cfg_to_json(cfg_t *cfg);
static void setting_json2cfg(json_object *json_value, const char * const setting_path, cfg_t *cfg);

extern cc_cfg_t *cc_cfg;
extern bool restart;

/*
 * get_config_setting_value() - Transform the provided configuration option to JSON
 *
 * @cfg_opt:	The configuration option to transform.
 *
 * Return: A JSON object with the configuration option.
 */
static json_object *get_config_setting_value(cfg_opt_t cfg_opt)
{
	int size = cfg_opt_size(&cfg_opt);
	json_object *value = NULL;
	int i;

	if (size > 1 || IS_FLAG_SET(CFGF_LIST, cfg_opt.flags)) {
		log_debug("   %s list setting", cfg_opt.name);
		value = json_object_new_array_ext(size);
	}

	for (i = 0; i < size; i++) {
		json_object *single_val = NULL;

		switch (cfg_opt.type) {
			case CFGT_INT:
			{
				int int_val = cfg_opt_getnint(&cfg_opt, i);

				log_debug("   Index: %d, Type: integer, Value: %d", i, int_val);
				single_val = json_object_new_int(int_val);
				break;
			}
			case CFGT_FLOAT:
			{
				double float_val = cfg_opt_getnfloat(&cfg_opt, i);

				log_debug("   Index: %d, Type: float, Value: %lf", i, float_val);
				single_val = json_object_new_double(float_val);
				break;
			}
			case CFGT_STR:
			{
				char *str_val = cfg_opt_getnstr(&cfg_opt, i);

				log_debug("   Index: %d, Type: string, Value: %s", i, str_val);
				if (!str_val)
					single_val = NULL;
				else
					single_val = json_object_new_string(str_val);
				break;
			}
			case CFGT_BOOL:
			{
				bool bool_val = cfg_opt_getnbool(&cfg_opt, i);

				log_debug("   Index: %d, Type: boolean, Value: %i", i, bool_val);
				single_val = json_object_new_boolean(bool_val);
				break;
			}
			case CFGT_SEC:
			{
				cfg_t *cfg_sec = cfg_opt_getnsec(&cfg_opt, i);

				log_debug("   Index: %d, Type: section", i);
				if (!cfg_sec) {
					single_val = NULL;
					break;
				}
				single_val = json_object_new_object();
				if (!single_val)
					break;

				single_val = convert_cfg_to_json(cfg_sec);
				break;
			}
			case CFGT_FUNC:
			case CFGT_PTR:
			case CFGT_COMMENT:
			default:
				log_debug("   Index: %d, Type: unsupported (%d)", i, cfg_opt.type);
				continue;
		}

		if (!single_val) {
			log_warning("Unable to get value for setting '%s'", cfg_opt.name);
			continue;
		}

		if (!value)	/* Not an array */
			value = single_val;
		else if (json_object_array_add(value, single_val) != 0)
			log_warning("Unable to add value to array '%s'", cfg_opt.name);
	}

	return value;
}

/*
 * convert_cfg_to_json() - Transform the provided configuration to JSON
 *
 * @cfg:	The configuration to convert to JSON.
 *
 * Return: A JSON object with the configuration settings and their values,
 *         NULL if it fails.
 */
static json_object *convert_cfg_to_json(cfg_t *cfg)
{
	json_object *json = json_object_new_object();
	int i, total = cfg_num(cfg);

	if (!json)
		return NULL;

	log_debug("%s", "Convert configuration to JSON");

	for (i = 0; i < total; i++) {
		json_object *value = NULL;
		cfg_opt_t cfg_opt = cfg->opts[i];

		log_debug("Configuration option %d: %s", i, cfg_opt.name);

		if (!strncmp(cfg_opt.name, "__unknown", strlen(cfg_opt.name)))
			continue;

		value = get_config_setting_value(cfg_opt);
		if (!value || json_object_object_add(json, cfg_opt.name, value) != 0) {
			log_warning("Unable to add setting '%s' to response", cfg_opt.name);
			json_object_put(value);
		}
	}

	return json;
}

/*
 * convert_settings_to_json() - Transform provided configuration settings to JSON
 *
 * @cfg:		The configuration to get the settings from.
 * @json_settings:	List of setting names to transform.
 *
 * Return: A JSON object with the settings and their values, NULL if it fails.
 */
static json_object *convert_settings_to_json(cfg_t *cfg, json_object *json_settings)
{
	json_object *resp = json_object_new_object();
	int len, i;

	if (!resp)
		return NULL;

	len = json_object_array_length(json_settings);

	for (i = 0; i < len; i++) {
		cfg_opt_t *cfg_opt;
		const char *setting = NULL;
		json_object *json_val = NULL;
		json_object *item = json_object_array_get_idx(json_settings, i);

		if (!json_object_is_type(item, json_type_string)) {
			log_warning("%s", "Invalid setting name");
			continue;
		}

		setting = json_object_get_string(item);
		if (!setting) {
			log_warning("%s", "Invalid setting name");
			continue;
		}

		cfg_opt = cfg_getopt(cfg, setting);
		if (!cfg_opt) {
			log_warning("Setting '%s' does not exist", setting);
			continue;
		}

		json_val = get_config_setting_value(*cfg_opt);
		if (!json_val) {
			log_warning("Unable to get value for setting '%s'", setting);
			continue;
		}

		if (json_object_object_add(resp, setting, json_val) != 0) {
			log_warning("Unable to add setting '%s' to response", setting);
			json_object_put(json_val);
		}
	}

	return resp;
}

/*
 * get_cc_config_cb() - Data callback for 'cc_get_config' device requests
 *
 * @target:		Target ID of the device request (cc_get_config).
 * @transport:		Communication transport used by the device request.
 * @req_buffer:		Buffer containing the device request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: 'CCAPI_RECEIVE_ERROR_NONE' if success, any other error on failure.
 */
static ccapi_receive_error_t get_cc_config_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const req_buffer,
		ccapi_buffer_info_t *const resp_buffer)
{
	ccapi_receive_error_t status = CCAPI_RECEIVE_ERROR_NONE;
	char *request = req_buffer->buffer;
	cfg_t *cfg = NULL;
	json_object *req = NULL, *resp = NULL;

	log_debug("%s: target='%s' - transport='%d'", __func__, target, transport);

	resp_buffer->buffer = NULL;

	cfg = get_confuse_configuration();
	if (!cfg) {
		char *error = "Unable to get Cloud Connector service configuration";

		status = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
		log_error("%s", error);
		resp_buffer->buffer = strdup(error);
		if (!resp_buffer)
			goto error;
		goto done;
	}

	if (req_buffer->length == 0) {
		/* Return the whole configuration */
		resp = convert_cfg_to_json(cfg);
	} else {
		json_object *json_settings = NULL;

		/* Parse req_buffer */
		request[req_buffer->length] = '\0';
		req = json_tokener_parse(request);
		if (!req)
			goto bad_format;

		if (!json_object_object_get_ex(req, "settings", &json_settings)
		    || !json_object_is_type(json_settings, json_type_array))
			goto bad_format;

		resp = convert_settings_to_json(cfg, json_settings);
	}

	if (!resp)
		goto error;

	resp_buffer->buffer = strdup(json_object_to_json_string(resp));
	if (!resp_buffer->buffer)
		goto error;

	goto done;
bad_format:
	resp_buffer->buffer = strdup("Invalid format");
	status = resp_buffer->buffer == NULL ? CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY : CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
	log_error("Cannot parse request for target '%s': Invalid format", target);
	goto done;

error:
	status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	log_error("Cannot generate response for target '%s': Out of memory", target);

done:
	if (resp_buffer->buffer) {
		resp_buffer->length = strlen(resp_buffer->buffer);

		log_debug("%s: response: %s (len: %zu)", __func__,
			(char *)resp_buffer->buffer, resp_buffer->length);
	}

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
 * setting_array_json2cfg() - Sets a JSON array value to a setting in the configuration
 *
 * @json_value:		The new array value to configure.
 * @setting_path:	The path of the setting to modify in the configuration.
 * @cfg:		The configuration to modify.
 */
static void setting_array_json2cfg(json_object *json_value, const char * const setting_path, cfg_t *cfg)
{
	int len = json_object_array_length(json_value);
	int i;

	if (!len)
		return;

	for (i = 0; i < len; i++) {
		json_object *item = json_object_array_get_idx(json_value, i);
		json_type type;

		if (!item) {
			log_error("Unable to get '%s' value at index '%d'",
				setting_path, i);
			continue;
		}
		type = json_object_get_type(item);
		log_debug("[%s] index %d (%s): %s", setting_path, i,
			json_type_to_name(type), json_object_get_string(item));

		switch (json_object_get_type(item)) {
			case json_type_boolean:
				if (i == 0)
					cfg_setlist(cfg, setting_path, 1, json_object_get_boolean(item));
				else
					cfg_addlist(cfg, setting_path, 1, json_object_get_boolean(item));
				break;
			case json_type_double:
				if (i == 0)
					cfg_setlist(cfg, setting_path, 1, json_object_get_double(item));
				else
					cfg_addlist(cfg, setting_path, 1, json_object_get_double(item));
				break;
			case json_type_int:
				if (i == 0)
					cfg_setlist(cfg, setting_path, 1, json_object_get_int(item));
				else
					cfg_addlist(cfg, setting_path, 1, json_object_get_int(item));
				break;
			case json_type_string:
				if (i == 0)
					cfg_setlist(cfg, setting_path, 1, json_object_get_string(item));
				else
					cfg_addlist(cfg, setting_path, 1, json_object_get_string(item));
				break;
			case json_type_object:
				{
					cfg_opt_t *opt = cfg_getopt(cfg, setting_path);

					if (i == 0) {
						char **values = NULL;
						int j;

						/* Remove objects */
						for (j = 0; j < (int)opt->nvalues; j++)
							cfg_rmnsec(cfg, setting_path, j);

						/* Add objects */
						values = calloc(len, sizeof(*values));
						if (!values) {
							log_error("%s: Unable to add '%s' to configuration: Out of memory",
								__func__, setting_path);
							return;
						}
						for (j = 0; j < len; j++) {
							values[j] = calloc(1, sizeof(**values));
							if (!values[j]) {
								int k;

								log_error("%s: Unable to add '%s' to configuration: Out of memory",
									__func__, setting_path);
								for (k = 0; k < j; k++)
									free(values[k]);
								free(values);
								return;
							}
						}

						if (cfg_setmulti(cfg, setting_path, len, values) != 0) {
							for (j = 0; j < len; j++)
								free(values[j]);
							free(values);
							return;
						}
					}
					setting_json2cfg(item, "", opt->values[i]->section);

					break;
				}
			case json_type_array:
			case json_type_null:
			default:
				log_debug("   Type: unsupported (%d)", json_object_get_type(item));
				break;
		}
	}
}

/*
 * setting_object_json2cfg() - Sets a JSON value to a setting in the configuration
 *
 * @json_value:		The new value to configure.
 * @setting_path:	The path of the setting to modify in the configuration.
 * @cfg:		The configuration to modify.
 */
static void setting_object_json2cfg(json_object *json_obj, const char * const setting_path, cfg_t *cfg)
{
	struct json_object_iterator it = json_object_iter_init_default();
	struct json_object_iterator it_end;

	it = json_object_iter_begin(json_obj);
	it_end = json_object_iter_end(json_obj);

	while (!json_object_iter_equal(&it, &it_end)) {
		const char *set_name = json_object_iter_peek_name(&it);
		json_object *json_value = json_object_iter_peek_value(&it);
		char union_str[] = "|";
		char *path = NULL;
		int len;

		log_debug("[%s] %s", setting_path, set_name);

		if (strlen(setting_path) == 0)
			union_str[0] = '\0';

		len = snprintf(NULL, 0, "%s%s%s", setting_path, union_str, set_name);
		path = calloc(len + 1, sizeof(*path));
		if (!path) {
			log_error("Cannot get value of setting '%s%s%s': Out of memory",
				setting_path, union_str, set_name);
			goto json_continue;
		}

		sprintf(path, "%s%s%s", setting_path, union_str, set_name);

		setting_json2cfg(json_value, path, cfg);

		free(path);
json_continue:
		json_object_iter_next(&it);
	}
}

/*
 * setting_json2cfg() - Sets a JSON value to a setting in the configuration
 *
 * @json_value:		The new value to configure.
 * @setting_path:	The path of the setting to modify in the configuration.
 * @cfg:		The configuration to modify.
 */
static void setting_json2cfg(json_object *json_value, const char * const setting_path, cfg_t *cfg)
{
	json_type type = json_object_get_type(json_value);

	log_debug("[%s] (%s) %s", setting_path, json_type_to_name(type),
		json_object_get_string(json_value));

	switch (type) {
		case json_type_boolean:
			{
				bool val = json_object_get_boolean(json_value);

				if (cfg_setnbool(cfg, setting_path, val, 0) != 0)
					log_error("Unable to set boolean value '%s' for '%s'",
						val ? "true" : "false", setting_path);
			}
			break;
		case json_type_double:
			{
				double val = json_object_get_double(json_value);

				if (cfg_setnfloat(cfg, setting_path, val, 0) != 0)
					log_error("Unable to set float value '%lf' for '%s'",
						val, setting_path);
			}
			break;
		case json_type_int:
			{
				int val = json_object_get_int(json_value);

				if (cfg_setnint(cfg, setting_path, val, 0) != 0)
					log_error("Unable to set integer value '%d' for '%s'",
						val, setting_path);
			}
			break;
		case json_type_object:
			setting_object_json2cfg(json_value, setting_path, cfg);
			break;
		case json_type_array:
			setting_array_json2cfg(json_value, setting_path, cfg);
			break;
		case json_type_string:
			{
				const char *val = json_object_get_string(json_value);

				if (cfg_setnstr(cfg, setting_path, val, 0) != 0)
					log_error("Unable to set string value '%s' for '%s'",
						val, setting_path);
			}
			break;
		case json_type_null:
		default:
			log_debug("   Type: unsupported (%d)", json_object_get_type(json_value));
			break;
	}
}

/*
 * convert_json_to_cfg() - Sets the JSON setting values to the configuration
 *
 * @json:	The configuration parameters and values to set.
 * @cfg:	The configuration to modify.
 */
static void convert_json_to_cfg(json_object *json, cfg_t *cfg)
{
	struct json_object_iterator it = json_object_iter_init_default();
	struct json_object_iterator it_end;

	it = json_object_iter_begin(json);
	it_end = json_object_iter_end(json);

	while (!json_object_iter_equal(&it, &it_end)) {
		const char *setting_path = json_object_iter_peek_name(&it);
		json_object *json_value = json_object_iter_peek_value(&it);

		setting_json2cfg(json_value, setting_path, cfg);

		json_object_iter_next(&it);
	}
}

/*
 * set_cc_config_cb() - Data callback for 'cc_set_config' device requests
 *
 * @target:		Target ID of the device request (cc_set_config).
 * @transport:		Communication transport used by the device request.
 * @req_buffer:		Buffer containing the device request.
 * @resp_buffer:	Buffer to store the answer of the request.
 *
 * Logs information about the received request and executes the corresponding
 * command.
 *
 * Return: 'CCAPI_RECEIVE_ERROR_NONE' if success, any other error on failure.
 */
static ccapi_receive_error_t set_cc_config_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t const *const req_buffer,
		ccapi_buffer_info_t *const resp_buffer)
{
	ccapi_receive_error_t status = CCAPI_RECEIVE_ERROR_NONE;
	char *request = req_buffer->buffer;
	json_object *req = NULL, *resp = NULL;

	log_debug("%s: target='%s' - transport='%d' - request='%s'",
		__func__, target, transport, (char *)req_buffer->buffer);

	resp_buffer->buffer = NULL;

	if (req_buffer->length == 0)
		goto bad_format;

	/* Parse req_buffer */
	request[req_buffer->length] = '\0';
	req = json_tokener_parse(request);
	if (!req)
		goto bad_format;

	{
		int ret;
		cfg_t *cfg = get_confuse_configuration();

		if (!cfg) {
			char *error = "Unable to get Cloud Connector service configuration";

			status = CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
			log_error("%s", error);
			resp_buffer->buffer = strdup(error);
			if (!resp_buffer)
				goto error;
			goto done;
		}

		convert_json_to_cfg(req, cfg);

		ret = apply_configuration(cc_cfg);
		resp = json_object_new_object();
		switch (ret) {
			case 0: /* Success */
				restart = true;
				if (!resp
					|| json_object_object_add(resp, "status", json_object_new_int(ret)) < 0
					|| json_object_object_add(resp, "desc", json_object_new_string("Success")) < 0)
					goto error;
				break;
			case 1: /* Error with provided configuration values */
				if (!resp
					|| json_object_object_add(resp, "status", json_object_new_int(ret)) < 0
					|| json_object_object_add(resp, "desc", json_object_new_string("Bad configuration values")) < 0)
					goto error;
				break;
			case 2: /* Error writing to file */
				/* Should we return to the previous values instead of restart? */
				restart = true;
				if (!resp
					|| json_object_object_add(resp, "status", json_object_new_int(ret)) < 0
					|| json_object_object_add(resp, "desc", json_object_new_string("Error storing configuration")) < 0)
					goto error;
				break;
			default:
				/* Should not occur */
				break;
		}
	}

	resp_buffer->buffer = strdup(json_object_to_json_string(resp));
	if (resp_buffer->buffer == NULL)
		goto error;

	goto done;
bad_format:
	if (resp_buffer->buffer != NULL)
		free(resp_buffer->buffer);
	resp_buffer->buffer = strdup("Invalid format");
	status = resp_buffer->buffer == NULL ? CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY : CCAPI_RECEIVE_ERROR_INVALID_DATA_CB;
	log_error("Cannot parse request for target '%s': Invalid format", target);
	goto done;

error:
	if (resp_buffer->buffer != NULL)
		free(resp_buffer->buffer);
	resp_buffer->buffer = strdup("Out of memory");
	status = CCAPI_RECEIVE_ERROR_INSUFFICIENT_MEMORY;
	log_error("Cannot process request for target '%s': Out of memory", target);

done:
	if (resp_buffer->buffer != NULL) {
		resp_buffer->length = strlen(resp_buffer->buffer);

		log_debug("%s: response: %s (len: %zu)", __func__,
			(char *)resp_buffer->buffer, resp_buffer->length);
	}

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
 * request_status_cb() - Status callback for cc device requests
 *
 * @target:		Target ID of the device request.
 * @transport:		Communication transport used by the device request.
 * @resp_buffer:	Buffer containing the response data.
 * @receive_error:	The error status of the receive process.
 *
 * This callback is executed when the receive process has finished. It doesn't
 * matter if everything worked or there was an error during the process.
 *
 * Cleans and frees the response buffer.
 */
static void request_status_cb(char const *const target,
		ccapi_transport_t const transport,
		ccapi_buffer_info_t *const resp_buffer,
		ccapi_receive_error_t receive_error)
{
	log_debug("%s: target='%s' - transport='%d' - error='%d'", __func__,
		target, transport, receive_error);

	/* Free the response buffer */
	if (resp_buffer)
		free(resp_buffer->buffer);
}

ccapi_receive_error_t register_cc_device_requests(void)
{
	char *target = TARGET_CC_GET_CONFIG;
	ccapi_receive_error_t error;

	get_configuration(cc_cfg);

	error = ccapi_receive_add_target(target, get_cc_config_cb,
		request_status_cb, CCAPI_RECEIVE_NO_LIMIT);

	if (error == CCAPI_RECEIVE_ERROR_TARGET_ALREADY_ADDED)
		log_warning("Target '%s' already registered", target);
	else if (error != CCAPI_RECEIVE_ERROR_NONE)
		goto done;

	target = TARGET_CC_SET_CONFIG;
	error = ccapi_receive_add_target(target, set_cc_config_cb,
		request_status_cb, CCAPI_RECEIVE_NO_LIMIT);
done:
	if (error == CCAPI_RECEIVE_ERROR_TARGET_ALREADY_ADDED)
		log_warning("Target '%s' already registered", target);
	else if (error != CCAPI_RECEIVE_ERROR_NONE)
		log_error("Cannot register target '%s', error %d", target, error);

	return error;
}

void unregister_cc_device_requests(void)
{
	unsigned int i;
	char *targets[] = {
		TARGET_CC_GET_CONFIG,
		TARGET_CC_SET_CONFIG
	};

	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		ccapi_receive_error_t error = ccapi_receive_remove_target(targets[i]);

		if (error != CCAPI_RECEIVE_ERROR_NONE)
			log_error("Could not remove registered target '%s' (%d)",
				targets[i], error);
	}
}