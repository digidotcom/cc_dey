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
#include <libdigiapix/process.h>
#include <miniunz/unzip.h>
#include <pthread.h>
#ifdef ENABLE_RECOVERY_UPDATE
#include <recovery.h>
#endif /* ENABLE_RECOVERY_UPDATE */
#include <stdio.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "cc_config.h"
#include "cc_firmware_update.h"
#include "cc_logging.h"
#include "_utils.h"

/* Swupdate support */
#ifdef ENABLE_ONTHEFLY_UPDATE
#include <swupdate_status.h>
#include <network_ipc.h>
#endif /* ENABLE_ONTHEFLY_UPDATE */

/*------------------------------------------------------------------------------
                             D E F I N I T I O N S
------------------------------------------------------------------------------*/
#define FW_UPDATE_TAG				"FW UPDATE:"

#define REBOOT_TIMEOUT				1

#define UPDATE_PACKAGE_EXT			".swu"
#define FRAGMENT_EXT				".zip"

#define MANIFEST_PROP_SIZE			"size"
#define MANIFEST_PROP_FRAGMENTS		"fragments"
#define MANIFEST_PROP_NAME			"name"
#define MANIFEST_PROP_CHECKSUM		"checksum"
#define MANIFEST_PROP_SRC_DIR		"src_dir"
#define MANIFEST_PROP_UNKNOWN		"__unknown"

#define WRITE_BUFFER_SIZE			128 * 1024 /* 128KB */
#define FW_SWU_CHUNK_SIZE			128 * 1024 /* 128KB, CC6UL flash sector size */

#define LINE_BUFSIZE				255
#define CMD_BUFSIZE				255
#define FW_UPDATE_CMD				"update-firmware"

typedef enum {
	CC_FW_TARGET_SWU,
	CC_FW_TARGET_MANIFEST,
	__CC_FW_TARGET_LAST,
} cc_fw_target_t;

/*
 * struct mf_fw_t - Firmware manifest type
 *
 * @fw_total_size:	Total size in bytes of the firmware package
 * @n_fragments:	Number of fragments to reconstruct the firmware package
 * @fragment_name:	Name of each fragment (no index, no extension)
 * @fw_checksum:	CRC32 of the firmware package
 * @fragments_dir:	Directory where the fragments are located
 */
typedef struct {
	size_t fw_total_size;
	int n_fragments;
	char *fragment_name;
	uint32_t fw_checksum;
	char *fragments_dir;
} mf_fw_t;

/*
 * struct mf_fragment_t - Firmware package fragment type
 *
 * @path:	Absolute path of the firmware fragment
 * @name:	Name of the fragment (with index and extension)
 * @index:	Fragment index
 */
typedef struct {
	char *path;
	char *name;
	int index;
} mf_fragment_t;

/*
 * struct mf_fw_info_t - Firmware package information type
 *
 * @file_path:		Absolute path of the assembled firmware package
 * @file_name:		Name of the firmware package (with extension)
 * @manifest:		Firmware manifest
 * @fragments:		List of fragments to reconstruct the firmware package
 * @n_fragments:	Number of fragments in the list
 */
typedef struct {
	char *file_path;
	char *file_name;
	mf_fw_t manifest;
	mf_fragment_t *fragments;
	int n_fragments;
} mf_fw_info_t;

/*
 * struct otf_info_t - On-the-fly information type
 *
 * @buffer:				Buffer to store received data from server to used in
 * 						the read on-the-fly callback to get a package chunk
 * @chunk_ready:		Flag to indicate a new chunk of data is received from
 * 						the server
 * @chunk_size:			Size of received data chunk from the server
 * @last_chunk_size:	Size of last received data chunk from the server
 * @end_status:			End status of the on-the-fly update
 * @update_successful:	Flag to indicate if the update process ends successfully
 * @mutex:				On-the-fly update mutex
 * @cv_end:				On-thy-fly update end condition
 */
typedef struct {
	char buffer[FW_SWU_CHUNK_SIZE];
	bool chunk_ready;
	int chunk_size;
	int last_chunk_size;
	int end_status;
	bool update_successful;

	pthread_mutex_t mutex;
	pthread_cond_t cv_end;
} otf_info_t;


/**
 * log_fw_debug() - Log the given message as debug
 *
 * @format:		Debug message to log.
 * @args:		Additional arguments.
 */
#define log_fw_debug(format, ...)									\
	log_debug("%s " format, FW_UPDATE_TAG, __VA_ARGS__)

/**
 * log_fw_info() - Log the given message as info
 *
 * @format:		Info message to log.
 * @args:		Additional arguments.
 */
#define log_fw_info(format, ...)									\
	log_info("%s " format, FW_UPDATE_TAG, __VA_ARGS__)

/**
 * log_fw_error() - Log the given message as error
 *
 * @format:		Error message to log.
 * @args:		Additional arguments.
 */
#define log_fw_error(format, ...)									\
	log_error("%s " format, FW_UPDATE_TAG, __VA_ARGS__)

extern cc_cfg_t *cc_cfg;
static FILE *fw_fp = NULL;
static char *fw_downloaded_path = NULL;
#ifdef ENABLE_RECOVERY_UPDATE
static pthread_t reboot_thread;
#endif /* ENABLE_RECOVERY_UPDATE */

#ifdef ENABLE_ONTHEFLY_UPDATE
static otf_info_t otf_info = {
	.buffer = {0},
	.chunk_ready = false,
	.chunk_size = 0,
	.last_chunk_size = 0,
	.end_status = EXIT_SUCCESS,
	.update_successful = false,
	.cv_end = PTHREAD_COND_INITIALIZER,
};

#endif /* ENABLE_ONTHEFLY_UPDATE */
static int is_dual = -1;

/*
 * is_dual_boot_system() - Check if the system is dual boot
 *
 * @return: 1 if dual system capable, 0 if not, and -1 on failure
 */
static int is_dual_boot_system(void)
{
	char *resp = NULL;

	if (is_dual != -1)
		return is_dual;

	if (ldx_process_execute_cmd("fw_printenv -n dualboot", &resp, 2) != 0 || resp == NULL) {
		if (resp != NULL)
			log_fw_error("Error getting dualboot system info: %s", resp);
		else
			log_fw_error("%s: Error getting dualboot system info", __func__);

		is_dual = -1;
	} else {
		is_dual = !strcmp(trim(resp), "yes");
	}
	free(resp);

	return is_dual;
}

/*
 * get_available_space() - Retrieve the available space in bytes
 *
 * @path:	The path to get the available space.
 *
 * Return: Number of free bytes.
 */
static size_t get_available_space(const char* path)
{
	struct statvfs stat;

	if (statvfs(path, &stat) != 0)
		return 0;

	return stat.f_bsize * stat.f_bavail;
}

/*
 * concatenate_path() - Concatenate directory path and file name
 *
 * @directory:	Parent directory absolute path.
 * @file:		File name.
 *
 * Concatenate the given directory path and file name, and returns a pointer to
 * a new string with the result. If the given directory path does not finish
 * with a '/' it is automatically added.
 *
 * Memory for the new string is obtained with 'malloc' and can be freed with
 * 'free'.
 *
 * Return: A pointer to a new string with the concatenation or NULL if both
 * 			'directory' and 'file' are NULL.
 */
static char* concatenate_path(const char *directory, const char *file)
{
	char *full_path = NULL;
	int len = 0;

	if (directory == NULL && file == NULL)
		return NULL;

	if (directory == NULL && file != NULL)
		return strdup(file);

	if (directory != NULL && file == NULL)
		return strdup(directory);

	len = strlen(directory) + strlen(file)
			+ (directory[strlen(directory) - 1] != '/' ? 1 : 0) + 1;

	full_path = calloc(1, sizeof (char) * len);
	if (full_path == NULL)
		return NULL;

	strcpy(full_path, directory);
	if (directory[strlen(directory) - 1] != '/')
		strcat(full_path, "/");
	strcat(full_path, file);

	return full_path;
}

/******************** Firmware manifest ********************/

/*
 * mf_free_fragments() - Release the provided list of fragments
 *
 * @fragments:	List of fragments (mf_fragment_t) to release.
 * @n_fragments:	Number of fragments in the list.
 */
static void mf_free_fragments(mf_fragment_t *fragments, int n_fragments)
{
	int i;

	if (fragments == NULL)
		return;

	for (i = 0; i < n_fragments; i++) {
		free(fragments[i].name);
		fragments[i].name = NULL;
		free(fragments[i].path);
		fragments[i].path = NULL;
	}
	free(fragments);
	fragments = NULL;
}

/*
 * mf_free_fw_info() - Release the provided firmware information
 *
 * @fw_info:	Firmware information struct (mf_fw_info_t).
 */
static void mf_free_fw_info(mf_fw_info_t *fw_info)
{
	if (fw_info == NULL)
		return;

	free(fw_info->file_path);
	fw_info->file_path = NULL;
	free(fw_info->file_name);
	fw_info->file_name = NULL;
	free(fw_info->manifest.fragment_name);
	fw_info->manifest.fragment_name = NULL;
	free(fw_info->manifest.fragments_dir);
	fw_info->manifest.fragments_dir = NULL;

	mf_free_fragments(fw_info->fragments, fw_info->n_fragments);
}

/*
 * mf_get_fragment_file_name() - Retrieve a fragment complete name including index
 * 								and extension
 *
 * @name:	Fragment base name without index and without extension.
 * @index:	Fragment index.
 *
 * Memory for the name is obtained with 'malloc' and can be freed with 'free'.
 *
 * Return: The fragment name or NULL in case of failure.
 */
static char* mf_get_fragment_file_name(const char *name, int index)
{
	int len = snprintf(NULL, 0, "%s%d"FRAGMENT_EXT, name, index);
	char *fragment_name = calloc(len + 1, sizeof(char));

	if (!fragment_name)
		return NULL;

	sprintf(fragment_name, "%s%d"FRAGMENT_EXT, name, index);

	return fragment_name;
}

/*
 * check_mf_size() - Validate size property of the manifest
 *
 * @mf_cfg:	The section were the size is defined.
 * @opt:			The size option.
 *
 * @Return: 0 on success, -1 otherwise.
 */
static int check_mf_size(cfg_t *mf_cfg, cfg_opt_t *opt)
{
	long int size = cfg_opt_getnint(opt, 0);

	if (size <= 0) {
		cfg_error(mf_cfg, "Invalid %s (%l): size must be greater than 1",
				opt->name, size);
		return -1;
	}

	return 0;
}

/*
 * check_mf_fragments() - Validate fragments property of the manifest
 *
 * @mf_cfg:	The section were the fragments is defined.
 * @opt:			The fragments option.
 *
 * @Return: 0 on success, -1 otherwise.
 */
static int check_mf_fragments(cfg_t *mf_cfg, cfg_opt_t *opt)
{
	long int fragments = cfg_opt_getnint(opt, 0);

	if (fragments <= 0) {
		cfg_error(mf_cfg, "Invalid %s (%l): number of fragments must be greater than 1",
				opt->name, fragments);
		return -1;
	}

	return 0;
}

/*
 * check_mf_name() - Validate name property of the manifest
 *
 * @mf_cfg:	The section were the name is defined.
 * @opt:			The name option.
 *
 * @Return: 0 on success, -1 otherwise.
 */
static int check_mf_name(cfg_t *mf_cfg, cfg_opt_t *opt)
{
	char *name = cfg_opt_getnstr(opt, 0);

	if (name == NULL || strlen(name) == 0) {
		cfg_error(mf_cfg, "Invalid %s: cannot be empty", opt->name);
		return -1;
	}

	return 0;
}

/*
 * check_mf_checksum() - Validate checksum property of the manifest
 *
 * @mf_cfg:	The section were the checksum is defined.
 * @opt:			The checksum option.
 *
 * @Return: 0 on success, -1 otherwise.
 */
static int check_mf_checksum(cfg_t *mf_cfg, cfg_opt_t *opt)
{
	char* checksum = cfg_opt_getnstr(opt, 0);

	if (checksum == NULL || strlen(checksum) == 0) {
		cfg_error(mf_cfg, "Invalid %s: cannot be empty", opt->name);
		return -1;
	}

	return 0;
}

/*
 * check_mf_src_dir() - Validate src_dir property of the manifest
 *
 * @mf_cfg:	The section were the src_dir is defined.
 * @opt:			The src_dir option.
 *
 * @Return: 0 on success, -1 otherwise.
 */
static int check_mf_src_dir(cfg_t *mf_cfg, cfg_opt_t *opt)
{
	char *src_dir = cfg_opt_getnstr(opt, 0);

	if (src_dir == NULL || strlen(src_dir) == 0) {
		cfg_error(mf_cfg, "Invalid %s: cannot be empty", opt->name);
		return -1;
	}

	if (access(src_dir, R_OK) != 0) {
		cfg_error(mf_cfg,
				"Invalid %s (%s): file does not exist or is not readable",
				opt->name, src_dir);
		return -1;
	}

	return 0;
}

/*
 * mf_parse_file() - Load the downloaded 'manifest.txt' file
 *
 * @manifest_path:	Absolute path of the 'manifest.txt' file.
 * @fw_info:		Firmware information struct (mf_fw_info_t) where the
 * 					settings are saved.
 *
 * Read the provided 'manifest.txt' file and save the settings in the given
 * mf_fw_info_t struct. If the file does not exist or cannot be read, the
 * struct is initialized with the default settings.
 *
 * Return: 0 if the file is loaded successfully, -1 otherwise.
 */
static int mf_parse_file(const char *const manifest_path, mf_fw_info_t *fw_info)
{
	cfg_t *mf_cfg = NULL;
	int error = 0;

	/* Overall structure of the manifest properties. */
	static cfg_opt_t opts[] = {
			/* ------------------------------------------------------------ */
			/*|  TYPE   |   SETTING NAME    |  DEFAULT VALUE   |   FLAGS   |*/
			/* ------------------------------------------------------------ */
			CFG_INT		(MANIFEST_PROP_SIZE,		0,			CFGF_NODEFAULT),
			CFG_INT		(MANIFEST_PROP_FRAGMENTS,	0,			CFGF_NODEFAULT),
			CFG_STR		(MANIFEST_PROP_NAME,		NULL,		CFGF_NODEFAULT),
			CFG_STR		(MANIFEST_PROP_CHECKSUM,	NULL,		CFGF_NODEFAULT),
			CFG_STR		(MANIFEST_PROP_SRC_DIR,		NULL,		CFGF_NODEFAULT),

			/* Needed for unknown properties. */
			CFG_STR		(MANIFEST_PROP_UNKNOWN,		NULL,		CFGF_NONE),
			CFG_END()
	};

	if (access(manifest_path, R_OK) != 0) {
		log_fw_error("Firmware manifest file '%s' cannot be read", manifest_path);
		return -1;
	}

	mf_cfg = cfg_init(opts, CFGF_IGNORE_UNKNOWN);
	cfg_set_validate_func(mf_cfg, MANIFEST_PROP_SIZE, check_mf_size);
	cfg_set_validate_func(mf_cfg, MANIFEST_PROP_FRAGMENTS, check_mf_fragments);
	cfg_set_validate_func(mf_cfg, MANIFEST_PROP_NAME, check_mf_name);
	cfg_set_validate_func(mf_cfg, MANIFEST_PROP_CHECKSUM, check_mf_checksum);
	cfg_set_validate_func(mf_cfg, MANIFEST_PROP_SRC_DIR, check_mf_src_dir);

	/* Parse the manifest file. */
	switch (cfg_parse(mf_cfg, manifest_path)) {
		case CFG_FILE_ERROR:
			log_fw_error("Firmware manifest file '%s' could not be read: %s",
					manifest_path, strerror(errno));
			error = -1;
			goto done;
		case CFG_SUCCESS:
			break;
		case CFG_PARSE_ERROR:
			log_fw_error("Error parsing firmware manifest file '%s'", manifest_path);
			error = -1;
			goto done;
	}

	/* Fill manifest properties. */
	fw_info->manifest.fw_total_size = cfg_getint(mf_cfg, MANIFEST_PROP_SIZE);
	fw_info->manifest.n_fragments = cfg_getint(mf_cfg, MANIFEST_PROP_FRAGMENTS);
	fw_info->manifest.fw_checksum = strtoul(cfg_getstr(mf_cfg, MANIFEST_PROP_CHECKSUM), NULL, 10);
	fw_info->manifest.fragment_name = strdup(cfg_getstr(mf_cfg, MANIFEST_PROP_NAME));
	if (fw_info->manifest.fragment_name == NULL) {
		error = -1;
		goto done;
	}
	fw_info->manifest.fragments_dir = strdup(cfg_getstr(mf_cfg, MANIFEST_PROP_SRC_DIR));
	if (fw_info->manifest.fragments_dir == NULL) {
		error = -1;
		goto done;
	}

done:
	cfg_free(mf_cfg);

	return error;
}

/*
 * mf_get_fw_path() - Retrieve the absolute path of the firmware update package
 *
 * @fw_info:		Firmware information struct (mf_fw_info_t) where the
 * 					path is stored.
 *
 * Memory for the path is obtained with 'malloc' and can be freed with 'free'.
 *
 * Return: 0 on success, -1 otherwise.
 */
static int mf_get_fw_path(mf_fw_info_t *fw_info)
{
	mf_fw_t manifest = fw_info->manifest;
	int len = strlen(manifest.fragment_name) + strlen(UPDATE_PACKAGE_EXT) + 1;

	fw_info->file_name = calloc(1, sizeof (char) * len);
	if (fw_info->file_name == NULL) {
		log_fw_error("Cannot allocate memory for update package '%s%s",
				manifest.fragment_name, UPDATE_PACKAGE_EXT);
		return -1;
	}
	strcpy(fw_info->file_name, manifest.fragment_name);
	strcat(fw_info->file_name, UPDATE_PACKAGE_EXT);

	fw_info->file_path = concatenate_path(cc_cfg->fw_download_path,
			fw_info->file_name);
	if (fw_info->file_path == NULL) {
		log_fw_error("Cannot allocate memory for update package '%s%s",
				manifest.fragment_name, UPDATE_PACKAGE_EXT);
		return -1;
	}

	return 0;
}

/*
 * mf_get_fragments() - Retrieve all fragments information
 *
 * @fw_info:		Firmware information struct (mf_fw_info_t) where the
 * 					fragments information is stored.
 *
 * Return: Number of total fragments, 0 if no fragment is found or if any error
 * 			occurs.
 */
static int mf_get_fragments(mf_fw_info_t *fw_info)
{
	mf_fw_t manifest = fw_info->manifest;
	int n_fragments = 0;
	int i;

	fw_info->fragments = calloc(manifest.n_fragments, sizeof (mf_fragment_t));
	if (fw_info->fragments == NULL) {
		log_fw_error("%s", "Cannot allocate memory for firmware fragments");
		return 0;
	}

	for (i = 0; i < manifest.n_fragments; i++) {
		mf_fragment_t *fragment = &fw_info->fragments[i];

		n_fragments++;
		fragment->index = i;

		/* Get fragment file path */
		fragment->name = mf_get_fragment_file_name(manifest.fragment_name, i);
		if (fragment->name == NULL) {
			log_fw_error("Cannot allocate memory for fragment file '%s%d%s",
					manifest.fragment_name, i, FRAGMENT_EXT);
			goto error;
		}

		fragment->path = concatenate_path(manifest.fragments_dir, fragment->name);
		if (fragment->path == NULL) {
			log_fw_error("Cannot allocate memory for fragment file '%s",
					fragment->name);
			goto error;
		}

		if (access(fragment->path, F_OK) != 0) {
			log_fw_error("Missing fragment number '%d' ('%s')", i, fragment->path);
			goto error;
		}
	}
	goto done;

error:
	mf_free_fragments(fw_info->fragments, n_fragments);
	fw_info->fragments = NULL;
	n_fragments = 0;

done:
	fw_info->n_fragments = n_fragments;
	return n_fragments;
}

/**
 * mf_assemble_fragment() - Append a fragment to a file
 *
 * @fragment:		Fragment file to be assembled.
 * @file_name:		Name of the file compressed in the fragment.
 * @swu_fp:			File pointer to the destination file.
 *
 * Return: 0 if the file was successfully assembled, -1 otherwise.
 */
static int mf_assemble_fragment(mf_fragment_t *fragment, const char *file_name, FILE *swu_fp)
{
	unzFile src = NULL;
	char buffer[WRITE_BUFFER_SIZE];
	int size_buffer = WRITE_BUFFER_SIZE;
	int error = 0;

	src = unzOpen(fragment->path);
	if (src == NULL) {
		log_fw_error("Error assembling fragment, cannot open fragment '%s'",
				fragment->path);
		return -1;
	}

	if (unzLocateFile(src, file_name, 1) != UNZ_OK) {
		log_fw_error(
				"Error assembling fragment, file '%s' not found in fragment",
				file_name);
		error = -1;
		goto done;
	}

	if (unzOpenCurrentFilePassword(src, NULL) != UNZ_OK) {
		log_fw_error(
				"Error assembling fragment, cannot open fragment '%s' for decompression",
				fragment->name);
		error = -1;
		goto done;
	}

	do {
		int read = unzReadCurrentFile(src, buffer, size_buffer);
		if (read > 0) {
			size_t written = fwrite(buffer, read, 1, swu_fp);
			if (written != 1) {
				error = -1;
				break;
			}
		} else {
			error = (!read ? 0 : -1);
			break;
		}
	} while (error == 0);

	if (error)
		log_fw_error("Error assembling fragment '%s'", fragment->path);

done:
	unzCloseCurrentFile(src);

	return error;
}

/*
 * mf_delete_fragments() - Remove all fragment files of a firmware package
 *
 * @fw_info:	Firmware information struct (mf_fw_info_t).
 */
static void mf_delete_fragments(mf_fw_info_t *fw_info)
{
	int i;

	for (i = 0; i < fw_info->n_fragments; i++)
		remove(fw_info->fragments[i].path);
}

/*
 * mf_assemble_fw_package() - Assemble fragments to generate the firmware package
 *
 * @fw_info:	Firmware information struct (mf_fw_info_t).
 *
 * The generation of the firmware package follow these steps:
 * 		1. Uncompress each fragment and assemble to the final package.
 * 		2. Delete the fragment.
 * 		3. Compare the package size with the specified in the 'manifest.txt'
 * 		   file.
 * 		4. Calculate the package CRC32 and compare with the specified in the
 * 		   'manifest.txt' file.
 *
 * Return: 0 on success, -1 otherwise.
 */
static int mf_assemble_fw_package(mf_fw_info_t *const fw_info)
{
	int error = 0;
	int i;
	struct stat st;
	uint32_t crc32 = 0xFFFFFFFF;
	FILE *swu_fp = fopen(fw_info->file_path, "wb+");

	if (swu_fp == NULL) {
		log_fw_error("Unable to create '%s' firmware package",
				fw_info->file_path);
		mf_delete_fragments(fw_info);
		return -1;
	}

	/* Assemble fragments. */

	for (i = 0; i < fw_info->n_fragments; i++) {
		mf_fragment_t fragment = fw_info->fragments[i];

		log_fw_debug("Processing fragment %d", i);

		if (mf_assemble_fragment(&fragment, fw_info->file_name, swu_fp) != 0) {
			error = -1;
			break;
		}

		log_fw_debug("Fragment %d assembled", i);
		if (remove(fragment.path) == -1)
			log_fw_error("Unable to remove fragment %d (errno %d: %s)", i,
					errno, strerror(errno));
	}

	if (fsync(fileno(swu_fp)) != 0 || fclose(swu_fp) != 0) {
		log_fw_error("Unable to close firmware package (errno %d: %s)", errno,
				strerror(errno));
		error = -1;
	}

	if (error != 0) {
		mf_delete_fragments(fw_info);
		error = -1;
		goto error;
	}

	log_fw_debug("Firmware package ready, '%s'", fw_info->file_path);

	/* Check file size */

	stat(fw_info->file_path, &st);
	if ((size_t) st.st_size != fw_info->manifest.fw_total_size) {
		log_fw_error("Bad firmware package size: %zu, expected %zu",
			     (size_t)st.st_size, fw_info->manifest.fw_total_size);
		error = -1;
		goto error;
	}

	/* Check CRC32 of the assembled file. */

	if (crc32file(fw_info->file_path, &crc32) != 0) {
		log_fw_error("Unable to calculate CRC32 of firmware package '%s'",
				fw_info->file_name);
		error = -1;
		goto error;
	}

	if (crc32 != fw_info->manifest.fw_checksum) {
		log_fw_error("Wrong CRC32, calculated 0x%08x, expected 0x%08x", crc32,
				fw_info->manifest.fw_checksum);
		error = -1;
		goto error;
	}

	log_fw_debug("CRC32 (0x%08x) is correct", crc32);

	goto done;

error:

	if (remove(fw_info->file_path) == -1)
		log_fw_error("Unable to remove firmware package (errno %d: %s)",
				errno, strerror(errno));

done:

	return error;
}

/*
 * mf_generate_fw() - Generate firmware package via manifest
 *
 * @manifest_path:	Absolute path to the downloaded manifest file.
 * @target:			Target number.
 *
 * Steps of the firmware update via manifest:
 * 		1. Load the downloaded 'manifest.txt'.
 * 		2. Check if there is enough space for the complete firmware package
 * 		   (once it is assembled) plus a single uncompressed fragment.
 * 		3. Check if all the fragments are located in the path specified in the
 * 		   'manifest.txt' file.
 * 		4. Generate the firmware package using the fragments:
 * 				a. Uncompress each fragment and assemble to the final package.
 * 				b. Delete the fragment.
 * 				c. Compare the package size with the specified in the
 * 				   'manifest.txt' file.
 * 				d. Calculate the package CRC32 and compare with the specified
 * 				   in the 'manifest.txt' file.
 * 		5. Return generated package path.
 *
 * Return: 0 on success, -1 otherwise.
 */
static int mf_generate_fw(const char *manifest_path, int target)
{
	size_t available_space;
	char *tmp = NULL;
	mf_fw_info_t fw_info = {0};
	int error = 0;

	/* Load received manifest file. */

	if (mf_parse_file(manifest_path, &fw_info) != 0) {
		log_fw_error("Error loading firmware manifest file '%s'",
				manifest_path);
		error = -1;
		goto done;
	}

	/* Check available space. */

	available_space = get_available_space(cc_cfg->fw_download_path);
	if (available_space == 0) {
		log_fw_error("Unable to get available space (target '%d')", target);
		error = -1;
		goto done;
	}

	if (available_space < fw_info.manifest.fw_total_size) {
		log_fw_error(
				"Not enough space in %s to update firmware (target '%d'), needed %zu have %zu",
				cc_cfg->fw_download_path, target,
				fw_info.manifest.fw_total_size, available_space);
		error = -1;
		goto done;
	}

	/* Check fragments. */

	if (mf_get_fw_path(&fw_info) != 0 || !mf_get_fragments(&fw_info)) {
		error = -1;
		goto done;
	}

	log_fw_debug("%d fragments are ready. Begin image assembly",
			fw_info.n_fragments);

	/* Generate firmware package from fragments. */

	if (mf_assemble_fw_package(&fw_info) != 0) {
		error = -1;
		goto done;
	}

	/* Save firmware package path */

	log_fw_debug("Image was assembly in '%s'", fw_info.file_path);
	tmp = calloc(1, sizeof(char) * (strlen(fw_info.file_path) + 1));
	if (tmp == NULL) {
		log_fw_error("Unable to install software package %s: Out of memory", fw_info.file_path);
		error = -1;
		goto done;
	}
	free(fw_downloaded_path);
	fw_downloaded_path = tmp;
	strcpy(fw_downloaded_path, fw_info.file_path);

done:
	mf_free_fw_info(&fw_info);

	return error;
}

/******************** Recovery update ********************/

#ifdef ENABLE_RECOVERY_UPDATE
/*
 * reboot_threaded() - Perform the reboot in a new thread
 *
 * @unused:	Unused parameter.
 */
static void *reboot_threaded(void *unused)
{
	UNUSED_ARGUMENT(unused);

	if (reboot_recovery(REBOOT_TIMEOUT))
		log_fw_error("%s", "Error rebooting in recovery mode");

	pthread_exit(NULL);

	return NULL;
}
#endif /* ENABLE_RECOVERY_UPDATE */

/******************** On the fly update ********************/

#ifdef ENABLE_ONTHEFLY_UPDATE
/*
 * otf_read_image_cb() - Swupdate callback to read a new chunk of the on the fly image
 *
 * @p:		Buffer for the new chunk data.
 * @size:	Size of the new chunk.
 *
 * this is the callback to get a new chunk of the image in the on the fly
 * firmware update process.
 * It is called by a thread generated by the library and can block.
 */
static int otf_read_image_cb(char **p, int *size)
{
	while (!otf_info.chunk_ready)
		usleep(1000);

	*p = otf_info.buffer;
	*size = otf_info.chunk_size;
	if (otf_info.chunk_size >= otf_info.last_chunk_size)
		otf_info.chunk_ready = false;
	otf_info.last_chunk_size = otf_info.chunk_size;
	otf_info.chunk_size = 0;

	return otf_info.last_chunk_size;
}

/*
 * otf_print_status_cb() - Swupdate callback to report on the fly firmware update
 *                         progress status
 *
 * @msg:	IPC message with the status of the on the fly firmware update.
 *
 * This is called by the Swupdate library to inform
 * about the current status of the upgrade
 *
 * Returns 0.
 */
static int otf_print_status_cb(ipc_message *msg)
{
	log_fw_debug("Status: %d message: %s",
		msg->data.status.current,
		strlen(msg->data.status.desc) > 0 ? msg->data.status.desc : "");

	return 0;
}

/*
 * otf_end_cb() - Swupdate callback to report and finish the on the fly firmware update
 *
 * @status:	Status of the on the fly firmware update.
 *
 * This is called at the end reporting the status
 * of the on the fly upgrade and running any post-update
 * actions if successful
 *
 * Returns 0.
 */
static int otf_end_cb(RECOVERY_STATUS status)
{
	otf_info.end_status = (status == SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;

	log_fw_info("Swupdate %s",
		status == FAILURE ? "*failed*!" :
			"was successful!");

	if (status == SUCCESS) {
		ipc_message msg;

		log_fw_info("Executing post-update actions. %s", __func__);
		msg.data.procmsg.len = 0;
		if (ipc_postupdate(&msg) != 0 || msg.type != ACK) {
			log_fw_error("Running post-update failed! %s", __func__);
			otf_info.end_status = EXIT_FAILURE;
		}
	}

	pthread_mutex_lock(&otf_info.mutex);
	pthread_cond_signal(&otf_info.cv_end);
	pthread_mutex_unlock(&otf_info.mutex);

	if (status == SUCCESS && otf_info.end_status == EXIT_SUCCESS)
		otf_info.update_successful = true;

	return 0;
}
#endif /* ENABLE_ONTHEFLY_UPDATE */

/*
 * process_swu_package() - Perform the installation of the SWU software package
 *
 * @swu_path:		Absolute path to the downloaded SWU file.
 * @target:		Target number.
 */
static ccapi_fw_data_error_t process_swu_package(const char *swu_path, int target)
{
	ccapi_fw_data_error_t error = CCAPI_FW_DATA_ERROR_NONE;

	if (is_dual_boot_system() > 0) {
		char cmd[CMD_BUFSIZE] = {0};
		char line[LINE_BUFSIZE] = {0};
		FILE *fp;

		log_fw_debug("We will start the %s script at path %s", FW_UPDATE_CMD, swu_path);
		sprintf(cmd, "%s %s", FW_UPDATE_CMD, swu_path);
		/* Open process to execute update command */
		fp = popen(cmd, "r");
		if (fp == NULL){
			log_fw_error("Couldn't execute dualboot installation cmd %s", cmd);
		} else {
			/* Read script output till finished */
			while (fgets(line, LINE_BUFSIZE, fp) != NULL) {
				log_fw_debug("swupdate: %s", line);
				if(strstr(line, "There was an error performing the update")) {
					log_fw_error(
						"Error updating firmware using package '%s' for target '%d'",
						swu_path, target);
					error = CCAPI_FW_DATA_ERROR_INVALID_DATA;
				}
			}
			/* close the process */
			pclose(fp);
		}
#ifdef ENABLE_RECOVERY_UPDATE
	} else {
		if (update_firmware(swu_path)) {
			log_fw_error(
					"Error updating firmware using package '%s' for target '%d'",
					swu_path, target);
			error = CCAPI_FW_DATA_ERROR_INVALID_DATA;
		}
#endif /* ENABLE_RECOVERY_UPDATE */
	}

	return error;
}

/******************** CC firmware update callbacks ********************/

/*
 * firmware_request_cb() - Incoming firmware update request callback
 *
 * @target:		Target number of the firmware update request.
 * @filename:	Name of the firmware file to download.
 * @total_size:	Total size required for the downloaded firmware.
 *
 * This callback ask for acceptance of an incoming firmware update request.
 * The decision can be taken based on the request target number, the file name,
 * and the total size.
 *
 * Returns: 0 on success, error code otherwise.
 */
static ccapi_fw_request_error_t firmware_request_cb(unsigned int const target,
		char const *const filename, size_t const total_size) {
	ccapi_fw_request_error_t error = CCAPI_FW_REQUEST_ERROR_NONE;
	size_t available_space;

	log_fw_info("Firmware download requested (target '%d')", target);

	if (get_configuration(cc_cfg) != 0) {
		log_fw_error("Cannot load configuration (target '%d')", target);
		return CCAPI_FW_REQUEST_ERROR_ENCOUNTERED_ERROR;
	}

#ifdef ENABLE_ONTHEFLY_UPDATE
	if (is_dual_boot_system() > 0 && cc_cfg->on_the_fly && target != CC_FW_TARGET_MANIFEST) {
		char system_to_update[256] = {0};
		int active_system_len = 7;
		char *resp = NULL;
		char *active_system = NULL;
		int retval;
		static struct swupdate_request req;

		log_fw_debug("Firmware download streaming requested (target '%d')", target);
		/* Start swupdate process */
		pthread_mutex_init(&otf_info.mutex, NULL);

		/* Initialize on-the-fly info */
		otf_info.chunk_ready = false;
		otf_info.chunk_size = 0;
		otf_info.last_chunk_size = 0;
		otf_info.end_status = EXIT_SUCCESS;
		otf_info.update_successful = false;

		/* Prepare request structure */
		swupdate_prepare_req(&req);

		if (ldx_process_execute_cmd("fw_printenv -n active_system", &resp, 2) != 0 || resp == NULL) {
			if (resp != NULL)
				log_fw_error("Error getting active system: %s", resp);
			else
				log_fw_error("%s: Error getting active system", __func__);
			retval = -1;
		} else {
			/* Read active system */
			active_system = trim(resp);
			log_fw_debug("Active system detected: '%s'", active_system);

			/* Detect storage media, on eMMC devices the response will be 1*/
			if (ldx_process_execute_cmd("grep -qs mtd /proc/mtd", NULL, 2) == 0) {
				strncpy(req.software_set, "mtd" , sizeof(req.software_set) -1);
			} else {
				strncpy(req.software_set, "mmc" , sizeof(req.software_set) - 1);
			}
			log_fw_debug("Is a %s device", req.software_set);

			/* Detect active system & save the partition to umount */
			if (!strncmp(active_system, "linux_a", active_system_len)) {
				strncpy(req.running_mode, "secondary" , sizeof(req.running_mode) -1);
				sprintf(system_to_update, "%s", "umount /mnt/linux_b > /dev/null");
			} else {
				strncpy(req.running_mode, "primary" , sizeof(req.running_mode) - 1);
				sprintf(system_to_update, "%s", "umount /mnt/linux_a > /dev/null");
			}

			log_fw_debug("Selected %s partition to update", req.running_mode);

			/* We don't care about the result of the command, it will fail
			if the partition is already umount, for example in the scenario
			when a first update fails, and we perform a retry */
			ldx_process_execute_cmd(system_to_update, NULL, 2);

			retval = swupdate_async_start(otf_read_image_cb, otf_print_status_cb, otf_end_cb, &req, sizeof(req));
		}

		free(resp);

		/* Return if we've hit an error scenario */
		if (retval < 0) {
			log_fw_error("Streaming update process failed, returns '%d'", retval);
			pthread_mutex_unlock(&otf_info.mutex);
			return CCAPI_FW_REQUEST_ERROR_ENCOUNTERED_ERROR;
		}
	} else
#endif /* ENABLE_ONTHEFLY_UPDATE */
	{
		fw_downloaded_path = concatenate_path(cc_cfg->fw_download_path, filename);
		if (fw_downloaded_path == NULL) {
			log_fw_error(
					"Cannot allocate memory for '%s' firmware file (target '%d')",
					filename, target);
			return CCAPI_FW_REQUEST_ERROR_ENCOUNTERED_ERROR;
		}

		available_space = get_available_space(cc_cfg->fw_download_path);
		if (available_space == 0) {
			log_fw_error("Unable to get available space (target '%d')", target);
			error = CCAPI_FW_REQUEST_ERROR_ENCOUNTERED_ERROR;
			goto done;
		}
		if (available_space < total_size) {
			log_fw_error("Not enough space to download '%s' firmware file (target '%d')", filename, target);
			error = CCAPI_FW_REQUEST_ERROR_DOWNLOAD_INVALID_SIZE;
			goto done;
		}

		fw_fp = fopen(fw_downloaded_path, "wb+");
		if (fw_fp == NULL) {
			log_fw_error("Unable to create '%s' file (target '%d')", filename, target);
			error = CCAPI_FW_REQUEST_ERROR_ENCOUNTERED_ERROR;
			goto done;
		}
	}
done:

	if (error != CCAPI_FW_REQUEST_ERROR_NONE)
		free(fw_downloaded_path);

	return error;
}

/*
 * firmware_data_cb() - Receive firmware data chunk callback
 *
 * @target:		Target number of the firmware data chunk.
 * @offset:		Offset in the received data.
 * @data:		Firmware data chunk.
 * @size:		Size of the data chunk.
 * @last_chunk:	CCAPI_TRUE if it is the last data chunk.
 *
 * Data to program is received including the offset where it should be
 * programmed. The size of the data will be the one configured by the user in
 * the chunk_size field of the target information.
 *
 * Returns: 0 on success, error code otherwise.
 */
static ccapi_fw_data_error_t firmware_data_cb(unsigned int const target, uint32_t offset,
		void const *const data, size_t size, ccapi_bool_t last_chunk) {
	ccapi_fw_data_error_t error = CCAPI_FW_DATA_ERROR_NONE;
	int retval;

	log_fw_debug("Received chunk: target=%d offset=0x%x length=%zu last_chunk=%d", target, offset, size, last_chunk);

#ifdef ENABLE_ONTHEFLY_UPDATE
	if (is_dual_boot_system() > 0 && cc_cfg->on_the_fly && target != CC_FW_TARGET_MANIFEST) {
		log_fw_debug("Get data package from Remote Manager %d", target);
		otf_info.chunk_size = size;
		memcpy(otf_info.buffer, data, otf_info.chunk_size);
		otf_info.chunk_ready = true;

		if (last_chunk) {
			int loops = 0;

			log_fw_debug("Firmware download completed for target '%d'", target);
			/* End called, unlock and exit */
			pthread_mutex_lock(&otf_info.mutex);
			pthread_cond_wait(&otf_info.cv_end, &otf_info.mutex);
			pthread_mutex_unlock(&otf_info.mutex);

			/* Verify upgrade status and post-update actions */
			if (otf_info.end_status == EXIT_FAILURE) {
				log_fw_error("Firmware download streaming failed '%d'", otf_info.end_status);
				return CCAPI_FW_DATA_ERROR_INVALID_DATA;
			}

			/* Due to asynchronous update writing, we must wait until
			 * the last packet has been written.
			 */
			while (!otf_info.update_successful && loops < 100) {
				usleep(10000);
				log_fw_debug("Waiting for download and update to finish (%d)", otf_info.update_successful);
				loops++;
			}
			if (loops >= 100) {
				log_fw_error("Timeout waiting to finish on the fly update process (%d)", loops);
				error = CCAPI_FW_DATA_ERROR_INVALID_DATA;
			}
		}
	} else
#endif /* ENABLE_ONTHEFLY_UPDATE */
	{
		retval = fwrite(data, size, 1, fw_fp);
		if (retval != 1) {
			log_fw_error("%s", "Error writing to firmware file");
			return CCAPI_FW_DATA_ERROR_INVALID_DATA;
		}

		if (last_chunk) {
			if (fw_fp != NULL) {
				int fd = fileno(fw_fp);

				if (fsync(fd) != 0 || fclose(fw_fp) != 0) {
					log_fw_error("Unable to close firmware file (errno %d: %s)", errno, strerror(errno));
					return CCAPI_FW_DATA_ERROR_INVALID_DATA;
				}
			}
			log_fw_info("Firmware download completed for target '%d'", target);

			log_fw_info("Starting firmware update process (target '%d')", target);

			switch(target) {
				/* Target for manifest.txt files. */
				case CC_FW_TARGET_MANIFEST: {
					if (mf_generate_fw(fw_downloaded_path, target) != 0) {
						log_fw_error(
								"Error generating firmware package from '%s' for target '%d'",
								fw_downloaded_path, target);
						error = CCAPI_FW_DATA_ERROR_INVALID_DATA;
						break;
					}
					error = process_swu_package(fw_downloaded_path, target);
					break;
				}
				/* Target for *.swu files. */
				case CC_FW_TARGET_SWU: {
					error = process_swu_package(fw_downloaded_path, target);
					break;
				}
				default:
					error = CCAPI_FW_DATA_ERROR_INVALID_DATA;
			}

			free(fw_downloaded_path);
		}
	}

	return error;
}

/*
 * firmware_cancel_cb() - Firmware update process abort callback
 *
 * @target:			Target number.
 * @cancel_reason:	Abort reason or status.
 *
 * Called when a firmware update abort message is received.
 */
static void firmware_cancel_cb(unsigned int const target, ccapi_fw_cancel_error_t cancel_reason)
{
	log_fw_info("Cancel firmware update for target '%d'. Cancel_reason='%d'",
			target, cancel_reason);

	if (fw_fp != NULL) {
		int fd = fileno(fw_fp);

		if (fsync(fd) != 0 || fclose(fw_fp) != 0)
			log_fw_error("Unable to close firmware file (errno %d: %s)", errno, strerror(errno));
		else if (remove(fw_downloaded_path) == -1)
			log_fw_error("Unable to remove firmware file (errno %d: %s)",
					errno, strerror(errno));
	}

	free(fw_downloaded_path);
}

/*
 * firmware_reset_cb() - Reset device callback
 *
 * @target:			Target number.
 * @system_reset:	CCAPI_TRUE to reboot the device, CCAPI_FALSE otherwise.
 * @version:		Version for the updated target.
 *
 * It is called when firmware update has finished. It lets the user decide
 * whether rebooting the device.
 */
static void firmware_reset_cb(unsigned int const target, ccapi_bool_t *system_reset, ccapi_firmware_target_version_t *version)
{
	UNUSED_ARGUMENT(target);
	UNUSED_ARGUMENT(version);

	*system_reset = CCAPI_FALSE;

	if (is_dual_boot_system() > 0) {
#ifdef ENABLE_ONTHEFLY_UPDATE
		if (cc_cfg->on_the_fly && target != CC_FW_TARGET_MANIFEST){
			char *resp = NULL;

			if (!otf_info.update_successful) {
				log_fw_error("On the fly update failed (%d)", otf_info.update_successful);
				return;
			}
			log_fw_debug("On the fly update finished. Now we will reboot the system (%d)", otf_info.update_successful);

			/* Swap the active system partition */
			if (ldx_process_execute_cmd("on-the-fly-swap-partition.sh", &resp, 2) != 0) {
				if (resp != NULL)
					log_fw_error("Error swapping active system: %s", resp);
				else
					log_fw_error("%s: Error swapping active system", __func__);
				free(resp);
				return;
			}

			free(resp);
		} else
#endif /* ENABLE_ONTHEFLY_UPDATE */
		{
			log_fw_debug("%s", "Dualboot mode does not reboot the system");
			return;
		}
	}

	log_fw_info("Rebooting in %d seconds", REBOOT_TIMEOUT);

	if (is_dual_boot_system() > 0) {
#ifdef ENABLE_ONTHEFLY_UPDATE
		if (cc_cfg->on_the_fly && target != CC_FW_TARGET_MANIFEST) {
			sync();
			fflush(stdout);
			sleep(REBOOT_TIMEOUT);
			reboot(RB_AUTOBOOT);
		}
#endif /* ENABLE_ONTHEFLY_UPDATE */
#ifdef ENABLE_RECOVERY_UPDATE
	} else {
		int error = pthread_create(&reboot_thread, NULL, reboot_threaded, NULL);
		if (error) {
			/* If we cannot create the thread just reboot. */
			if (reboot_recovery(REBOOT_TIMEOUT))
				log_fw_error("%s", "Error rebooting in recovery mode");
		}
#endif /* ENABLE_RECOVERY_UPDATE */
	}
}

/*
 * init_fw_service() - Initialization of firmware service
 *
 * @fw_version:	The current firmware version.
 * @fw_service:	Struct to store the firmware service initialization.
 *
 * Returns: 0 on success, 1 otherwise.
 */
int init_fw_service(const char * const fw_version, ccapi_fw_service_t **fw_service)
{
#if !defined(ENABLE_RECOVERY_UPDATE) || !defined(ENABLE_ONTHEFLY_UPDATE)
	UNUSED_ARGUMENT(fw_version);
	*fw_service = NULL;

	return 0;
#else /* !ENABLE_RECOVERY_UPDATE || !ENABLE_ONTHEFLY_UPDATE */
	uint8_t version[4];
	ccapi_firmware_target_t *fw_list = NULL;

	*fw_service = NULL;

	if (fw_version == NULL)
		return 0;

	if (sscanf(fw_version, "%hhu.%hhu.%hhu.%hhu", &version[0], &version[1],
			&version[2], &version[3]) != 4) {
		log_fw_error("Error initializing Cloud connection: Bad firmware_version string '%s', firmware update disabled",
				fw_version);
		return 0;
	}

	fw_list = calloc(__CC_FW_TARGET_LAST, sizeof(*fw_list));
	*fw_service = calloc(1, sizeof(**fw_service));
	if (fw_list == NULL || *fw_service == NULL) {
		log_fw_error("Error initializing Cloud connection: %s", "Out of memory");
		free(fw_list);
		return 1;
	}

	fw_list[CC_FW_TARGET_SWU].chunk_size = FW_SWU_CHUNK_SIZE;
	fw_list[CC_FW_TARGET_SWU].description = "System";
	fw_list[CC_FW_TARGET_SWU].filespec = ".*\\.[sS][wW][uU]";
	fw_list[CC_FW_TARGET_SWU].maximum_size = 0;
	fw_list[CC_FW_TARGET_SWU].version.major = version[0];
	fw_list[CC_FW_TARGET_SWU].version.minor = version[1];
	fw_list[CC_FW_TARGET_SWU].version.revision = version[2];
	fw_list[CC_FW_TARGET_SWU].version.build = version[3];

	fw_list[CC_FW_TARGET_MANIFEST].chunk_size = 0;
	fw_list[CC_FW_TARGET_MANIFEST].description = "Update manifest";
	fw_list[CC_FW_TARGET_MANIFEST].filespec = "[mM][aA][nN][iI][fF][eE][sS][tT]\\.[tT][xX][tT]";
	fw_list[CC_FW_TARGET_MANIFEST].maximum_size = 0;
	fw_list[CC_FW_TARGET_MANIFEST].version.major = version[0];
	fw_list[CC_FW_TARGET_MANIFEST].version.minor = version[1];
	fw_list[CC_FW_TARGET_MANIFEST].version.revision = version[2];
	fw_list[CC_FW_TARGET_MANIFEST].version.build = version[3];

	(*fw_service)->target.count = __CC_FW_TARGET_LAST;
	(*fw_service)->target.item = fw_list;

	(*fw_service)->callback.request = firmware_request_cb;
	(*fw_service)->callback.data = firmware_data_cb;
	(*fw_service)->callback.reset = firmware_reset_cb;
	(*fw_service)->callback.cancel = firmware_cancel_cb;

	return 0;
#endif /* !ENABLE_RECOVERY_UPDATE || !ENABLE_ONTHEFLY_UPDATE */
}