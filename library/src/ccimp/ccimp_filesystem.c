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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cc_logging.h"
#include "ccimp/ccimp_filesystem.h"
#include "_utils.h"

#define MIN_VALUE(a, b)		((a) < (b) ? (a) : (b))
#define APP_HASH_BUFFER_SIZE	1024

#define ERROR_SESSION		"Session error %d"

/**
 * struct dir_data_t - Struct used as handle typedef for directory operations
 *
 * @dirp:	The directory stream object.
 * @dir_entry:	Dirent structure representing a directory entry. It includes
 * 		the name of the directory.
 *
 */
typedef struct
{
	DIR *dirp;
	struct dirent dir_entry;
} dir_data_t;

/**
 * app_convert_file_open_mode() - Get the open mode based on the given flags
 *
 * @oflag:	Value of the open mode flags to be translated.
 *
 * Returns: The file open mode based on the given flags.
 */
static int app_convert_file_open_mode(int const oflag)
{
	int result = 0;

	if (oflag & CCIMP_FILE_O_WRONLY)
		result |= O_WRONLY;
	if (oflag & CCIMP_FILE_O_RDWR)
		result |= O_RDWR;
	if (oflag & CCIMP_FILE_O_APPEND)
		result |= O_APPEND;
	if (oflag & CCIMP_FILE_O_CREAT)
		result |= O_CREAT;
	if (oflag & CCIMP_FILE_O_TRUNC)
		result |= O_TRUNC;
	if ((oflag & (CCIMP_FILE_O_WRONLY | CCIMP_FILE_O_RDWR)) == 0)
		result |= O_RDONLY;

	return result;
}

/**
 * ccimp_fs_file_open() - Open a file for the specified path
 *
 * @file_open_data:	ccimp_fs_file_open_t struct containing the information
 * 			of the file to open.
 *
 * The path of the file is always absolute and it is open with the permissions
 * and behavior specified by the flags (read/write/seek and
 * append/create/truncate, etc.). The file handle is returned inside the
 * structure and can be used by other file functions (read, write, close).
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_file_open(ccimp_fs_file_open_t *const file_open_data)
{
	int const oflag = app_convert_file_open_mode(file_open_data->flags);
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH; /* 0664 = Owner RW + Group RW + Others R */
	int fd;
	char *tmp = strdupa(file_open_data->path);

	if (tmp == NULL) {
		file_open_data->errnum = errno;
		return CCIMP_STATUS_ERROR;
	}

	if (oflag & CCIMP_FILE_O_CREAT && mkpath(dirname(tmp), mode) == -1) {
		file_open_data->errnum = errno;
		return CCIMP_STATUS_ERROR;
	}

	fd = open(file_open_data->path, oflag | O_CLOEXEC, mode);
	if (fd < 0) {
		file_open_data->errnum = errno;
		return CCIMP_STATUS_ERROR;
	}
	file_open_data->handle = fd;

	return CCIMP_STATUS_OK;
}

/**
 * ccimp_fs_file_read() - Read data from a file
 *
 * @file_read_data:	ccimp_fs_file_read_t struct containing the data read
 * 			information, including the file handle.
 *
 * Data read is stored in buffer up to the maximum bytes_available. The amount
 * of bytes read is specified in the bytes_used field.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_file_read(ccimp_fs_file_read_t *const file_read_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	int result = read(file_read_data->handle, file_read_data->buffer,
			file_read_data->bytes_available);

	if (result >= 0) {
		file_read_data->bytes_used = result;
	} else {
		if (errno == EAGAIN) {
			status = CCIMP_STATUS_BUSY;
		} else {
			file_read_data->errnum = errno;
			status = CCIMP_STATUS_ERROR;
		}
	}

	return status;
}

/**
 * ccimp_fs_file_write() - Write data to a file
 *
 * @file_write_data:	ccimp_fs_file_write_t struct containing information
 * 			about the data to write, including the file handle.
 *
 * The function writes up to bytes_available bytes from buffer into the handle
 * and specifies in bytes_used how many bytes were actually written.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_file_write(ccimp_fs_file_write_t \
		*const file_write_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	int result = write(file_write_data->handle, file_write_data->buffer,
			file_write_data->bytes_available);

	if (result >= 0) {
		file_write_data->bytes_used = result;
	} else {
		if (errno == EAGAIN) {
			status = CCIMP_STATUS_BUSY;
		} else {
			file_write_data->errnum = errno;
			status = CCIMP_STATUS_ERROR;
		}
	}

	return status;
}

/**
 * ccimp_fs_file_close() - Close a file
 *
 * @file_close_data:	ccimp_fs_file_close_t struct containing information
 * 			about the file to close, including the file handle.
 *
 * This function closes the handle created by ccimp_fs_file_open().
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_file_close(ccimp_fs_file_close_t \
		*const file_close_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	int result = close(file_close_data->handle);

	if (result < 0) {
		file_close_data->errnum = errno;
		status = CCIMP_STATUS_ERROR;
	}

	return status;
}

/**
 * ccimp_fs_file_seek() - Set the offset for an open file
 *
 * @file_seek_data:	ccimp_fs_file_seek_t containing information about the
 * 			file to set its offset, including the file handle.
 *
 * Depending on the origin (current, set, or end) the function sets the file
 * offset to the requested_offset and returns the actual one in
 * resulting_offset.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_file_seek(ccimp_fs_file_seek_t *const file_seek_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	int origin;
	off_t offset;

	switch (file_seek_data->origin) {
		case CCIMP_SEEK_SET:
			origin = SEEK_SET;
			break;
		case CCIMP_SEEK_END:
			origin = SEEK_END;
			break;
		case CCIMP_SEEK_CUR:
		default:
			origin = SEEK_CUR;
			break;
	}
	offset = lseek(file_seek_data->handle,
			file_seek_data->requested_offset, origin);
	file_seek_data->resulting_offset = (ccimp_file_offset_t) offset;
	if (offset < 0) {
		file_seek_data->errnum = errno;
		status = CCIMP_STATUS_ERROR;
	}

	return status;
}

/**
 * ccimp_fs_file_truncate() - Truncate an open file to the specified length
 *
 * @file_truncate_data:		ccimp_fs_file_truncate_t struct containing
 * 				information about the file to truncate, including
 * 				the file handle.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_file_truncate(ccimp_fs_file_truncate_t \
		*const file_truncate_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	int result = ftruncate(file_truncate_data->handle,
			file_truncate_data->length_in_bytes);

	if (result < 0) {
		file_truncate_data->errnum = errno;
		status = CCIMP_STATUS_ERROR;
	}

	return status;
}

/**
 * ccimp_fs_file_remove() - Delete an existing file from the file system
 *
 * @file_remove_data:	ccimp_fs_file_remove_t struct containing the full path
 * 			of the file to remove.
 *
 * The ccimp_fs_file_remove_t contains the full path of the file instead of its
 * handle because the file must be closed.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_file_remove(ccimp_fs_file_remove_t \
		*const file_remove_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	int result = unlink(file_remove_data->path);

	if (result < 0) {
		if (errno == EBUSY) {
			status = CCIMP_STATUS_BUSY;
		} else {
			file_remove_data->errnum = errno;
			status = CCIMP_STATUS_ERROR;
		}
	}

	return status;
}

/**
 * ccimp_fs_dir_open() - Open a directory in order to list its contents
 *
 * @dir_open_data:	ccimp_fs_dir_open_t struct containing information about
 * 			the folder to open.
 *
 * The directory handle is returned inside the struct.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_dir_open(ccimp_fs_dir_open_t *const dir_open_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	DIR *dirp;
	char *path = realpath(dir_open_data->path, NULL);
	if (path == NULL) {
		dir_open_data->errnum = errno;
		return CCIMP_STATUS_ERROR;
	}

	dirp = opendir(path);
	if (dirp != NULL) {
		dir_data_t *dir_data = calloc(1, sizeof(*dir_data));
		if (dir_data != NULL) {
			dir_open_data->handle = dir_data;
			dir_data->dirp = dirp;
		} else {
			closedir(dirp);
			dir_open_data->errnum = ENOMEM;
			status = CCIMP_STATUS_ERROR;
		}
	} else {
		dir_open_data->errnum = errno;
		status = CCIMP_STATUS_ERROR;
	}

	free(path);

	return status;
}

/**
 * ccimp_fs_dir_read_entry() - Get the list of elements from a directory
 *
 * @dir_read_data:	ccimp_fs_dir_read_entry_t struct containing the directory
 * 			to get its list of elements.
 *
 * Once a directory is open, CCAPI calls this method to get the list of
 * elements (files or directories) that are inside it. Using the handle, the
 * entry_name null-terminated string must be filled (be careful and not write
 * beyond bytes_available). Once the last element is listed, the next entry
 * name must be an empty string.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_dir_read_entry(ccimp_fs_dir_read_entry_t \
		*const dir_read_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;
	dir_data_t *dir_data = (dir_data_t *)dir_read_data->handle;
	struct dirent *p_dirent = NULL;

	errno = 0;
	p_dirent = readdir(dir_data->dirp);
	if (errno != 0) {
		dir_read_data->errnum = errno;
		status = CCIMP_STATUS_ERROR;
	} else if (p_dirent == NULL) {
		/* Finished with the directory. */
		dir_read_data->entry_name[0] = '\0';
	} else {
		/* Valid entry, copy the name. */
		size_t name_len = strlen(p_dirent->d_name);

		if (name_len < dir_read_data->bytes_available) {
			memcpy(dir_read_data->entry_name, p_dirent->d_name, name_len + 1);
		} else {
			dir_read_data->errnum = ENAMETOOLONG;
			status = CCIMP_STATUS_ERROR;
		}
	}

	return status;
}

/**
 * ccimp_fs_dir_entry_status() - Fill information about an entry of a directory
 *
 * @dir_entry_status_data:	ccimp_fs_dir_entry_status_t struct where
 * 				information about the entry element is saved.
 *
 * This method is called for each entry found by ccimp_fs_dir_read_entry() to
 * learn more about the element. The information saved in dir_entry_status_data
 * depends on the entry type:
 *
 *  If it is a file:
 *    - Set type to CCIMP_DIR_ENTRY_FILE
 *    - Size
 *    - Last modification time (seconds since 00:00 1/1/1970)
 *  If it is a subdirectory:
 *    - Set type to CCIMP_DIR_ENTRY_DIR
 *    - Last modification time (seconds since 00:00 1/1/1970)
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_dir_entry_status(ccimp_fs_dir_entry_status_t \
		*const dir_entry_status_data)
{
	struct stat statbuf;
	int const result = stat(dir_entry_status_data->path, &statbuf);

	if (result != 0) {
		dir_entry_status_data->status.type = CCIMP_FS_DIR_ENTRY_UNKNOWN;
		dir_entry_status_data->status.file_size = 0;
		dir_entry_status_data->status.last_modified = 0;
		dir_entry_status_data->errnum = errno;
		return CCIMP_STATUS_ERROR;
	}

	dir_entry_status_data->status.last_modified = \
			(uint32_t)statbuf.st_mtim.tv_sec;
	if (S_ISDIR(statbuf.st_mode)) {
		dir_entry_status_data->status.type = CCIMP_FS_DIR_ENTRY_DIR;
	} else if (S_ISREG(statbuf.st_mode)) {
		dir_entry_status_data->status.type = CCIMP_FS_DIR_ENTRY_FILE;
		dir_entry_status_data->status.file_size = \
				(ccimp_file_offset_t)statbuf.st_size;
	} else {
		dir_entry_status_data->status.type = CCIMP_FS_DIR_ENTRY_UNKNOWN;
	}

	return CCIMP_STATUS_OK;
}

/**
 * ccimp_fs_dir_close() - Close a directory after listing all its contents
 *
 * @dir_close_data:	ccimp_fs_dir_close_t struct containing the information
 * 			of the directory to close.
 *
 * This function is called when a directory has completely been listed. Closes
 * any open handle and frees any resources that ccimp_fs_dir_open() has
 * allocated.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_dir_close(ccimp_fs_dir_close_t *const dir_close_data)
{
	dir_data_t const *const dir_data = dir_close_data->handle;

	closedir(dir_data->dirp);
	free((void *)dir_data);

	return CCIMP_STATUS_OK;
}

/**
 * ccimp_fs_hash_alg() - Set the hash algorithm to be used
 *
 * @hash_status_data:	ccimp_fs_get_hash_alg_t struct containing the hash
 * 			information.
 *
 * CCAPI calls this function to get the hash algorithm that should be used.
 * It can be MD5, SHA512 or CRC32, or none if the device does not support it.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_hash_alg(ccimp_fs_get_hash_alg_t \
		*const hash_status_data)
{
	switch (hash_status_data->hash_alg.requested) {
		case CCIMP_FS_HASH_SHA3_512:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
			hash_status_data->hash_alg.actual = CCIMP_FS_HASH_NONE;
			break;
#endif
		case CCIMP_FS_HASH_NONE:
		case CCIMP_FS_HASH_SHA512:
		case CCIMP_FS_HASH_MD5:
		case CCIMP_FS_HASH_CRC32:
			hash_status_data->hash_alg.actual = hash_status_data->hash_alg.requested;
			break;
		case CCIMP_FS_HASH_BEST:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
			hash_status_data->hash_alg.actual = CCIMP_FS_HASH_SHA512;
#else
			hash_status_data->hash_alg.actual = CCIMP_FS_HASH_SHA3_512;
#endif
			break;
	}

	return CCIMP_STATUS_OK;
}

/**
 * app_calc_crc32() - Calculate the CRC32 hash of a file
 *
 * @path:		Full path of the file to calculate its CRC32 hash.
 * @hash_value:		CRC32 hash that has been calculated.
 * @hash_value_len:	Length of the hash.
 *
 * Returns: The status of the operation.
 */
static ccimp_status_t app_calc_crc32(char const *const path,
		uint8_t *hash_value, size_t const hash_value_len)
{
	uint32_t crc32;
	size_t i;
	int const retval = crc32file(path, &crc32);

	if (retval < 0)
		return CCIMP_STATUS_ERROR;

	for (i = 0; i < hash_value_len; i++) {
		uint32_t const mask = 0xFF000000 >> (8 * i);
		uint8_t const shift = 8 * (hash_value_len - (i + 1));

		hash_value[i] = (crc32 & mask) >> shift;
	}

	return CCIMP_STATUS_OK;
}

/**
 * app_calc_md() - Calculate the hash of a file
 *
 * @path:		Full path of the file to calculate its hash.
 * @hash_value:		Hash that has been calculated.
 * @hash_value_len:	Length of the hash
 * @hash_value_type:	Type of the hash.
 *
 * Returns: The status of the operation.
 */
static ccimp_status_t app_calc_md(char const *const path,
		uint8_t *const hash_value, size_t const hash_value_len,
		EVP_MD const * const hash_value_type)
{
	int ret;
	char buf[APP_HASH_BUFFER_SIZE];
	ccapi_bool_t finished = CCAPI_FALSE;
	ccimp_status_t status;
	EVP_MD_CTX * ctx = NULL;
	int const fd = open(path, O_RDONLY);

	if (fd == -1) {
		/* Cannot access the path, return OK but with a hash of 0. */
		memset(hash_value, 0, hash_value_len);
		return CCIMP_STATUS_OK;
	}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	ctx = EVP_MD_CTX_create();
#else
	ctx = EVP_MD_CTX_new();
#endif
	if (ctx == NULL || (EVP_DigestInit_ex(ctx, hash_value_type, NULL) == 0)) {
		goto error;
	}

	do {
		ret = read(fd, buf, sizeof buf);
		if (ret > 0) {
			if (EVP_DigestUpdate(ctx, buf, ret) != 1) {
				finished = CCAPI_TRUE;
				ret = -1;
			}
		} else if (ret == 0 || (ret == -1 && errno != EAGAIN)) {
			finished = CCAPI_TRUE;
		}
	} while (finished == CCAPI_FALSE);

	if (ret == 0 && EVP_DigestFinal_ex(ctx, hash_value, NULL) == 1) {
		status = CCIMP_STATUS_OK;
		goto done;
	}

error:
	memset(hash_value, 0, hash_value_len);
	status = CCIMP_STATUS_ERROR;

done:
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	EVP_MD_CTX_destroy(ctx);
#else
	EVP_MD_CTX_free(ctx);
#endif
	close(fd);
	return status;
}

/**
 * ccimp_fs_hash_file() - Call the proper hash calculation method for a file
 *
 * @file_hash_data:	ccimp_fs_hash_file_t struct containing the hash
 * 			information of a file.
 *
 * When Remote Manager asks for a hash (md5sum or crc32) of a file, CCAPI calls
 * this method, which will execute the corresponding hash calculation process.
 * It may take more than 1 second to calculate the hash.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_hash_file(ccimp_fs_hash_file_t *const file_hash_data)
{
	ccimp_status_t status = CCIMP_STATUS_OK;

	switch (file_hash_data->hash_algorithm) {
		case CCIMP_FS_HASH_CRC32:
			status = app_calc_crc32(file_hash_data->path,
					file_hash_data->hash_value, file_hash_data->bytes_requested);
			break;
		case CCIMP_FS_HASH_MD5:
			status = app_calc_md(file_hash_data->path, file_hash_data->hash_value,
					file_hash_data->bytes_requested, EVP_md5());
			break;
		case CCIMP_FS_HASH_SHA512:
			status = app_calc_md(file_hash_data->path, file_hash_data->hash_value,
					file_hash_data->bytes_requested, EVP_sha512());
			break;
		case CCIMP_FS_HASH_SHA3_512:
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
			status = app_calc_md(file_hash_data->path, file_hash_data->hash_value,
					file_hash_data->bytes_requested, EVP_sha3_512());
			break;
#endif
		case CCIMP_FS_HASH_NONE:
		case CCIMP_FS_HASH_BEST:
			break;
	}

	return status;
}

/**
 * ccimp_fs_error_desc() - Parse the errnum into a readable string
 *
 * @error_desc_data:	ccimp_fs_error_desc_t struct containing the errnum to
 * 			parse, the error_string and the error_status to be set.
 *
 * This function is called when any of the file, directory or hash operations
 * functions return CCIMP_STATUS_ERROR.
 *
 * The error_string is displayed in Remote Manager or in the XML data if a Web
 * Service initiated the request.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_error_desc(ccimp_fs_error_desc_t \
		*const error_desc_data)
{
	ccimp_fs_errnum_t errnum = error_desc_data->errnum;

	error_desc_data->bytes_used = 0;

	if (errnum != 0) {
		char *err_str = strerror(errnum);

		error_desc_data->bytes_used = MIN_VALUE(strlen(err_str),
				error_desc_data->bytes_available);
		memcpy(error_desc_data->error_string, err_str,
				error_desc_data->bytes_used);
	}

	switch(errnum) {
		case EACCES:
		case EPERM:
		case EROFS:
			error_desc_data->error_status = CCIMP_FS_ERROR_PERMISSION_DENIED;
			break;
		case ENOMEM:
		case ENAMETOOLONG:
			error_desc_data->error_status = CCIMP_FS_ERROR_INSUFFICIENT_MEMORY;
			break;
		case ENOENT:
		case ENODEV:
		case EBADF:
			error_desc_data->error_status = CCIMP_FS_ERROR_PATH_NOT_FOUND;
			break;
		case EINVAL:
		case ENOSYS:
		case ENOTDIR:
		case EISDIR:
			error_desc_data->error_status = CCIMP_FS_ERROR_INVALID_PARAMETER;
			break;
		case ENOSPC:
			error_desc_data->error_status = CCIMP_FS_ERROR_INSUFFICIENT_SPACE;
			break;
		default:
			error_desc_data->error_status = CCIMP_FS_ERROR_UNKNOWN;
			break;
	}

	return CCIMP_STATUS_OK;
}

/**
 * ccimp_fs_session_error() - Print the session error
 *
 * @session_error_data:		ccimp_fs_session_error_t struct containing the
 * 				session error data.
 *
 * This function is called if an error is found while handling a file system
 * session, which might be caused by network communication problems, session
 * timeout, insufficient memory, etc.
 *
 * Returns: The status of the operation.
 */
ccimp_status_t ccimp_fs_session_error(ccimp_fs_session_error_t \
		*const session_error_data)
{
	if (!session_error_data)
		return CCIMP_STATUS_OK;

	log_error(ERROR_SESSION, session_error_data->session_error);
	free(session_error_data->imp_context);

	return CCIMP_STATUS_OK;
}
