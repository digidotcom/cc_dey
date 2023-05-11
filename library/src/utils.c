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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include "cc_logging.h"
#include "_utils.h"
#include "utils.h"

/**
 * file_exists() - Check that the file with the given name exists
 *
 * @filename:	Full path of the file to check if it exists.
 *
 * Return: 1 if the file exits, 0 if it does not exist.
 */
int file_exists(const char * const filename)
{
	return access(filename, F_OK) == 0;
}

/**
 * file_readable() - Check that the file with the given name can be read
 *
 * @filename:	Full path of the file to check if it is readable.
 *
 * Return: 1 if the file is readable, 0 if it cannot be read.
 */
int file_readable(const char * const filename)
{
	return access(filename, R_OK) == 0;
}

/**
 * file_writable() - Check that the file with the given name can be written
 *
 * @filename:	Full path of the file to check if it is writable.
 *
 * Return: 1 if the file is writable, 0 if it cannot be written.
 */
int file_writable(const char * const filename)
{
	return access(filename, W_OK) == 0;
}

/**
 * mkpath() - Create a directory and its parents if they do not exist
 *
 * @dir:	Full path of the directory to create.
 * @mode:	Permissions to use.
 *
 * Return: 0 if success, -1 otherwise.
 */
int mkpath(char *dir, mode_t mode)
{
	struct stat sb;
	char *p = NULL;
	char tmp[PATH_MAX + 2]; /* path + last separator + null */
	size_t len = 0;

	if (dir == NULL) {
		errno = EINVAL;
		return -1;
	}

	len = strlen(dir);
	if(len == 0 || len > PATH_MAX) {
		errno = EINVAL;
		return -1;
	}

	if (len == 1 && dir[0] == '/')
		return 0;

	strncpy(tmp, dir, len);
	tmp[len] = 0;
	if (tmp[len - 1] != '/') {
		tmp[len] = '/';
		tmp[len + 1] = 0;
	}

	for (p = tmp; *p; p++) {
		if (*p != '/')
			continue;
		*p = 0;
		if (strlen(tmp) > 0) {
			if (stat(tmp, &sb) != 0) {
				if (mkdir(tmp, mode) < 0)
					return -1;
			} else if (!S_ISDIR(sb.st_mode)) {
				errno = EROFS;
				return -1;
			}
		}
		*p = '/';
	}

	return 0;
}

/**
 * read_file() - Read the given file and returns its contents
 *
 * @path:		Absolute path of the file to read.
 * @buffer:		Buffer to store the contents of the file.
 * @file_size:	The number of bytes to read.
 *
 * Return: The number of read bytes.
 */
long read_file(const char *path, char *buffer, long file_size)
{
	FILE *fd = NULL;
	long read_size = -1;

	if ((fd = fopen(path, "rb")) == NULL) {
		log_debug("%s: fopen error: %s", __func__, path);
		return -1;
	}

	read_size = fread(buffer, sizeof(char), file_size, fd);
	if (ferror(fd)) {
		log_debug("%s: fread error: %s", __func__, path);
		goto done;
	}

	buffer[read_size - 1] = '\0';

done:
	fclose(fd);

	return read_size;
}

/**
 * read_file_line() - Read the first line of the file and return its contents
 *
 * @path:			Absolute path of the file to read.
 * @buffer:			Buffer to store the contents of the file.
 * @bytes_to_read:	The number of bytes to read.
 *
 * Return: 0 on success, -1 on error.
 */
int read_file_line(const char * const path, char *buffer, int bytes_to_read)
{
	FILE *fd = NULL;
	int error = 0;

	if (!file_readable(path)) {
		log_error("%s: file is not readable: %s", __func__, path);
		return -1;
	}
	if ((fd = fopen(path, "rb")) == NULL) {
		log_error("%s: fopen error: %s", __func__, path);
		return -1;
	}
	if (fgets(buffer, bytes_to_read, fd) == NULL) {
		log_error("%s: fgets error: %s", __func__, path);
		error = -1;
	}
	fclose(fd);

	return error;
}

/**
 * write_to_file() - Write data to a file
 *
 * @path:		Absolute path of the file to be written.
 * @format:		String that contains the text to be written to the file.
 *
 * Return: 0 if the file was written successfully, -1 otherwise.
 */
int write_to_file(const char * const path, const char * const format, ...)
{
	va_list args;
	FILE *f = NULL;
	int len, error = 0;

	if (!file_writable(path)) {
		log_error("%s: file cannot be written: %s", __func__, path);
		return -1;
	}
	va_start(args, format);
	f = fopen(path, "w");
	if (f == NULL) {
		log_error("%s: fopen error: %s", __func__, path);
		error = -1;
		goto done;
	}
	len = vfprintf(f, format, args);
	if (len < 0) {
		log_error("%s: vfprintf error: %s", __func__, path);
		error = -1;
	}
	fsync(fileno(f));
	fclose(f);

done:
	va_end(args);

	return error;
}

/**
 * crc32file() - Calculate the CRC32 hash of a file
 *
 * @path:	Full path of the file to calculate its CRC32 hash.
 * @crc:	CRC32 hash calculated.
 *
 * Returns: 0 if success, -1 otherwise.
 */
int crc32file(char const *const path, uint32_t *crc)
{
	Bytef buff[1024];
	ssize_t read_bytes;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd == -1)
		return -1;

	*crc = 0;
	while ((read_bytes = read(fd, buff, sizeof buff)) > 0)
		*crc = crc32(*crc, buff, read_bytes);

	close (fd);

	return read_bytes == 0 ? 0 : -1;
}

/*
 * delete_quotes() - Delete quotes from the given string.
 *
 * @str:	String to delete quotes from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without the quotes.
 */
char *delete_quotes(char *str)
{
	int len = 0;

	if (str == NULL)
		return str;

	len = strlen(str);
	if (len == 0)
		return str;

	if (str[len - 1] == '"')
		str[len - 1] = 0;

	if (str[0] == '"')
		memmove(str, str + 1, len);

	return str;
}

/*
 * delete_leading_spaces() - Delete leading spaces from the given string.
 *
 * @str:	String to delete leading spaces from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without leading white spaces.
 */
char *delete_leading_spaces(char *str)
{
	int len = 0;
	char *p = str;

	if (str == NULL || strlen(str) == 0)
		return str;

	while (isspace(*p) || !isprint(*p))
		++p;

	len = strlen(p);
	memmove(str, p, len);
	str[len] = 0;

	return str;
}

/*
 * delete_trailing_spaces() - Delete trailing spaces from the given string.
 *
 * Trailing spaces also include new line '\n' and carriage return '\r' chars.
 *
 * @str:	String to delete trailing spaces from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without trailing white spaces.
 */
char *delete_trailing_spaces(char *str)
{
	char *p = NULL;

	if (str == NULL || strlen(str) == 0)
		return str;

	p = str + strlen(str) - 1;

	while ((isspace(*p) || !isprint(*p) || *p == 0) && p >= str)
		--p;

	*++p = 0;

	return str;
}

/*
 * trim() - Trim the given string removing leading and trailing spaces.
 *
 * Trailing spaces also include new line '\n' and carriage return '\r' chars.
 *
 * @str:	String to delete leading and trailing spaces from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without leading nor trailing white spaces.
 */
char *trim(char *str)
{
	return delete_leading_spaces(delete_trailing_spaces(str));
}

/*
 * delete_newline_character() - Remove new line character '\n' from the end of
 *                              the given string.
 *
 * @str:	String to delete ending new line character '\n' from.
 *
 * This function modifies the original string.
 *
 * Return: The original string without the final new line.
 */
char *delete_newline_character(char *str)
{
	int len = 0;

	if (str == NULL)
		return str;

	len = strlen(str);
	if (len == 0)
		return str;

	if (str[len - 1] == '\n')
		str[len - 1] = '\0';

	return str;
}
