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

int file_exists(const char * const filename)
{
	return access(filename, F_OK) == 0;
}

int file_readable(const char * const filename)
{
	return access(filename, R_OK) == 0;
}

int file_writable(const char * const filename)
{
	return access(filename, W_OK) == 0;
}

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

char *trim(char *str)
{
	return delete_leading_spaces(delete_trailing_spaces(str));
}

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
