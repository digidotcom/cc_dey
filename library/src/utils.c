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
#include <dirent.h>
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

#define DAEMON_NAME			"CCCSD"

int init_logger(int level, int options, char *name)
{
	if (!name)
		openlog(DAEMON_NAME, options, LOG_USER);
	else
		openlog(name, options, LOG_USER);
	setlogmask(LOG_UPTO(level));

	/* Init CCAPI logging */
	return ccimp_logging_init();
}

void deinit_logger(void)
{
	ccimp_logging_deinit();
	closelog();
}

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

int write_buffer_to_file(char const * const path, char const * const buff, size_t size)
{
	FILE *f = NULL;
	size_t n_written;

	if (!buff || !size || !path || path[0] == '\0')
		return 0;

	f = fopen(path, "wb+");
	if (!f) {
		log_error("Unable to open file '%s' to write: %s (%d)", path, strerror(errno), errno);
		return 1;
	}

	n_written = fwrite(buff, sizeof(*buff), size, f);
	if (n_written < size)
		log_error("Unable to write to file '%s': %s (%d)", path, strerror(errno), errno);

	fclose(f);

	return n_written != size;
}

int cp_file(char const * const in_path, char const * const out_path)
{
	int fd_in = -1, fd_out = -1;
	char buffer[1024 * 2];
	struct stat stat;
	ssize_t len, n_read, n_write;
	int ret;

	if (!in_path || in_path[0] == '\0' || !out_path || out_path[0] == '\0')
		return 0;

	fd_in = open(in_path, O_RDONLY);
	if (fd_in == -1) {
		log_error("Unable to copy file '%s', cannot open file: %s (%d)",
			in_path, strerror(errno), errno);
		return 1;
	}

	fd_out = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd_out == -1) {
		log_error("Unable to copy file '%s', cannot create destination file: %s (%d)",
			in_path, strerror(errno), errno);
		ret = 1;
		goto done;
	}

	if (fstat(fd_in, &stat)) {
		log_error("Unable to copy file '%s', cannot get size: %s (%d)",
			in_path, strerror(errno), errno);
		ret = 1;
		goto done;
	}

	len = stat.st_size;

	while (len > 0) {
		n_read = read(fd_in, buffer, sizeof(buffer) / sizeof(buffer[0]));
		if (n_read == -1) {
			log_error("Unable to copy file '%s', cannot read: %s (%d)",
				in_path, strerror(errno), errno);
			ret = 1;
			goto done;
		}

		n_write = 0;
		while (n_write < n_read) {
			int n_w = write(fd_out, buffer, n_read - n_write);

			if (n_w == -1) {
				log_error("Unable to copy file '%s', cannot write to destination: %s (%d)",
					in_path, strerror(errno), errno);
				ret = 1;
				goto done;
			}

			n_write += n_w;
		}

		len -= n_write;
	}

	ret = 0;
done:
	close(fd_in);
	close(fd_out);

	if (ret)
		remove(out_path);

	return ret;
}

int get_directory_size(const char * const dir_path, unsigned long long *dir_size)
{
	struct dirent *p_dirent = NULL;
	DIR *dirp = NULL;
	char buf[PATH_MAX];
	int ret = 0;

	*dir_size = 0L;

	if (!dir_path || !strlen(dir_path))
		return 0;

	strcpy(buf, dir_path);
	strcat(buf, "/");

	dirp = opendir(dir_path);
	if (!dirp) {
		if (errno == ENOENT)
			return -1;
		return 1;
	}

	while ((p_dirent = readdir(dirp))) {
		struct stat st;

		if (strcmp(p_dirent->d_name, "..") == 0
			|| strcmp(p_dirent->d_name, ".") == 0)
			continue;

		buf[strlen(dir_path) + 1] = '\0';
		strcat(buf, p_dirent->d_name);

		if (stat(buf, &st)) {
			log_error("Unable to get size of '%s' in directory '%s': %s (%d)",
				buf, dir_path, strerror(errno), errno);
			ret = 1;
			break;
		}

		if (S_ISREG(st.st_mode)) {
			*dir_size += st.st_size;
		} else {
			unsigned long long s;

			if (get_directory_size(buf, &s) != 0) {
				ret = 1;
				break;
			}
			*dir_size += s;
		}
	}
	closedir(dirp);

	if (ret)
		*dir_size = 0L;

	return ret;
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
