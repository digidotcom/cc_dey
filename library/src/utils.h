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

#ifndef __UTILS_H__
#define __UTILS_H__

#define IPV4_GROUPS			4
#define MAC_ADDRESS_GROUPS	6

#define IP_STRING_LENGTH 	(4 * IPV4_GROUPS)
#define IP_FORMAT			"%d.%d.%d.%d"
#define MAC_STRING_LENGTH	(3 * MAC_ADDRESS_GROUPS)
#define MAC_FORMAT			"%02x:%02x:%02x:%02x:%02x:%02x"

/**
 * file_exists() - Check that the file with the given name exists
 *
 * @filename:	Full path of the file to check if it exists.
 *
 * Return: 1 if the file exits, 0 if it does not exist.
 */
int file_exists(const char * const filename);

/**
 * file_readable() - Check that the file with the given name can be read
 *
 * @filename:	Full path of the file to check if it is readable.
 *
 * Return: 1 if the file is readable, 0 if it cannot be read.
 */

int file_readable(const char * const filename);

/**
 * file_writable() - Check that the file with the given name can be written
 *
 * @filename:	Full path of the file to check if it is writable.
 *
 * Return: 1 if the file is writable, 0 if it cannot be written.
 */
int file_writable(const char * const filename);

/**
 * read_file() - Read the given file and returns its contents
 *
 * @path:		Absolute path of the file to read.
 * @buffer:		Buffer to store the contents of the file.
 * @file_size:	The number of bytes to read.
 *
 * Return: The number of read bytes.
 */
long read_file(const char *path, char *buffer, long file_size);

/**
 * read_file_line() - Read the first line of the file and return its contents
 *
 * @path:			Absolute path of the file to read.
 * @buffer:			Buffer to store the contents of the file.
 * @bytes_to_read:	The number of bytes to read.
 *
 * Return: 0 on success, -1 on error.
 */
int read_file_line(const char * const path, char *buffer, int bytes_to_read);

/**
 * write_to_file() - Write data to a file
 *
 * @path:		Absolute path of the file to be written.
 * @format:		String that contains the text to be written to the file.
 *
 * Return: 0 if the file was written successfully, -1 otherwise.
 */
int write_to_file(const char * const path, const char * const format, ...);

#endif /* __UTILS_H__ */
