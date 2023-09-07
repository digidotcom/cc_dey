/*
 * Copyright (c) 2022, 2023 Digi International Inc.
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
#include <libdigiapix/process.h>
#include <poll.h>
#include <pthread.h>
#include <pty.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ccapi/ccapi.h"
#include "cc_logging.h"
#include "signals.h"

#define CLI_TAG			"CLI:"

/**
 * log_cli_debug() - Log the given message as debug
 *
 * @format:	Debug message to log.
 * @args:	Additional arguments.
 */
#define log_cli_debug(format, ...)			\
	log_debug("%s " format, CLI_TAG, __VA_ARGS__)

/**
 * log_cli_info() - Log the given message as info
 *
 * @format:	Info message to log.
 * @args:	Additional arguments.
 */
#define log_cli_info(format, ...)			\
	log_info("%s " format, CLI_TAG, __VA_ARGS__)

/**
 * log_cli_error() - Log the given message as error
 *
 * @format:	Error message to log.
 * @args:	Additional arguments.
 */
#define log_cli_error(format, ...)			\
	log_error("%s " format, CLI_TAG, __VA_ARGS__)

#define DEFAULT_TIMEOUT_STR		"10"

typedef enum {
	sessionless_execute_state_init,
	sessionless_execute_state_running,
	sessionless_execute_state_reading,
	sessionless_execute_state_clean,
	sessionless_execute_state_done,
	sessionless_execute_state_forbidden
} sessionless_execute_state_t;

typedef struct
{
	int timeout;
	FILE *file_command;
	FILE *file_output;
	int start;
	sessionless_execute_state_t state;
} connection_handle_execute_t;

typedef struct {
	int pty;
	pid_t pid;
	connection_handle_execute_t execute;
} connection_handle_t;

static int exec_cli(void)
{
	const char *argv[2];
	const char *envp[1];
	int ret;

	argv[0] = "/bin/login";
	argv[1] = NULL; /* No arguments */
	envp[0] = NULL; /* No environment variables */

	ret = execve(argv[0], (char * const *)argv, (char * const *)envp);

	return ret;
}

static int configure_pty(int pty)
{
	int const current = fcntl(pty, F_GETFL);

	return fcntl(pty, F_SETFL, current | O_NONBLOCK | O_CLOEXEC);
}

static void *kill_session_thread(void *arg)
{
	connection_handle_t *conn = (connection_handle_t *) arg;
	pid_t pid = conn->pid;

	if (conn->pid != -1)
		log_cli_debug("Kill session '%u'", pid);
	else
		log_cli_debug("%s", "Kill session");

	if (conn->pty != -1)
		close(conn->pty);

	if (conn->pid != -1) {
		kill(conn->pid, SIGTERM);

		waitpid(conn->pid, NULL, 0);
		conn->pid = -1;
		log_cli_debug("Killed session '%u'", pid);
	}
	free(conn);

	return NULL;
}

static void kill_session(connection_handle_t *conn)
{
	pthread_t thread;
	pthread_attr_t attr;
	int err;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	err = pthread_create(&thread, &attr, kill_session_thread, conn);
	if (err)
		/* Last resort: kill the child directly and let this process wait */
		kill_session_thread(conn);

	pthread_attr_destroy(&attr);
}

static connector_callback_status_t start_session(connector_streaming_cli_session_start_request_t *request)
{
	connection_handle_t *conn;
	pid_t child_process = 0;
	int master = 0;
	int ret;

	log_cli_info("%s", "Start session");

	if (request->terminal_mode != connector_cli_terminal_vt100) {
		log_cli_error("Failed to start session: non-VT100 terminal mode (mode: %d)",
			request->terminal_mode);

		return connector_callback_error;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		log_cli_error("Failed to start session: %s", "Out of memory");

		return connector_callback_error;
	}

	child_process = forkpty(&master, NULL, NULL, NULL);
	if (child_process == 0) {
		if (enable_signals() == 0) {
			ret = exec_cli();
			log_cli_error("Failed to start session (%d)", ret);
		} else {
			log_cli_error("Failed to start session: %s", "Error enabling signals");
		}

		exit(1);
	} else if (child_process == -1) {
		log_cli_error("Failed to start session: %s (%d)", strerror(errno), errno);
		close(master);
		free(conn);

		return connector_callback_error;
	}

	conn->pty = master;
	conn->pid = child_process;
	conn->execute.timeout = 0;

	if (configure_pty(master)) {
		log_cli_error("Failed to configure session: %s (%d)", strerror(errno), errno);

		kill_session(conn);

		return connector_callback_error;
	}

	request->handle = conn;

	log_cli_debug("Session started: '%u'", conn->pid);

	return connector_callback_continue;
}

static connector_callback_status_t poll_session(connector_streaming_cli_poll_request_t *request)
{
	connection_handle_t *conn = request->handle;
	int n_bytes;

	if (ioctl(conn->pty, FIONREAD, &n_bytes) || n_bytes < 0) {
		log_cli_error("Unable to check data to read: %s (%d)", strerror(errno), errno);

		return connector_callback_error;
	}

	if (n_bytes == 0) {
		struct pollfd fd = {
			conn->pty,
			POLLIN,
			0
		};
		poll(&fd, 1, 0);

		request->session_state = fd.revents & POLLHUP ? connector_cli_session_state_done : connector_cli_session_state_idle;
	} else {
		request->session_state = connector_cli_session_state_readable;
	}

	return connector_callback_continue;
}

static connector_callback_status_t send_data(connector_streaming_cli_session_send_data_t *request)
{
	connection_handle_t *conn = request->handle;
	int n_left;
	ssize_t n_read;

	ioctl(conn->pty, FIONREAD, &n_left);
	n_read = read(conn->pty, request->buffer, request->bytes_available);
	if (n_read < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return connector_callback_busy;

		log_cli_error("Failed to send data: %s (%d)", strerror(errno), errno);
		request->bytes_used = 0;

		return connector_callback_error;
	}
	request->bytes_used = n_read;

	request->more_data = n_read < n_left ? connector_true : connector_false;

	return connector_callback_continue;
}

static connector_callback_status_t receive_data(connector_streaming_cli_session_receive_data_t *request)
{
	ssize_t n_written = 0;
	connection_handle_t *conn = request->handle;

	n_written = write(conn->pty, request->buffer, request->bytes_available);
	if (n_written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			n_written = 0;
		} else {
			log_cli_error("Failed to receive data: %s (%d)", strerror(errno), errno);

			return connector_callback_error;
		}
	}

	request->bytes_used = n_written;

	return connector_callback_continue;
}

static connector_callback_status_t end_session(connector_streaming_cli_session_end_request_t * const request)
{
	connection_handle_t *conn = request->handle;

	if (conn->pid != -1)
		log_cli_info("End session '%u'", conn->pid);
	else
		log_cli_info("%s", "End session");

	if (conn->execute.file_command != NULL) {
		fclose(conn->execute.file_command);
		conn->execute.file_command = NULL;
	}

	if (conn->execute.file_output != NULL) {
		fclose(conn->execute.file_output);
		conn->execute.file_output = NULL;
	}

	kill_session(conn);

	return connector_callback_continue;
}

static connector_callback_status_t sessionless_execute(connector_streaming_cli_session_sessionless_execute_run_request_t * const request)
{
	connection_handle_t *conn = (connection_handle_t *) request->handle;
	FILE *file_command = conn->execute.file_command;
	FILE *file_output = conn->execute.file_output;

	log_cli_info("%s", "Execute command");

	if (conn->execute.state == sessionless_execute_state_init) {
		int timeout_length = snprintf(NULL, 0, "%d", conn->execute.timeout);
		char *timeout_str = calloc(timeout_length + 1, sizeof(*timeout_str));

		if (timeout_str)
			snprintf(timeout_str, timeout_length + 1, "%d", conn->execute.timeout);
		else
			log_cli_info("Unable to get timeout (using default value '%s'): Out of memory", DEFAULT_TIMEOUT_STR);

		fseek(file_command, 0, SEEK_SET);
		fseek(file_output, 0, SEEK_SET);

		conn->execute.start = (int) time(NULL);

		conn->pid = ldx_process_exec_fd(fileno(file_command),
			fileno(file_output), fileno(file_output),
			"timeout", timeout_str != NULL ? timeout_str : DEFAULT_TIMEOUT_STR,
			"/bin/sh");

		free(timeout_str);
		request->more_data = connector_true;

		conn->execute.state = sessionless_execute_state_running;

		log_cli_info("Start command execution: '%u'", conn->pid);
	}

	if (conn->execute.state == sessionless_execute_state_running) {
		int status;
		int ret = waitpid(conn->pid, &status, WNOHANG);

		if (ret == 0) {
			int time_elapsed = (int) time(NULL) - conn->execute.start;
			if (time_elapsed > conn->execute.timeout) {
				kill(conn->pid, SIGKILL);

				waitpid(conn->pid, NULL, 0);
				request->status = -13;
			} else {
				sleep(1); /* Avoid flooding the request */

				return connector_callback_busy;
			}
		} else if (ret != conn->pid) {
			request->status = -257;
		} else if (WIFEXITED(status)) {
			request->status = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			request->status = -WTERMSIG(status);
		} else {
			request->status = -258;
		}
		conn->pid = -1;
		request->more_data = connector_true;
		conn->execute.state = sessionless_execute_state_reading;

		log_cli_debug("Execution status: 0x%x (%d)", request->status, request->status);
	}

	if (conn->execute.state == sessionless_execute_state_reading) {
		int n_left;
		ssize_t n_read;

		fseek(file_output, 0, SEEK_SET);
		ioctl(fileno(conn->execute.file_output), FIONREAD, &n_left);
		n_read = read(fileno(conn->execute.file_output), request->buffer, request->bytes_available);

		fseek(file_output, n_read, SEEK_CUR);
		if (n_read < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return connector_callback_busy;

			request->bytes_used = 0;
			log_cli_error("Failed to get response: %s (%d)", strerror(errno), errno);

			return connector_callback_error;
		}
		request->bytes_used = n_read;
		request->more_data = n_read < n_left ? connector_true : connector_false;

		if (!request->more_data) {
			conn->execute.state = sessionless_execute_state_clean;
		} else {
			FILE *resize_file = conn->execute.file_output;
			char *old_contents = NULL;
			char *new_contents = NULL;
			/* Get total message size */
			size_t bytes_remaining = 0;

			fseek(resize_file, 0, SEEK_END);
			bytes_remaining = (size_t) ftell(resize_file);
			/* Get old message contents */
			fseek(resize_file, 0, SEEK_SET);
			old_contents = calloc(bytes_remaining, sizeof(*old_contents));
			if (old_contents) {
				n_read = fread(old_contents, 1, bytes_remaining, resize_file);
				/* Get new message (old message minus what we sent) */
				new_contents = old_contents;
				new_contents += request->bytes_used;
				/* Close file to delete, then create a new empty file */
				fclose(resize_file);
				resize_file = tmpfile();
				/* Save and tidy */
				conn->execute.file_output = resize_file;
				n_read = write(fileno(resize_file), new_contents, bytes_remaining - request->bytes_used);
				free(old_contents);
			} else {
				log_cli_error("Failed to get response: %s", "Out of memory");
			}
		}
	}

	if (conn->execute.state == sessionless_execute_state_clean) {
		fclose(conn->execute.file_command);
		conn->execute.file_command = NULL;
		fclose(conn->execute.file_output);
		conn->execute.file_output = NULL;

		conn->execute.state = sessionless_execute_state_done;
	}

	return connector_callback_continue;
}

static connector_callback_status_t sessionless_store(connector_streaming_cli_session_sessionless_execute_store_request_t * const request)
{
	connection_handle_t *conn = NULL;
	ssize_t n_written = 0;

	log_cli_info("Store command: '%s'", request->buffer);

	if (request->init) {
		conn = calloc(1, sizeof(*conn));
		if (!conn) {
			log_cli_error("Failed to store command: %s", "Out of memory");

			return connector_callback_error;
		}
		conn->pty = -1;
		conn->pid = -1;
		conn->execute.file_command = tmpfile();
		conn->execute.file_output = tmpfile();
		conn->execute.timeout = request->timeout;
		conn->execute.state = sessionless_execute_state_init;

		request->handle = conn;
	} else {
		conn = (connection_handle_t *) request->handle;
	}

	n_written = write(fileno(conn->execute.file_command), request->buffer, request->bytes_available);
	if (n_written < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			n_written = 0;
		} else {
			log_cli_error("Failed to store command: %s (%d)", strerror(errno), errno);

			return connector_callback_error;
		}
	}
	request->bytes_used = n_written;

	return connector_callback_continue;
}

ccapi_streaming_cli_service_t streaming_cli_service = {
	start_session,
	poll_session,
	send_data,
	receive_data,
	end_session,
	sessionless_execute,
	sessionless_store
};
