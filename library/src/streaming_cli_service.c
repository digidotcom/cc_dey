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
	log_error("%s: Error executing execve()", __func__);   /* execve() returns only on error */

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

	log_debug("Stopping CLI process %u", pid);
	if (conn->pty != -1)
		close(conn->pty);

	if (conn->pid != -1) {
		kill(conn->pid, SIGTERM);

		waitpid(conn->pid, NULL, 0);
		conn->pid = -1;
		log_debug("Stopped CLI process %u", pid);
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

	log_debug("    Called '%s'", __func__);
	if (request->terminal_mode != connector_cli_terminal_vt100) {
		log_error("%s: Rejecting non-VT100 terminal_mode of: %d", __func__, request->terminal_mode);
		return connector_callback_error;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return connector_callback_error;

	child_process = forkpty(&master, NULL, NULL, NULL);
	if (child_process == 0) {
		if (enable_signals() == 0) {
			ret = exec_cli();
			log_error("%s: Error executing CLI (%d)", __func__, ret);
		} else {
			log_error("%s: Error enabling process signals", __func__);
		}

		exit(1);
	} else if (child_process == -1) {
		log_debug("Failed to start CLI process. errno: %d", errno);
		close(master);
		free(conn);

		return connector_callback_error;
	}

	conn->pty = master;
	conn->pid = child_process;
	conn->execute.timeout = 0;

	if (configure_pty(master)) {
		kill_session(conn);

		return connector_callback_error;
	}

	request->handle = conn;

	return connector_callback_continue;
}

static connector_callback_status_t poll_session(connector_streaming_cli_poll_request_t *request)
{
	connection_handle_t *conn = request->handle;
	int n_bytes;

	if (ioctl(conn->pty, FIONREAD, &n_bytes) || n_bytes < 0)
		return connector_callback_error;

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
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			n_written = 0;
		else
			return connector_callback_error;
	}

	request->bytes_used = n_written;

	return connector_callback_continue;
}

static connector_callback_status_t end_session(connector_streaming_cli_session_end_request_t * const request)
{
	connection_handle_t *conn = request->handle;

	log_debug("    Called '%s'", __func__);
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
	UNUSED_ARGUMENT(request);

	log_debug("    Called '%s'", __func__);

	return connector_callback_continue;
}

static connector_callback_status_t sessionless_store(connector_streaming_cli_session_sessionless_execute_store_request_t * const request)
{
	UNUSED_ARGUMENT(request);

	log_debug("    Called '%s'", __func__);

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
