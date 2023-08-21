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

#include <cloudconnector.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "daemonize.h"
#include "device_request.h"

#define VERSION		"0.1" GIT_REVISION

#define USAGE \
	"Cloud Connector client.\n" \
	"Copyright(c) Digi International Inc.\n" \
	"\n" \
	"Version: %s\n" \
	"\n" \
	"Usage: %s [options]\n\n" \
	"  -d  --daemon              Daemonize the process\n" \
	"  -c  --config-file=<PATH>  Use a custom configuration file instead of\n" \
	"                            the default one located in /etc/cc.conf\n" \
	"  -h  --help                Print help and exit\n" \
	"\n"

#define REQUEST_TARGETS_DUMP_PATH	"/tmp/cc_request_targets.bin"

volatile bool restart = false;
static volatile bool stop = false;

/**
 * signal_handler() - Manage signal received.
 *
 * @sig_num: Received signal.
 */
static void signal_handler(int sig_num)
{
	log_debug("%s: Received signal %d to close Cloud connection.", __func__, sig_num);
	stop = true;
}

/*
 * setup_signal_handler() - Setup process signals
 *
 * Return: 0 on success, 1 otherwise.
 */
static int setup_signal_handler(void)
{
	struct sigaction new_action, old_action;
	sigset_t set;

	memset(&new_action, 0, sizeof(new_action));
	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		if (sigaction(SIGINT, &new_action, NULL)) {
			log_error("%s", "Failed to install signal handler");
			return 1;
		}
	}

	sigemptyset(&set);
	sigaddset(&set, SIGINT);

	if (pthread_sigmask(SIG_UNBLOCK, &set, NULL)) {
		log_error("%s", "Failed to unblock SIGTERM");
		return 1;
	}

	return 0;
}

/*
 * start_connector() - Start Cloud Connector
 *
 * @config_file:	Absolute path of the configuration file to use. NULL to
 * 			use the default one (/etc/cc.conf).
 *
 * Return: 0 on success, 1 otherwise.
 */
static int start_connector(const char *config_file)
{
	cc_init_error_t init_error;
	cc_start_error_t start_error;

	if (setup_signal_handler())
		return EXIT_FAILURE;

	do {
		restart = false;

		init_error = init_cloud_connection(config_file);
		if (init_error != CC_INIT_ERROR_NONE && init_error != CC_INIT_ERROR_ADD_VIRTUAL_DIRECTORY) {
			log_error("Cannot initialize cloud connection, error %d", init_error);
			return EXIT_FAILURE;
		}

		register_cc_device_requests();

		import_devicerequests(REQUEST_TARGETS_DUMP_PATH);

		start_error = start_cloud_connection();
		if (start_error != CC_START_ERROR_NONE) {
			log_error("Cannot start cloud connection, error %d", start_error);
			return EXIT_FAILURE;
		}

		do {
			sleep(2);
		} while (get_cloud_connection_status() != CC_STATUS_DISCONNECTED && !stop && !restart);

		if (restart)
			dump_devicerequests(REQUEST_TARGETS_DUMP_PATH);

		unregister_cc_device_requests();

		stop_cloud_connection();
	} while (restart);

	return EXIT_SUCCESS;
}

/**
 * usage() - Print usage information
 *
 * @name:	Name of the daemon.
 */
static void usage(char const *const name)
{
	printf(USAGE, VERSION, name);
}

int main(int argc, char *argv[])
{
	int result = EXIT_SUCCESS;
	char *name = basename(argv[0]);
	static int opt, opt_index;
	int create_daemon = 0;
	int log_options = LOG_CONS | LOG_NDELAY | LOG_PID | LOG_PERROR;
	char *config_file = NULL;
	static const char *short_options = "dc:h";
	static const struct option long_options[] = {
			{"daemon", no_argument, NULL, 'd'},
			{"config-file", required_argument, NULL, 'c'},
			{"help", no_argument, NULL, 'h'},
			{NULL, 0, NULL, 0}
	};

	/* Initialize the logging interface. */
	init_logger(LOG_DEBUG, log_options, NULL);

	while (1) {
		opt = getopt_long(argc, argv, short_options, long_options,
				&opt_index);
		if (opt == -1)
			break;

		switch (opt) {
		case 'd':
			create_daemon = 1;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'h':
			usage(name);
			goto done;
		default:
			usage(name);
			result = EXIT_FAILURE;
			goto done;
		}
	}

	/* Daemonize if requested. */
	if (create_daemon) {
		if (start_daemon(name) != 0) {
			result = EXIT_FAILURE;
			goto done;
		}
	}

	/* Do the real work. */
	start_connector(config_file);

done:
	deinit_logger();

	return result;
}
