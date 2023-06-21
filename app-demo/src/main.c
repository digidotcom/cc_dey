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

#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cc_srv_services.h"
#include "data_points.h"

#define VERSION		"0.1" GIT_REVISION

#define USAGE \
	"ConnectCore Cloud Services demo.\n" \
	"Copyright(c) Digi International Inc.\n" \
	"\n" \
	"Version: %s\n" \
	"\n" \
	"Usage: %s [options]\n\n" \
	"  -h  --help                Print help and exit\n" \
	"\n"

static volatile bool stop_requested = false;

/**
 * usage() - Print usage information
 *
 * @name:	Name of the daemon.
 */
static void usage(char const *const name)
{
	printf(USAGE, VERSION, name);
}

/**
 * signal_handler() - Manage signal received.
 *
 * @sig_num: Received signal.
 */
static void signal_handler(int sig_num)
{
	log_debug("Signal %d to stop ConnectCore Cloud Services demo", sig_num);
	stop_requested = true;
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

int main(int argc, char *argv[])
{
	int result = EXIT_SUCCESS;
	char *name = basename(argv[0]);
	static int opt, opt_index;
	int log_options = LOG_CONS | LOG_NDELAY | LOG_PID | LOG_PERROR;
	static const char *short_options = "h";
	static const struct option long_options[] = {
			{"help", no_argument, NULL, 'h'},
			{NULL, 0, NULL, 0}
	};

	/* Initialize the logging interface. */
	init_logger(LOG_DEBUG, log_options, name);

	while (1) {
		opt = getopt_long(argc, argv, short_options, long_options,
				&opt_index);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			usage(name);
			goto done;
		default:
			usage(name);
			result = EXIT_FAILURE;
			goto done;
		}
	}

	if (setup_signal_handler()) {
		result = EXIT_FAILURE;
		goto done;
	}

	/* Do the real work. */
	if (start_monitoring() != 0) {
		log_error("%s", "Cannot start monitoring");
		goto done;
	}

	do {
		sleep(2);
	} while (!stop_requested);

	stop_monitoring();

done:
	deinit_logger();

	return result;
}
