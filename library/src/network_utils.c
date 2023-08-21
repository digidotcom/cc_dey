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

#include <arpa/inet.h>
#include <libdigiapix/process.h>
#include <regex.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "ccimp/ccimp_network.h"
#include "ccimp/dns_helper.h"
#include "cc_logging.h"
#include "network_utils.h"

#define ARRAY_SIZE(array)		(sizeof(array)/sizeof(array[0]))

/**
 * compare_iface() - Provide an ordering for network interfaces by their name.
 *
 * @n1:		Name of the first network interface.
 * @n2: 	Name of the second network interface.
 *
 * The interfaces priority order is the following:
 *   - Ethernet (eth0, eth1, ...)
 *   - Wi-Fi (wlan0, wlan1, ...)
 *   - No interface (empty string)
 *   - Other interface (any other string)
 *
 * Return:
 *      >0 when n1 > n2
 *       0 when n1 = n2
 *      <0 when n1 < n2
 */
static int compare_iface(const char *n1, const char *n2)
{
	const char *patterns[] = { "^eth([0-9]{1,3})$", "^wlan([0-9]{1,3})$", "^$"};
	regmatch_t match_group[2];
	regex_t regex;
	size_t i;
	int retvalue = 1;
	char msgbuf[128];

	for (i = 0; i < ARRAY_SIZE(patterns); i++) {
		int error = regcomp(&regex, patterns[i], REG_EXTENDED);
		if (error != 0) {
			regerror(error, &regex, msgbuf, sizeof(msgbuf));
			log_error("compare_iface(): Could not compile regex: %s (%d)", msgbuf, error);
			regfree(&regex);
			goto done;
		}
		if (regexec(&regex, n1, 0, NULL, 0) != REG_NOMATCH &&
			regexec(&regex, n2, 0, NULL, 0) == REG_NOMATCH) {
			/* Only the first matches: n1 > n2 */
			retvalue = 1;
			regfree(&regex);
			break;
		} else if (regexec(&regex, n1, 0, NULL, 0) == REG_NOMATCH &&
				regexec(&regex, n2, 0, NULL, 0) != REG_NOMATCH) {
			/* Only the second matches: n2 > n1 */
			retvalue = -1;
			regfree(&regex);
			break;
		} else if (regexec(&regex, n1, 2, match_group, 0) != REG_NOMATCH &&
				regexec(&regex, n2, 0, NULL, 0) != REG_NOMATCH) {
			/* If both matches, use the number to decide */
			int j1 = atoi(n1 + match_group[1].rm_so);
			int j2 = atoi(n2 + match_group[1].rm_so);
			retvalue = j2 - j1;
			regfree(&regex);
			break;
		} else {
			/* If none matches, try the next pattern */
			regfree(&regex);
		}
	}

done:
	return retvalue;
}

int get_main_iface_info(const char *url, net_state_t *net_state)
{
	int retval = -1, sockfd = -1, i = 0;
	struct sockaddr_in sin = {0}, info = {0};
	in_addr_t ip_addr = {0};
	net_names_list_t list_ifaces;
	socklen_t len = sizeof(struct sockaddr);

	/* 1 - Open a connection to url */
	if (dns_resolve(url, &ip_addr) != 0) {
		log_error("%s: dns_resolve() failed (url: %s)", __func__, url);
		goto done;
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
		log_error("%s: socket() failed", __func__);
		goto done;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip_addr;
#ifdef APP_SSL
	sin.sin_port = htons(CCIMP_SSL_PORT);
#else /* APP_SSL */
	sin.sin_port = htons(CCIMP_TCP_PORT);
#endif /* APP_SSL */

	if(connect(sockfd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0) {
		log_error("%s: connect() failed", __func__);
		goto done;
	}

	if (getsockname(sockfd, (struct sockaddr *) &info, &len) < 0) {
		log_error("%s: getsockname() failed", __func__);
		goto done;
	}

	/* 2 - Determine the interface used to connect */
	if (ldx_net_list_available_ifaces(&list_ifaces) <= 0)
		goto done;

	for (i = 0; i < list_ifaces.n_ifaces; i++) {
		net_state_t iface;
		char iface_ip[32];
		char *sock_ip;

		ldx_net_get_iface_state(list_ifaces.names[i], &iface);

		snprintf(iface_ip, ARRAY_SIZE(iface_ip), "%d.%d.%d.%d",
			iface.ipv4[0], iface.ipv4[1], iface.ipv4[2], iface.ipv4[3]);
		sock_ip = inet_ntoa(info.sin_addr);
		if (strcmp(sock_ip, iface_ip) == 0) {
			/* 3 - Get the interface info */
			*net_state = iface;
			retval = 0;
			break;
		}
	}

done:
	if (sockfd >= 0)
		close(sockfd);

	return retval;
}

uint8_t *get_primary_mac_address(uint8_t *const mac_addr)
{
	uint8_t *retval = NULL;
	net_state_t iface = {{0}};
	net_names_list_t list_ifaces;
	int i;

	if (ldx_net_list_available_ifaces(&list_ifaces) <= 0)
		return NULL;

	for (i = 0; i < list_ifaces.n_ifaces; i++) {
		if (compare_iface(iface.name, list_ifaces.names[i]) < 0) {
			if (ldx_net_get_iface_state(list_ifaces.names[i], &iface) != NET_STATE_ERROR_NONE)
				continue;

			log_debug("%s: Found better interface %s - MAC %02x:%02x:%02x:%02x:%02x:%02x",
					__func__, iface.name, iface.mac[0], iface.mac[1],
					iface.mac[2], iface.mac[3], iface.mac[4], iface.mac[5]);
		}
	}

	/* return the best interface found (if any) */
	if (iface.name[0] == '\0') {
		log_error("%s: no valid network interface", __func__);
		retval = NULL;
	} else {
		memcpy(mac_addr, iface.mac, sizeof(iface.mac));
		retval = mac_addr;
	}

	return retval;
}
