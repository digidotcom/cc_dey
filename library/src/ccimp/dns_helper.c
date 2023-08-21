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
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ccimp/ccimp_network.h"
#include "ccimp/ccimp_os.h"
#include "cc_logging.h"
#include "dns_helper.h"

#define APP_DNS_CACHE_TIMEOUT		(24 * 3600)
#define APP_MAX_HOST_NAME		64

#define cast_for_alignment(cast, ptr)	((cast) ((void *) (ptr)))

typedef struct
{
	char name[APP_MAX_HOST_NAME];
	in_addr_t ip_addr;
	unsigned long sys_time;
	int is_redirected;
} dns_cache_t;

static dns_cache_t dns_cache = {"", INADDR_NONE, 0, 0};

void dns_set_redirected(int const state)
{
	dns_cache.is_redirected = state;
}

void dns_cache_invalidate(void)
{
	dns_cache.ip_addr = INADDR_NONE;
}

static int dns_cache_is_valid(char const *const device_cloud_url, in_addr_t *const ip_addr)
{
	int valid = 0;

	if (dns_cache.is_redirected)
		return 0;

	if ((dns_cache.ip_addr != INADDR_NONE)
			&& (strncmp(dns_cache.name, device_cloud_url, APP_MAX_HOST_NAME) == 0)) {
		ccimp_os_system_up_time_t elapsed_time;

		ccimp_os_get_system_time(&elapsed_time);
		if ((elapsed_time.sys_uptime - dns_cache.sys_time) < APP_DNS_CACHE_TIMEOUT) {
			*ip_addr = dns_cache.ip_addr;
			valid = 1;
		}
	}

	return valid;
}

static int dns_resolve_name(char const *const domain_name, in_addr_t *const ip_addr)
{
	int ret = -1;
	struct addrinfo *res_list;
	struct addrinfo *res;

	{
		struct addrinfo hint = { 0 };
		int error;

		hint.ai_socktype = SOCK_STREAM;
		hint.ai_family = AF_INET;
		error = getaddrinfo(domain_name, NULL, &hint, &res_list);
		if (error != 0) {
			log_error("%s: DNS resolution failed for [%s]", __func__, domain_name);
			goto done;
		}
	}

	/* loop over all returned results and look for a IPv4 address */
	for (res = res_list; res; res = res->ai_next) {
		if (res->ai_family == PF_INET) {
			struct sockaddr_in * const sa = cast_for_alignment(struct sockaddr_in *, res->ai_addr);
			struct in_addr const ipv4_addr = sa->sin_addr;

			*ip_addr = ipv4_addr.s_addr;
			log_debug("%s: ip address = [%s]", __func__, inet_ntoa(ipv4_addr));
			ret = 0;
			break;
		}
	}
	freeaddrinfo(res_list);

done:
	return ret;
}

static void dns_cache_update(char const *const device_cloud_url, in_addr_t const ip_addr)
{
	if (dns_cache.is_redirected)
		return;

	strncpy(dns_cache.name, device_cloud_url, APP_MAX_HOST_NAME - 1);
	dns_cache.name[APP_MAX_HOST_NAME - 1] = '\0';
	dns_cache.ip_addr = ip_addr;
	{
		ccimp_os_system_up_time_t system_up_time;

		ccimp_os_get_system_time(&system_up_time);
		dns_cache.sys_time = system_up_time.sys_uptime;
	}
}

int dns_resolve(char const *const device_cloud_url, in_addr_t *const ip_addr)
{
	int status = -1;

	if (device_cloud_url == NULL || ip_addr == NULL)
		goto done;

	*ip_addr = inet_addr(device_cloud_url);

	if (*ip_addr == INADDR_NONE) {
		if (!dns_cache_is_valid(device_cloud_url, ip_addr)) {
			if (dns_resolve_name(device_cloud_url, ip_addr) == 0) {
				dns_cache_update(device_cloud_url, *ip_addr);
			} else {
				log_error("%s: Can't resolve DNS for %s", __func__, device_cloud_url);
				goto done;
			}
		}
	}
	status = 0;

done:
	return status;
}
