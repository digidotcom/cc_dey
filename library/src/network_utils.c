/*
 * Copyright (c) 2017-2022 Digi International Inc.
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
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ccimp/ccimp_network.h"
#include "ccimp/dns_helper.h"
#include "cc_logging.h"
#include "file_utils.h"
#include "network_utils.h"
#include "services_util.h"
#include "string_utils.h"

#define cast_for_alignment(cast, ptr)	((cast) ((void *) (ptr)))
#define ARRAY_SIZE(array)				(sizeof array/sizeof array[0])

#define DNS_FILE							"/etc/resolv.conf"
#define DNS_ENTRY							"nameserver"
#define PATH_PROCNET_DEV					"/proc/net/dev"

#define CMD_GET_GATEWAY	"route -n | grep %s | grep 'UG[ \t]' | awk '{print $2}'"
#define CMD_IS_DHCP	"nmcli conn show %s | grep \"ipv[4|6].method\" | grep auto"

static ccapi_bool_t interface_exists(const char *iface_name);
static int get_dns(uint8_t *dnsaddr1, uint8_t *dnsaddr2);
static int get_gateway(const char *iface_name, uint8_t *gateway);
static int get_mac_address(const char *iface_name, uint8_t *mac_address);
static bool is_dhcp(const char *iface_name);
static char *get_iface_name(char *buffer, char *name);
static int fill_stats_fields(char *iface_line, net_stats_t *net_stats);
static int compare_iface(const char *n1, const char *n2);
static int exec_bt_cmd(const char *cmd_fmt, const char *iface_name, const char *info_name, char **resp);
static char *parse_bt_info(const char *line, const char *pattern, int group_idx, const char* info_name);

/*
 * get_main_iface_info() - Retrieve information about the network
 *                         interface used to connect to url.
 *
 * @url:		URL to connect to to determine main network interface.
 * @iface_info:	Struct to fill with the network interface information
 *
 * Return: 0 on success, -1 otherwise.
 */
int get_main_iface_info(const char *url, iface_info_t *iface_info)
{
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;
	int retval = -1;
	struct sockaddr_in sin = {0};
	struct sockaddr_in info = {0};
	in_addr_t ip_addr = {0};
	int sockfd = -1;
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
#if (defined APP_SSL)
	sin.sin_port = htons(CCIMP_SSL_PORT);
#else
	sin.sin_port = htons(CCIMP_TCP_PORT);
#endif

	if(connect(sockfd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0) {
		log_error("%s: connect() failed", __func__);
		goto done;
	}

	if (getsockname(sockfd, (struct sockaddr *) &info, &len) < 0) {
		log_error("%s: getsockname() failed", __func__);
		goto done;
	}

	/* 2 - Determine the interface used to connect */
	if (getifaddrs(&ifaddr) == -1) {
		log_error("%s: getifaddrs() failed", __func__);
		goto done;
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			char buf[32];
			struct sockaddr_in * const sa = cast_for_alignment(struct sockaddr_in *, ifa->ifa_addr);
			char *ipv4_string;

			inet_ntop(ifa->ifa_addr->sa_family, (void *)&(sa->sin_addr), buf, sizeof(buf));
			ipv4_string = inet_ntoa(info.sin_addr);
			if (strcmp(ipv4_string, buf) == 0) {
				/* 3 - Get the interface info */
				if (get_iface_info(ifa->ifa_name, iface_info) == 0)
					retval = 0;
				break;
			}
		}
	}

done:
	freeifaddrs(ifaddr);
	if (sockfd >= 0)
		close(sockfd);

	return retval;
}

/*
 * get_iface_info() - Retrieve information about the given network interface.
 *
 * @name:		Network interface name.
 * @iface_info:	Struct to fill with the network interface information.
 *
 * Return: 0 on success, -1 otherwise.
 */
int get_iface_info(const char *iface_name, iface_info_t *iface_info)
{
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;
	struct sockaddr_in *sin;

	/* Clear all values */
	memset(iface_info, 0, sizeof (iface_info_t));
	/* Check if interface exists */
	if (!interface_exists(iface_name)) {
		log_error("Interface '%s' not found\n", iface_name);
		return -1;
	}
	/* Fill interface name */
	strncpy(iface_info->name, iface_name, IFNAMSIZ - 1);
	/* Fill MAC address */
	get_mac_address(iface_name, iface_info->mac_addr);
	if (getifaddrs(&ifaddr) == -1) {
		log_error("Unable to get network interfaces: %s (%d)", strerror(errno), errno);
		return -1;
	}

	/* Fill IPv4, subnet mask and enabled status */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (strncmp(iface_name, ifa->ifa_name, strlen(iface_name)) != 0
			|| ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			/* Set IPv4 address */
			sin = cast_for_alignment(struct sockaddr_in *, ifa->ifa_addr);
			memcpy(iface_info->ipv4_addr, &(sin->sin_addr), IPV4_GROUPS);
			/* Set subnet mask address */
			sin = cast_for_alignment(struct sockaddr_in *, ifa->ifa_netmask);
			memcpy(iface_info->submask, &(sin->sin_addr), IPV4_GROUPS);
			/* Set enablement status */
			if ((ifa->ifa_flags & IFF_UP) == IFF_UP)
				iface_info->enabled = CCAPI_TRUE;
			else
				iface_info->enabled = CCAPI_FALSE;

			break;
		}
	}
	/* Fill DNS addresses */
	get_dns(iface_info->dnsaddr1, iface_info->dnsaddr2);
	/* Fill gateway address */
	get_gateway(iface_name, iface_info->gateway);
	/* Fill DHCP flag */
	iface_info->dhcp = is_dhcp(iface_name);

	if (ifaddr != NULL)
		freeifaddrs(ifaddr);

	return 0;
}

/**
 * get_net_stats() - Fills the network interface statistics.
 *
 * @net_stats:	Name of the network interface to get its statistics.
 *
 * Return: 0 on success, 1 otherwise.
 */
int get_net_stats(const char *iface_name, net_stats_t *net_stats)
{
	FILE *fd;
	char buffer[512];
	int err;

	fd = fopen(PATH_PROCNET_DEV, "r");
	if (!fd) {
		log_error("Cannot get network statistics for '%s': %s (%d)",
			iface_name, strerror(errno), errno);
		goto error;
	}
	/* Ignore 2 first lines */
	if (fgets(buffer, sizeof(buffer), fd) == NULL) {
		log_error("Cannot get network statistics for '%s'", iface_name);
		goto error;
	}
	if (fgets(buffer, sizeof(buffer), fd) == NULL) {
		log_error("Cannot get network statistics for '%s'", iface_name);
		goto error;
	}

	err = 0;
	while (fgets(buffer, sizeof(buffer), fd)) {
		char *iface_line, name[IFNAMSIZ];

		iface_line = get_iface_name(buffer, name);

		fill_stats_fields(iface_line, net_stats);
		if (!strcmp(iface_name, name))
			goto done;
	}
	if (!ferror(fd))
		goto done;

	log_debug("%s: fgets error", __func__);

error:
	err = 1;
	fill_stats_fields(NULL, net_stats);

done:
	fclose(fd);

	return err;
}

/**
 * get_primary_mac_address() - Get the primary MAC address of the device.
 *
 * This is not guaranteed to be the MAC of the active network interface, and
 * should be only used for device identification purposes, where the same MAC
 * is desired no matter which network interface is active.
 *
 * The interfaces priority order is the following:
 *   - Ethernet (eth0, eth1, ...)
 *   - Wi-Fi (wlan0, wlan1, ...)
 *   - No interface (empty string)
 *   - Other interface (any other string)
 *
 * @mac_addr:	Pointer to store the MAC address.
 *
 * Return: The MAC address of primary interface.
 */
uint8_t *get_primary_mac_address(uint8_t *const mac_addr)
{
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;
	uint8_t *retval = NULL;
	iface_info_t iface = {{0}};

	if (getifaddrs(&ifaddr) == -1) {
		log_error("%s: getifaddrs() failed", __func__);
		goto done;
	}

	/* iterate over all the interfaces and keep the best one */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_PACKET &&
				compare_iface(iface.name, ifa->ifa_name) < 0) {
			if (get_mac_address(ifa->ifa_name, iface.mac_addr) != 0)
				goto done;
			strncpy(iface.name, ifa->ifa_name, IFNAMSIZ - 1);
			log_debug("%s: Found better interface %s - MAC %02x:%02x:%02x:%02x:%02x:%02x",
					__func__, ifa->ifa_name, iface.mac_addr[0],
					iface.mac_addr[1], iface.mac_addr[2],
					iface.mac_addr[3], iface.mac_addr[4],
					iface.mac_addr[5]);
		}
	}

	/* return the best interface found (if any) */
	if (iface.name[0] == '\0') {
		log_error("%s: no valid network interface", __func__);
		retval = NULL;
	} else {
		memcpy(mac_addr, iface.mac_addr, sizeof(iface.mac_addr));
		retval = mac_addr;
	}

done:
	if (ifaddr != NULL)
		freeifaddrs(ifaddr);

	return retval;
}

/*
 * get_bt_info() - Retrieve information about the given Bluetooth interface.
 *
 * @name:		Bluetooth interface name.
 * @bt_info:	Struct to fill with the Bluetooth interface information.
 *
 * Return: 0 on success, 1 otherwise.
 */
int get_bt_info(const char *iface_name, bt_info_t *bt_info)
{
	char **lines = NULL;
	char *resp = NULL, *info=NULL;
	int i = 0, n_lines = 0, ret = 0;

	strncpy(bt_info->name, iface_name, IFNAMSIZ - 1);

	if (exec_bt_cmd("hciconfig %s | sed -ne '2,5p'", iface_name, "info", &resp) != 0) {
		ret = 1;
		goto error;
	}

	info = strtok(resp, "\n");
	do {
		char **tmp = NULL;

		if (info == NULL)
			break;

		tmp = realloc(lines, sizeof(char*) * (n_lines + 1));
		if (tmp == NULL) {
			log_error("Could not get '%s' Bluetooth info: Out of memory", iface_name);
			ret = 1;
			n_lines--;
			goto error;
		}
		lines = tmp;

		lines[n_lines] = strdup(trim(info));
		if (lines[n_lines - 1] == NULL) {
			log_error("Could not get '%s' Bluetooth info: Out of memory", iface_name);
			ret = 1;
			n_lines--;
			goto error;
		}

		n_lines++;
		info = strtok(NULL, "\n");
	} while (info != NULL);

	if (n_lines < 4) {
		log_error("Could not get '%s' Bluetooth info", iface_name);
		ret = 1;
		goto error;
	}

	/* MAC address */
	info = parse_bt_info(lines[i++], "[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}", 0, "MAC");
	if(info == NULL) {
		ret = 1;
		goto error;
	}
	sscanf(info,
		"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:",
		&bt_info->mac_addr[0], &bt_info->mac_addr[1],
		&bt_info->mac_addr[2], &bt_info->mac_addr[3],
		&bt_info->mac_addr[4], &bt_info->mac_addr[5]);
	free(info);

	/* Status */
	info = parse_bt_info(lines[i++], "(UP) .*", 1, "status");
	if(info == NULL) {
		ret = 1;
		goto error;
	}
	if (strcmp(info, "UP") == 0)
		bt_info->enabled = CCAPI_TRUE;
	else
		bt_info->enabled = CCAPI_FALSE;
	free(info);

	/* RX bytes */
	info = parse_bt_info(lines[i++], "RX bytes:([0-9]+)", 1, "RX bytes");
	if(info == NULL) {
		ret = 1;
		goto error;
	}
	bt_info->stats.rx_bytes = strtoull(info, NULL, 10);
	free(info);

	/* TX bytes */
	info = parse_bt_info(lines[i], "TX bytes:([0-9]+)", 1, "TX bytes");
	if(info == NULL) {
		ret = 1;
		goto error;
	}
	bt_info->stats.tx_bytes = strtoull(info, NULL, 10);
	free(info);

	goto done;

error:
	/* Init to default values */
	memset(bt_info->mac_addr, 0, ARRAY_SIZE(bt_info->mac_addr));
	bt_info->enabled = CCAPI_FALSE;
	bt_info->stats.rx_bytes = 0;
	bt_info->stats.tx_bytes = 0;

done:
	for (i = 0; i < n_lines; i++)
		free(lines[i]);

	free(lines);
	free(resp);

	return ret;
}

/**
 * interface_exists() - Check if provided interface exists or not.
 *
 * @iface_name:	Name of the network interface to check
 *
 * Return: CCAPI_TRUE if interface exists, CCAPI_FALSE otherwise.
 */
static ccapi_bool_t interface_exists(const char *iface_name)
{
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;
	ccapi_bool_t exists = CCAPI_FALSE;

	if (iface_name == NULL || strlen(iface_name) == 0)
		goto done;
	if (getifaddrs(&ifaddr) == -1) {
		log_error("%s: getifaddrs() failed", __func__);
		goto done;
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if ((ifa->ifa_addr->sa_family == AF_PACKET || ifa->ifa_addr->sa_family == AF_INET) &&
		     strncmp(iface_name, ifa->ifa_name, strlen(iface_name)) == 0) {
			exists = CCAPI_TRUE;
			break;
		}
	}

done:
	if (ifaddr != NULL)
		freeifaddrs(ifaddr);

	return exists;
}

/**
 * get_mac_address() - Get the MAC address of the given interface.
 *
 * @iface_name: Name of the network interface to retrieve its MAC address
 * @mac_addr:	Pointer to store the MAC address.
 *
 * Return: 0 on success, -1 otherwise.
 */
static int get_mac_address(const char *iface_name, uint8_t *mac_address)
{
	struct ifreq ifr;
	int sock = -1;
	int ret = 0;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		log_error("%s: socket() failed", __func__);
		ret = -1;
		goto done;
	}
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
		log_error("%s: ioctl SIOCGIFFLAGS failed", __func__);
		ret = -1;
		goto done;
	}
	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, MAC_ADDRESS_GROUPS);

done:
	if (sock >= 0)
		close(sock);

	return ret;
}

/**
 * get_dns() - Get the DNS addresses of the given interface.
 *
 * @dnsaddr1: Pointer to store the primary DNS address.
 * @dnsaddr2: Pointer to store the secondary DNS address.
 *
 * Return: 0 on success, -1 otherwise.
 */
static int get_dns(uint8_t *dnsaddr1, uint8_t *dnsaddr2)
{
	char line[255];
	char dns_str[20];
	int i = 0;
	struct in_addr iaddr;
	FILE *fp;

	/* Get the DNS addresses from system */
	if ((fp = fopen(DNS_FILE, "r")) == NULL) {
		printf("%s: fopen error on %s", __func__, DNS_FILE);
		return -1;
	}
	while (fgets(line, sizeof(line) - 1, fp) && i < MAX_DNS_ADDRESSES) {
		if (strncmp(line, DNS_ENTRY, strlen(DNS_ENTRY)) == 0) {
			/* This is a DNS entry */
			if (sscanf(line, "%*s %s", dns_str)) {
				if (inet_aton(dns_str, &iaddr)) {
					if (i == 0)
						memcpy(dnsaddr1, &iaddr, IPV4_GROUPS);
					else
						memcpy(dnsaddr2, &iaddr, IPV4_GROUPS);
					i += 1;
				} else {
					log_error("%s: couldn't convert '%s' into a valid IP\n", __func__, dns_str);
				}
			}
		}
	}
	fclose(fp);

	return 0;
}

/**
 * get_gateway() - Get the gateway address of the given interface.
 *
 * @iface_name:	Name of the network interface to retrieve its gateway address
 * @gateway:	Pointer to store the gateway address.
 *
 * Return: 0 on success, 1 otherwise.
 */
static int get_gateway(const char *iface_name, uint8_t *gateway)
{
	struct in_addr iaddr;
	char *cmd = NULL, *resp = NULL;
	int len, ret = 1;

	len = snprintf(NULL, 0, CMD_GET_GATEWAY, iface_name);
	cmd = calloc(len + 1, sizeof(char));
	if (cmd == NULL) {
		log_error("Error getting '%s' gateway: Out of memory", iface_name);
		goto done;
	}

	sprintf(cmd, CMD_GET_GATEWAY, iface_name);

	if (execute_cmd(cmd, &resp, 2) != 0 || resp == NULL) {
		if (resp != NULL)
			log_error("Error getting '%s' gateway: %s", iface_name, resp);
		else
			log_error("Error getting '%s' gateway", iface_name);
		goto done;
	}

	if (strlen(resp) > 0)
		resp[strlen(resp) - 1] = '\0';  /* Remove the last line feed */

	if (!inet_aton(resp, &iaddr)) {
		log_error("Error getting '%s' gateway: Invalid IP\n", iface_name);
		goto done;
	}

	memcpy(gateway, &iaddr, IPV4_GROUPS);
	ret = 0;

done:
	free(cmd);
	free(resp);

	return ret;
}

/**
 * is_dhcp() - Check if provided interface uses DHCP or not.
 *
 * @iface_name:	Name of the network interface to retrieve its DHCP status
 *
 * Return: true if interface uses DHCP, false otherwise.
 */
static bool is_dhcp(const char *iface_name)
{
	char *cmd = NULL, *resp = NULL;
	int len;
	bool ret = false;

	if (strcmp(iface_name, "lo") == 0)
		return false;

	len = snprintf(NULL, 0, CMD_IS_DHCP, iface_name);
	cmd = calloc(len + 1, sizeof(char));
	if (cmd == NULL) {
		log_error("Error checking '%s' DHCP: Out of memory", iface_name);
		goto done;
	}

	sprintf(cmd, CMD_IS_DHCP, iface_name);

	if (execute_cmd(cmd, &resp, 2) != 0) {
		if (resp != NULL)
			log_error("Error checking '%s' DHCP: %s", iface_name, resp);
		else
			log_error("Error checking '%s' DHCP", iface_name);
		goto done;
	}

	ret = true;

done:
	free(cmd);
	free(resp);

	return ret;
}

/**
 * get_iface_name() - Gets the name of the first network interface in the provided buffer.
 *
 * @name:	Pointer to store the name.
 * @buffer:	Buffer.
 *
 * Return: The found name.
 */
static char *get_iface_name(char *buffer, char *name)
{
	while (isspace(*buffer))
		buffer++;

	while (*buffer) {
		if (isspace(*buffer))
			break;
		if (*buffer == ':') {	/* could be an alias */
			char *dot = buffer, *dotname = name;

			*name++ = *buffer++;
			while (isdigit(*buffer))
				*name++ = *buffer++;
			if (*buffer != ':') {	/* it wasn't, backup */
				buffer = dot;
				name = dotname;
			}
			if (*buffer == '\0')
				return NULL;
			buffer++;
			break;
		}
		*name++ = *buffer++;
	}
	*name++ = '\0';

	return buffer;
}

/**
 * fill_stats_fields() - Fills the statistics with the info in the provided line.
 *
 * @iface_line:	Line with statistics.
 * @net_stats:	Struct to fill its statistics.
 *
 * Return: 0 on success, 1 otherwise.
 */
static int fill_stats_fields(char *iface_line, net_stats_t *net_stats)
{
	if (iface_line) {
		sscanf(iface_line,
			"%llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu %lu",
			&net_stats->rx_bytes,
			&net_stats->rx_packets,
			&net_stats->rx_errors,
			&net_stats->rx_dropped,
			&net_stats->rx_fifo_errors,
			&net_stats->rx_frame_errors,
			&net_stats->rx_compressed,
			&net_stats->rx_multicast,
			&net_stats->tx_bytes,
			&net_stats->tx_packets,
			&net_stats->tx_errors,
			&net_stats->tx_dropped,
			&net_stats->tx_fifo_errors,
			&net_stats->collisions,
			&net_stats->tx_carrier_errors,
			&net_stats->tx_compressed);
		return 0;
	}

	net_stats->rx_bytes = 0;
	net_stats->rx_packets = 0;
	net_stats->rx_errors = 0;
	net_stats->rx_dropped = 0;
	net_stats->rx_fifo_errors = 0;
	net_stats->rx_frame_errors = 0;
	net_stats->rx_compressed = 0;
	net_stats->rx_multicast = 0;
	net_stats->tx_bytes = 0;
	net_stats->tx_packets = 0;
	net_stats->tx_errors = 0;
	net_stats->tx_dropped = 0;
	net_stats->tx_fifo_errors = 0;
	net_stats->collisions = 0;
	net_stats->tx_carrier_errors = 0;
	net_stats->tx_compressed = 0;

	return 1;
}

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

/**
 * exec_bt_cmd() - Execute the provided command and gets the response.
 *
 * @cmd_fmt:		Command format to execute.
 * @iface_name: 	Name of the Bluetooth interface.
 * @info_name: 		Name of the information to get.
 * @resp: 		Buffer for the response.
 *
 * Response may contain an error string or the result of the command. It must
 * be freed.
 *
 * Return: 0 on success, 1 otherwise.
 */
static int exec_bt_cmd(const char *cmd_fmt, const char *iface_name, const char *info_name, char **resp)
{
	char *cmd = NULL;
	int ret = 0;
	size_t len;

	len = snprintf(NULL, 0, cmd_fmt, iface_name);
	cmd = calloc(len + 1, sizeof(char));
	if (cmd == NULL) {
		log_error("Cannot get '%s' Bluetooth information: Out of memory", iface_name);
		return 1;
	}

	sprintf(cmd, cmd_fmt, iface_name);

	if (execute_cmd(cmd, resp, 2) != 0) {
		if (resp != NULL) {
			log_error("Error getting '%s' Bluetooth %s: %s", iface_name, info_name, *resp);
			free(*resp);
			*resp = NULL;
		} else {
			log_error("Error getting '%s' Bluetooth MAC: No %s", iface_name, info_name);
		}
		ret = 1;
	} else if (strlen(*resp) > 0) {
		(*resp)[strlen(*resp) - 1] = '\0';  /* Remove the last line feed */
	}

	free(cmd);

	return ret;
}

/**
 * parse_bt_info() - Parses the given line to get information based on a regex.
 *
 * @line:	The string to look in.
 * @pattern:	Pattern buffer.
 * @grp_idx:	Group where the search information is.
 * @i_name:	Name of the information to parse.
 *
 * Return: The requested information.
 */
static char *parse_bt_info(const char *line, const char *pattern, int grp_idx, const char* i_name)
{
	regex_t regex;
	regmatch_t grp[grp_idx + 1];
	char *result = NULL;
	int status;

	status = regcomp(&regex, pattern, REG_EXTENDED);
	if (status != 0) {
		log_error("Could not get Bluetooth %s: Unable to compile regular expression (%d)", i_name, status);
		goto done;
	}

	if (regexec(&regex, line, (size_t)grp_idx + 1, grp, 0) != 0) {
		log_error("Could not get Bluetooth %s: No matches", i_name);
		goto done;
	}

	if (grp[grp_idx].rm_so == -1) {
		log_error("Could not get Bluetooth %s", i_name);
		goto done;
	}

	result = calloc(grp[grp_idx].rm_eo - grp[grp_idx].rm_so + 1, sizeof(char));
	if (result == NULL) {
		log_error("Could not get Bluetooth %s: Out of memory", i_name);
		goto done;
	}

	strncpy(result, line + grp[grp_idx].rm_so, grp[grp_idx].rm_eo - grp[grp_idx].rm_so);

done: 
	regfree(&regex);

	return result;
}
