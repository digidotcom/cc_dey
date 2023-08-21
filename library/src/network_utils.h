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

#ifndef network_utils_h
#define network_utils_h

#include <libdigiapix/network.h>
#include <stdint.h>

/*
 * get_main_iface_info() - Retrieve information about the network
 *                         interface used to connect to url.
 *
 * @url:	URL to connect to to determine main network interface.
 * @net_state:	Struct to fill with the network interface information.
 *
 * Return: 0 on success, -1 otherwise.
 */
int get_main_iface_info(const char *url, net_state_t *net_state);

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
uint8_t *get_primary_mac_address(uint8_t * const mac_addr);

#endif
