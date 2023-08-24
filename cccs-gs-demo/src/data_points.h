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

#ifndef DATA_POINTS_H_
#define DATA_POINTS_H_

#include <stdbool.h>

/*
 * start_monitoring() - Start monitoring
 *
 * The variables being monitored are: USER_BUTTON.
 *
 * Return: 0 on success, 1 otherwise.
 */
int start_monitoring(void);

/*
 * is_monitoring() - Check monitor status
 *
 * Return: True if demo monitor is running, false otherwise.
 */
bool is_monitoring(void);

/*
 * stop_monitoring() - Stop monitoring
 */
void stop_monitoring(void);

#endif /* DATA_POINTS_H_ */
