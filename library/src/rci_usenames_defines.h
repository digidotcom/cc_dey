/*
 * Copyright (c) 2022 Digi International Inc.
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

#ifndef RCI_USENAMES_DEFINES_H
#define RCI_USENAMES_DEFINES_H

#if !(defined RCI_ELEMENTS_NAME_MAX_SIZE)
#define RCI_ELEMENTS_NAME_MAX_SIZE 22
#else
#if RCI_ELEMENTS_NAME_MAX_SIZE < 22
#undef RCI_ELEMENTS_NAME_MAX_SIZE
#define RCI_ELEMENTS_NAME_MAX_SIZE 22
#endif
#endif
#if !(defined RCI_COLLECTIONS_NAME_MAX_SIZE)
#define RCI_COLLECTIONS_NAME_MAX_SIZE 19
#else
#if RCI_COLLECTIONS_NAME_MAX_SIZE < 19
#undef RCI_COLLECTIONS_NAME_MAX_SIZE
#define RCI_COLLECTIONS_NAME_MAX_SIZE 19
#endif
#endif
#if !(defined RCI_VALUES_NAME_MAX_SIZE)
#define RCI_VALUES_NAME_MAX_SIZE 7
#else
#if RCI_VALUES_NAME_MAX_SIZE < 7
#undef RCI_VALUES_NAME_MAX_SIZE
#define RCI_VALUES_NAME_MAX_SIZE 7
#endif
#endif
#endif

