# ***************************************************************************
# Copyright (c) 2023 Digi International Inc.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Digi International Inc., 9350 Excelsior Blvd., Suite 700, Hopkins, MN 55343
#
# ***************************************************************************
# Use GNU C Compiler
CC ?= gcc

# Location of Source Code.
SRC = src

# Location of library.
CC_LIB_SRC = ../library/src

# Get commit sha1 for the version
GIT_REVISION := $(shell git rev-parse --verify --short=7 HEAD 2>/dev/null)

# CFLAG Definition
CFLAGS += $(DFLAGS)
# Enable Compiler Warnings
CFLAGS += -Winit-self -Wbad-function-cast -Wpointer-arith
CFLAGS += -Wmissing-parameter-type -Wstrict-prototypes -Wformat-security
CFLAGS += -Wformat-y2k -Wold-style-definition -Wcast-align -Wformat-nonliteral
CFLAGS += -Wredundant-decls -Wvariadic-macros
CFLAGS += -Wall -Werror -Wextra -pedantic
CFLAGS += -Wno-error=padded -Wno-error=format-nonliteral -Wno-unused-function -Wno-missing-field-initializers
# Use ANSIC 99
CFLAGS +=-std=c99
# Include POSIX and GNU features.
CFLAGS += -D_POSIX_C_SOURCE=200112L -D_GNU_SOURCE
# Include Public Header Files.
CFLAGS += -DGIT_REVISION=\"$(if $(GIT_REVISION),-g$(GIT_REVISION))\"

CFLAGS += -g -O -DDEBUG

CFLAGS += -I $(SRC)
CFLAGS += -I$(CC_LIB_SRC)/services-client -I$(CC_LIB_SRC)
CFLAGS += $(shell PKG_CONFIG_PATH=../library:$${PKG_CONFIG_PATH} pkg-config --cflags cloudconnector-srv)
CFLAGS += $(shell pkg-config --cflags libdigiapix)
CFLAGS += $(shell pkg-config --cflags json-c)

# Target output to generate.
SRCS = $(wildcard $(SRC)/*.c)

# Libraries to Link
LIBS += $(shell PKG_CONFIG_PATH=../library:$${PKG_CONFIG_PATH} pkg-config --libs --static cloudconnector-srv)
LIBS += $(shell pkg-config --libs --static libdigiapix)
LIBS += $(shell pkg-config --libs json-c)

# Generated Executable Name.
EXECUTABLE = cloudconnector-demo

.PHONY: all
all:  $(EXECUTABLE)

LDFLAGS += -L$(CC_LIB_SRC)/.. $(DFLAGS) -Wl,-Map,$(EXECUTABLE).map,--sort-common

OBJS = $(SRCS:.c=.o)

$(EXECUTABLE): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $(EXECUTABLE)

.PHONY: install
install: $(EXECUTABLE)
	install -d $(DESTDIR)/usr/bin
	install -m 0755 $< $(DESTDIR)/usr/bin/

.PHONY: clean
clean:
	-rm -f $(EXECUTABLE) $(OBJS) $(EXECUTABLE).map
