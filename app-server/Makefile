# ***************************************************************************
# Copyright (c) 2017-2023 Digi International Inc.
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

# Location of CC API dir.
CCAPI_DIR = $(CC_LIB_SRC)/cc_api

# Location of Connector dir.
CCFSM_DIR = $(CCAPI_DIR)/source/cc_ansic

# Location of Private Connector Source Code.
CCAPI_PRIVATE_DIR = $(CCAPI_DIR)/source
CCFSM_PRIVATE_DIR = $(CCFSM_DIR)/private

# Location of Public Include Header Files.
CCFSM_PUBLIC_HEADER_DIR = $(CCFSM_DIR)/public/include
CCAPI_PUBLIC_HEADER_DIR = $(CCAPI_DIR)/include
CUSTOM_PUBLIC_HEADER_DIR = $(CC_LIB_SRC)/custom
CUSTOM_CCFSM_PUBLIC_HEADER_DIR = $(CCAPI_DIR)/source/cc_ansic_custom_include

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
CFLAGS += -I $(SRC) -I $(CC_LIB_SRC) -I $(CUSTOM_CCFSM_PUBLIC_HEADER_DIR)
CFLAGS += -I $(CCFSM_PUBLIC_HEADER_DIR) -I $(CCAPI_PUBLIC_HEADER_DIR) -I $(CUSTOM_PUBLIC_HEADER_DIR)
CFLAGS += -DGIT_REVISION=\"$(if $(GIT_REVISION),-g$(GIT_REVISION))\"

CFLAGS += -g -O -DDEBUG

CFLAGS += $(shell PKG_CONFIG_PATH=../library:$${PKG_CONFIG_PATH} pkg-config --cflags cloudconnector)
CFLAGS += $(shell pkg-config --cflags libdigiapix)
CFLAGS += $(shell pkg-config --cflags json-c)

# Target output to generate.
APP_SRCS = $(wildcard $(SRC)/*.c)

SRCS = $(APP_SRCS)

# Libraries to Link
LIBS += $(shell PKG_CONFIG_PATH=../library:$${PKG_CONFIG_PATH} pkg-config --libs --static cloudconnector)
LIBS += $(shell pkg-config --libs --static libdigiapix)
LIBS += $(shell pkg-config --libs json-c)

# Generated Executable Name.
EXECUTABLE = cloudconnector-srv

.PHONY: all
all:  $(EXECUTABLE)

# Linking Flags.
LDFLAGS += -L$(CC_LIB_SRC)/.. $(DFLAGS) -Wl,-Map,$(EXECUTABLE).map,--sort-common

OBJS = $(SRCS:.c=.o)

$(EXECUTABLE): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $(EXECUTABLE)

.PHONY: install
install: $(EXECUTABLE)
	install -d $(DESTDIR)/usr/bin $(DESTDIR)/etc
	install -m 0755 $< $(DESTDIR)/usr/bin/
	install -m 0644 cfg_files/*.conf $(DESTDIR)/etc/

.PHONY: clean
clean:
	-rm -f $(EXECUTABLE) $(OBJS) $(EXECUTABLE).map
