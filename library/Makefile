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

# Generated Library name.
NAME := cccs
NAME_LEGACY := cloudconnector
MAJOR := 1
MINOR := 0
REVISION := 0
VERSION := $(MAJOR).$(MINOR).$(REVISION)

# Location of Source Code.
SRC = src

# Location of CC API dir.
CCAPI_DIR = $(SRC)/cc_api

# Location of Connector dir.
CCFSM_DIR = $(CCAPI_DIR)/source/cc_ansic

# Location of Private Connector Source Code.
CCAPI_PRIVATE_DIR = $(CCAPI_DIR)/source
CCFSM_PRIVATE_DIR = $(CCFSM_DIR)/private

# Location of Public Include Header Files.
CCFSM_PUBLIC_HEADER_DIR = $(CCFSM_DIR)/public/include
CCAPI_PUBLIC_HEADER_DIR = $(CCAPI_DIR)/include
CUSTOM_PUBLIC_HEADER_DIR = $(SRC)/custom
CUSTOM_CCFSM_PUBLIC_HEADER_DIR = $(CCAPI_DIR)/source/cc_ansic_custom_include
INSTALL_HEADERS_DIR = /usr/include/$(NAME_LEGACY)
INSTALL_HEADERS_DIR_SRV = /usr/include/$(NAME)

# Location of Platform Source Code.
PLATFORM_DIR = $(SRC)/ccimp
MINIUNZ_DIR = $(SRC)/miniunz
SERVICES_DIR = $(SRC)/services
SERVICES_CLIENT_DIR = $(SRC)/services-client

# Resolves where to find Source files.
vpath $(CCFSM_PRIVATE_DIR)/%.c
vpath $(PLATFORM_DIR)/%.c

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
CFLAGS += -g -O

# Target output to generate.
CC_PRIVATE_SRCS := $(CCFSM_PRIVATE_DIR)/connector_api.c
CCAPI_PRIVATE_SRCS := $(wildcard $(CCAPI_PRIVATE_DIR)/*.c)
PLATFORM_SRCS := $(wildcard $(PLATFORM_DIR)/*.c)
CC_DEY_SRCS := $(wildcard $(SRC)/*.c)
CC_MINIUNZ_SRCS := $(wildcard $(MINIUNZ_DIR)/*.c)
CC_SERVICES_SRCS := $(wildcard $(SERVICES_DIR)/*.c)
CC_SERVICES_CLIENT_SRCS := $(wildcard $(SERVICES_CLIENT_DIR)/*.c)

ifeq ($(CONFIG_DISABLE_RECOVERY_UPDATE),)
CFLAGS += -DENABLE_RECOVERY_UPDATE $(shell pkg-config --cflags recovery)
PC_REQUIRES_PRIVATE += recovery
endif
ifeq ($(CONFIG_DISABLE_ONTHEFLY_UPDATE),)
CFLAGS += -DENABLE_ONTHEFLY_UPDATE
PC_LIBS_PRIVATE += -lswupdate
endif

ifeq ($(CONFIG_DISABLE_BT),)
CFLAGS += -DENABLE_BT
endif

ifneq ($(CONFIG_ENABLE_RCI),)
CFLAGS += -DENABLE_RCI
CC_DEY_RCI_SRCS := $(wildcard $(SRC)/rci/*.c)
RCI_HEADERS = -I $(SRC)/rci
endif

CFLAGS += $(shell pkg-config --cflags libdigiapix)

# Include Public Header Files.
CFLAGS += -I $(SRC) $(RCI_HEADERS) -I $(CUSTOM_CCFSM_PUBLIC_HEADER_DIR) -I $(CCFSM_PUBLIC_HEADER_DIR)
CFLAGS += -I $(CCAPI_PUBLIC_HEADER_DIR) -I $(CUSTOM_PUBLIC_HEADER_DIR)
# Include Platform Header Files.
CFLAGS += -I $(MINIUNZ_DIR) -I $(SERVICES_DIR) -I $(PLATFORM_DIR)

SRCS = $(CC_DEY_SRCS) $(CC_SERVICES_SRCS) $(CC_SERVICES_CLIENT_SRCS) $(CC_DEY_RCI_SRCS) $(CC_MINIUNZ_SRCS) $(PLATFORM_SRCS) $(CC_PRIVATE_SRCS) $(CCAPI_PRIVATE_SRCS)

OBJS = $(SRCS:.c=.o)

LDFLAGS += -shared -Wl,-soname,lib$(NAME).so.$(MAJOR),--sort-common


.PHONY: all dynamic legacy-static
all: dynamic legacy-static

define PC_CONTENTS
prefix=/usr
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: $(NAME)
Description: ConnectCore Cloud Services library
Version: $(MAJOR).$(MINOR)

Requires.private: libconfuse openssl zlib libdigiapix $(PC_REQUIRES_PRIVATE)
Libs: -L$${libdir} -l$(NAME)
Libs.private: -lpthread -lutil $(PC_LIBS_PRIVATE)
Cflags: -I$${includedir}/$(NAME) -I$${includedir}
endef

export PC_CONTENTS

define PC_CONTENTS_DAEMON
prefix=/usr
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: $(NAME_LEGACY)
Description: Cloud Connector library
Version: $(MAJOR).$(MINOR)

Requires.private: libconfuse openssl zlib libdigiapix $(PC_REQUIRES_PRIVATE)
Libs: -L$${libdir} -l$(NAME_LEGACY)
Libs.private: -lpthread -lutil $(PC_LIBS_PRIVATE)
Cflags: -I$${includedir}/$(NAME_LEGACY) -I$${includedir}
endef

export PC_CONTENTS_DAEMON

$(NAME).pc:
	echo "$$PC_CONTENTS" >$(NAME).pc

lib$(NAME).so: lib$(NAME).so.$(VERSION)
	ln -sf lib$(NAME).so.$(VERSION) lib$(NAME).so.$(MAJOR)
	ln -sf lib$(NAME).so.$(VERSION) lib$(NAME).so

lib$(NAME).so.$(VERSION): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

$(NAME_LEGACY).pc:
	echo "$$PC_CONTENTS_DAEMON" >$(NAME_LEGACY).pc

lib$(NAME_LEGACY).a: $(OBJS)
	$(AR) -rcs $@ $(OBJS)

dynamic: $(NAME).pc $(NAME_LEGACY).pc lib$(NAME).so

legacy-static: $(NAME_LEGACY).pc lib$(NAME_LEGACY).a


.PHONY: install install-cccs install-legacy
install: install-cccs install-legacy

install-cccs-pkgconfig:
	install -d $(DESTDIR)/usr/lib/pkgconfig
	install -m 0644 $(NAME).pc $(DESTDIR)/usr/lib/pkgconfig/

install-cccs-headers:
	install -d $(DESTDIR)/$(INSTALL_HEADERS_DIR_SRV)
	install -m 0644 src/cc_logging.h $(DESTDIR)/$(INSTALL_HEADERS_DIR_SRV)/
	install -m 0644 src/services-client/cccs_services.h $(DESTDIR)/$(INSTALL_HEADERS_DIR_SRV)/
	install -m 0644 src/services-client/cccs_datapoints.h $(DESTDIR)/$(INSTALL_HEADERS_DIR_SRV)/
	install -m 0644 src/services-client/cccs_receive.h $(DESTDIR)/$(INSTALL_HEADERS_DIR_SRV)/
	install -m 0644 src/cc_utils.h $(DESTDIR)/$(INSTALL_HEADERS_DIR_SRV)/

install-daemon-pkgconfig:
	install -d $(DESTDIR)/usr/lib/pkgconfig
	install -m 0644 $(NAME_LEGACY).pc $(DESTDIR)/usr/lib/pkgconfig/

install-daemon-headers:
	install -d $(DESTDIR)/$(INSTALL_HEADERS_DIR)/ccapi/ \
		  $(DESTDIR)/$(INSTALL_HEADERS_DIR)/custom/ \
		  $(DESTDIR)/$(INSTALL_HEADERS_DIR)/ccimp/
	install -m 0644 src/cc_api/include/ccapi/*.h $(DESTDIR)/$(INSTALL_HEADERS_DIR)/ccapi/
	install -m 0644 src/cc_api/include/custom/*.h $(DESTDIR)/$(INSTALL_HEADERS_DIR)/custom/
	install -m 0644 src/cc_api/include/ccimp/ccimp_types.h $(DESTDIR)/$(INSTALL_HEADERS_DIR)/ccimp/
	install -m 0644 src/custom/custom_connector_config.h $(DESTDIR)/$(INSTALL_HEADERS_DIR)/custom/
	install -m 0644 src/cloudconnector.h src/cc_config.h src/cc_init.h src/cc_logging.h src/cc_system_monitor.h src/utils.h $(DESTDIR)/$(INSTALL_HEADERS_DIR)/

install-certs:
	install -d $(DESTDIR)/etc/ssl/certs
	install -m 0644 src/cc_api/source/cc_ansic/public/certificates/*.crt $(DESTDIR)/etc/ssl/certs/

install-dynamic-lib:
	install -d $(DESTDIR)/usr/lib
	install -m 0644 lib$(NAME).so.$(VERSION) $(DESTDIR)/usr/lib/
	ln -sf lib$(NAME).so.$(VERSION) $(DESTDIR)/usr/lib/lib$(NAME).so.$(MAJOR)
	ln -sf lib$(NAME).so.$(VERSION) $(DESTDIR)/usr/lib/lib$(NAME).so

install-legacy-static-lib:
	install -d $(DESTDIR)/usr/lib
	install -m 0644 lib$(NAME_LEGACY).a $(DESTDIR)/usr/lib/

install-daemon-resources: install-daemon-pkgconfig install-daemon-headers

install-dynamic: install-dynamic-lib install-daemon-resources install-certs

install-legacy-static: install-legacy-static-lib install-certs

install-cccs: install-dynamic install-cccs-pkgconfig install-cccs-headers

install-legacy: install-legacy-static install-daemon-resources


.PHONY: clean
clean:
	-rm -f *.so* lib$(NAME_LEGACY).a $(NAME_LEGACY).pc $(NAME).pc $(OBJS)
