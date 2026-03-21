############################################################################
# apps/system/libuv/Makefile
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#
############################################################################
include $(APPDIR)/Make.defs

LIBEV_PATH    = $(APPDIR)/system/libev
LIBEV_URL     = https://github.com/enki/libev
LIBEV_VERSION = 93823e6ca699df195a6c7b8bfa6006ec40ee0003
LIBEV_GIT     = libev

CSRCS  = ${LIBEV_PATH}/${LIBEV_GIT}/ev.c
CSRCS += ${LIBEV_PATH}/${LIBEV_GIT}/event.c

CFLAGS += ${INCDIR_PREFIX}${LIBEV_PATH}
CFLAGS += -Wno-undef -Wno-unused-value -Wno-shadow

ifeq ($(wildcard libev/.git),)
libev:
	@echo "Git Cloning: $(LIBEV_URL)"
	$(Q) git clone $(LIBEV_URL) ${LIBEV_GIT}
	@echo "Checkout commit: $(LIBEV_VERSION)"
	$(Q) cd $(LIBEV_GIT) && \
	git checkout -q $(LIBEV_VERSION)

context:: libev
endif

distclean::
	$(call DELDIR, $(LIBEV_GIT))

include $(APPDIR)/Application.mk