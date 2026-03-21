# ##############################################################################
# apps/netutils/nghttp3/Makefile
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  The ASF licenses this
# file to you under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.
#
# ##############################################################################

include $(APPDIR)/Make.defs

NGHTTP3_UNPACKNAME = nghttp3

CSRCS    = nghttp3/lib/nghttp3_rcbuf.c
CSRCS   += nghttp3/lib/nghttp3_mem.c
CSRCS   += nghttp3/lib/nghttp3_str.c
CSRCS   += nghttp3/lib/nghttp3_conv.c
CSRCS   += nghttp3/lib/nghttp3_buf.c
CSRCS   += nghttp3/lib/nghttp3_ringbuf.c
CSRCS   += nghttp3/lib/nghttp3_pq.c
CSRCS   += nghttp3/lib/nghttp3_map.c
CSRCS   += nghttp3/lib/nghttp3_ksl.c
CSRCS   += nghttp3/lib/nghttp3_qpack.c
CSRCS   += nghttp3/lib/nghttp3_qpack_huffman.c
CSRCS   += nghttp3/lib/nghttp3_qpack_huffman_data.c
CSRCS   += nghttp3/lib/nghttp3_err.c
CSRCS   += nghttp3/lib/nghttp3_debug.c
CSRCS   += nghttp3/lib/nghttp3_conn.c
CSRCS   += nghttp3/lib/nghttp3_stream.c
CSRCS   += nghttp3/lib/nghttp3_frame.c
CSRCS   += nghttp3/lib/nghttp3_tnode.c
CSRCS   += nghttp3/lib/nghttp3_vec.c
CSRCS   += nghttp3/lib/nghttp3_gaptr.c
CSRCS   += nghttp3/lib/nghttp3_idtr.c
CSRCS   += nghttp3/lib/nghttp3_range.c
CSRCS   += nghttp3/lib/nghttp3_http.c
CSRCS   += nghttp3/lib/nghttp3_version.c
CSRCS   += nghttp3/lib/nghttp3_balloc.c
CSRCS   += nghttp3/lib/nghttp3_opl.c
CSRCS   += nghttp3/lib/nghttp3_objalloc.c
CSRCS   += nghttp3/lib/nghttp3_unreachable.c
CSRCS   += nghttp3/lib/nghttp3_settings.c
CSRCS   += nghttp3/lib/nghttp3_callbacks.c
CSRCS   += nghttp3/lib/nghttp3_ratelim.c
CSRCS   += nghttp3/lib/sfparse/sfparse.c

# Compilation flags
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)$(DELIM)netutils$(DELIM)nghttp3

# nghttp3 specific includes
CFLAGS += ${INCDIR_PREFIX}$(NGHTTP3_UNPACKNAME)/lib
CFLAGS += ${INCDIR_PREFIX}$(NGHTTP3_UNPACKNAME)/lib/includes

# TODO : USE config.h
CFLAGS += -DHAVE_ARPA_INET_H -Wno-undef

NGHTTP3_VERSION = $(patsubst "%",%,$(strip $(CONFIG_NGHTTP3_VERSION)))
NGHTTP3_URL ?= "https://github.com/ngtcp2/nghttp3/releases/download"
NGHTTP3_TAR = nghttp3-$(NGHTTP3_VERSION).tar.bz2
NGHTTP3_UNPACKNAME = nghttp3

UNPACK ?= tar -xf

$(NGHTTP3_TAR):
	@echo "Downloading: $(NGHTTP3_URL)/v$(NGHTTP3_VERSION)/$(NGHTTP3_TAR)"
	$(Q) curl -o $(NGHTTP3_TAR) -L $(NGHTTP3_URL)/v$(NGHTTP3_VERSION)/$(NGHTTP3_TAR)

$(NGHTTP3_UNPACKNAME): $(NGHTTP3_TAR)
	@echo "Unpacking: $(NGHTTP3_TAR) -> $(NGHTTP3_UNPACKNAME)"
	$(Q) $(UNPACK) $(NGHTTP3_TAR)
	$(Q) mv nghttp3-$(NGHTTP3_VERSION) $(NGHTTP3_UNPACKNAME)

# Download and unpack tarball if no git repo found
ifeq ($(wildcard $(NGHTTP3_UNPACKNAME)/.git),)
distclean::
	$(call DELDIR, $(NGHTTP3_UNPACKNAME))
	$(call DELFILE, $(NGHTTP3_TAR))

$(NGHTTP3_UNPACKNAME)/lib/includes/nghttp3/nghttp3.h:: $(NGHTTP3_UNPACKNAME)
else
$(NGHTTP3_UNPACKNAME)/lib/includes/nghttp3/nghttp3.h::
endif

context:: $(NGHTTP3_UNPACKNAME)/lib/includes/nghttp3/nghttp3.h

include $(APPDIR)/Application.mk