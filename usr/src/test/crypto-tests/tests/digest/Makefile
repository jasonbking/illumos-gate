#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2018, Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com
include $(SRC)/cmd/Makefile.ctf

ALGS = sha1 sha256 sha384
CRYPTO = pkcs kcf

$(CRYPTO:%=sha1_%)	:= OBJS = sha1.o
$(CRYPTO:%=sha256_%)	:= OBJS = sha256.o
$(CRYPTO:%=sha384_%)	:= OBJS = sha384.o

PROGS_pkcs = $(ALGS:%=%_pkcs)
PROGS_kcf = $(ALGS:%=%_kcf)
PROGS = $(PROGS_pkcs) $(PROGS_kcf)

ROOTOPTPKG = $(ROOT)/opt/crypto-tests
TESTROOT = $(ROOTOPTPKG)/tests/digest
TESTDIR_pkcs = $(ROOTOPTPKG)/pkcs
TESTDIR_kcf = $(ROOTOPTPKG)/kcf

COMMONDIR = ../common

OBJS_COMMON	= $(COMMONDIR)/testfuncs.o
$(PROGS_pkcs)	:= OBJS_COMMON += $(COMMONDIR)/cryptotest_pkcs.o
$(PROGS_kcf)	:= OBJS_COMMON += $(COMMONDIR)/cryptotest_kcf.o
$(PROGS)	:= OBJS += main.o

CSTD = $(CSTD_GNU99)

CPPFLAGS += -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CPPFLAGS += -I$(COMMONDIR) -I$(SRC)/common/crypto

$(PROGS_pkcs) := LDLIBS += -lpkcs11 -lcryptoutil

all: $(PROGS)

$(COMMONDIR)/%.o:
$(PROGS): main.o

%_pkcs: %.o
	$(LINK.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%_kcf: %.o
	$(LINK.c) -o $@ $(OBJS) $(OBJS_COMMON) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) $(ALGS:%=%.o) main.o
