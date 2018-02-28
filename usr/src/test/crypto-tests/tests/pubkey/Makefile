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

ALGS = dh ecc
CRYPTO = pkcs kcf

PROGS_pkcs =	$(ALGS:%=%_pkcs)
PROGS_kcf =	$(ALGS:%=%_kcf)

dh_pkcs :=	OBJS = dh_pkcs.o common.o dh.o
ecc_pkcs :=	OBJS = ecc_pkcs.o common.o ecc.o

PROGS = $(PROGS_pkcs) $(PROGS_kcf)

ROOTOPTPKG =	$(ROOT)/opt/crypto-tests
TESTROOT =	$(ROOTOPTPKG)/tests/pubkey
TESTDIR_pkcs =	$(ROOTOPTPKG)/pkcs
TESTDIR_kcf =	$(ROOTOPTPKG)/kcf

CSTD = $(CSTD_GNU99)

CPPFLAGS +=	-I$(SRC)/common/crypto

LDLIBS += -lcryptoutil

$(PROGS_pkcs) := LDLIBS += -lpkcs11

all: $(PROGS)

dh_pkcs: dh_pkcs.o common.o dh.o
ecc_pkcs: ecc_pkcs.o common.o ecc.o

%: %.o
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) *.o
