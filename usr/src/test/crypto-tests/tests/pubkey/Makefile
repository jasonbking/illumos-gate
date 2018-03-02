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
PROGS =		$(PROGS_pkcs) $(PROGS_kcf)

ROOTOPTPKG =	$(ROOT)/opt/crypto-tests
TESTROOT =	$(ROOTOPTPKG)/tests/pubkey
TESTDIR_pkcs =	$(TESTROOT)/pkcs
TESTDIR_kcf =	$(TESTROOT)/kcf

CMDS_pkcs =	$(ALGS:%=$(TESTDIR_pkcs)/%)
CMDS_kcf =	$(ALGS:%=$(TESTDIR_kcf)/%)
CMDS =		$(CMDS_pkcs) $(CMDS_kcf)

$(CMDS) := FILEMODE = 0555

CSTD =		$(CSTD_GNU99)
CPPFLAGS +=	-I$(SRC)/common/crypto
LDLIBS +=	-lcryptoutil

LINTFLAGS += -xerroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2

OBJS_dh =	common.o dh.o
OBJS_ecc =	common.o ecc.o

dh_pkcs lint_dh_pkcs :=		OBJS = dh_pkcs.o $(OBJS_dh)
dh_kcf lint_dh_kfc :=		OBJS = dh_kcf.o $(OBJS_dh)
ecc_pkcs lint_ecc_pkcs :=	OBJS = ecc_pkcs.o $(OBJS_ecc)
ecc_kcf	lint_ecc_kcf :=		OBJS = ecc_kcf.o $(OBJS_ecc)

$(PROGS_pkcs) $(PROGS_pkcs:%=lint_%) := LDLIBS += -lpkcs11

all: $(PROGS)

dh_pkcs: dh_pkcs.o $(OBJS_dh)
dh_kcf:	dh_kcf.o $(OBJS_dh)
ecc_pkcs: ecc_pkcs.o $(OBJS_ecc)
ecc_kcf: ecc_kcf.o $(OBJS_ecc)

%: %.o
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(CMDS)

lint: $(CRYPTO:%=lint_%)
lint_pkcs: $(ALGS:%=lint_%_pkcs)
lint_kcf: $(ALGS:%=lint_%_kcf)

lint_%_pkcs:
	$(LINT.c) $(OBJS:%.o=%.c) $(LDLIBS)

lint_%_kcf:
	$(LINT.c) $(OBJS:%.o=%.c) $(LDLIBS)

clobber: clean
	-$(RM) $(PROGS)

clean:
	-$(RM) *.o

$(TESTDIR_pkcs):
	$(INS.dir)

$(TESTDIR_kcf):
	$(INS.dir)

$(CMDS_pkcs):	$(TESTDIR_pkcs)
$(CMDS_kcf):	$(TESTDIR_kcf)

$(TESTROOT)/pkcs/%: %_pkcs
	$(INS.rename)

$(TESTROOT)/kcf/%: %_kcf
	$(INS.rename)
