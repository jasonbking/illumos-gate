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
# Copyright 2026 Jason King
#

PROG =		lldp

include		$(SRC)/cmd/Makefile.cmd
# lldp is only built as a 64-bit executable
include		$(SRC)/cmd/Makefile.cmd.64
include		$(SRC)/cmd/Makefile.ctf

CSTD =		$(CSTD_GNU99)
LDLIBS +=	-ldladm -llldp -lofmt

OBJS =		lldp.o		\
		neighbors.o
SRCS =		$(OBJS:%.o=%.c)

# One message catalog for all of the sources
POFILES =	$(OBJS:%.o=%.po)
POFILE =	$(PROG)_all.po

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

%.o:		%.c
		$(COMPILE.c) $<
		$(POST_PROCESS_O)

install:	all $(ROOTUSRSBINPROG)

$(POFILE):	$(POFILES)
		$(RM) $@
		$(CAT) $(POFILES) > $@

clean:
		$(RM) $(OBJS) $(POFILES)

include		$(SRC)/cmd/Makefile.targ
