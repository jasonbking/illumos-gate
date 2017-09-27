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
# Copyright 2014 Adam Stevko.  All rights reserved.
# Copyright (c) 2019, Joyent, Inc. All rights reserved.
#

PROG=	arcstat
OBJS=	arcstat.o
SRCS=	$(OBJS:%.o=%.c) $(COMMON_SRCS)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/stat/Makefile.stat

COMMON_OBJS=	common.o
COMMON_SRCS=	$(COMMON_OBJS:%.o=$(STATCOMMONDIR)/%.c)

CSTD=		$(CSTD_GNU99)
CPPFLAGS +=	-I$(STATCOMMONDIR)
LDFLAGS +=	-lkstat -lcmdutils

.KEEP_STATE:

all: $(PROG)

install: all .WAIT $(ROOTPROG)

$(PROG): $(OBJS) $(COMMON_OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: $(STATCOMMONDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

clean:
	-rm -f $(OBJS) $(COMMON_OBJBS) $(PROG)

$(ROOTBINPROG): $(PROG)
	$(INS.file)

lint:

include $(SRC)/cmd/Makefile.targ
