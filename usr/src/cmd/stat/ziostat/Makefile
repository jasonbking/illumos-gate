#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright (c) 2019, Joyent, Inc.
#

PROG=	ziostat
OBJS=	ziostat.o
SRCS =$(OBJS:%.o=%.c) $(COMMON_SRCS)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/stat/Makefile.stat

COMMON_OBJS= common.o
COMMON_SRCS= $(COMMON_OBJS:%.o=$(STATCOMMONDIR)/%.c)

CSTD		= $(CSTD_GNU99)
CPPFLAGS	+= -I$(STATCOMMONDIR)
LDFLAGS		+= -lkstat -lm -lzonecfg

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
	-rm -f $(OBJS) $(COMMON_OBJS) $(PROG)

$(ROOTBINPROG): $(PROG)
	$(INS.file)

lint:

include $(SRC)/cmd/Makefile.targ
