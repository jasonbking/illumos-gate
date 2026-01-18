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

PROG = svc.periodicd
OBJS = \
       periodic.c \
       sched.c

SRCS = $(OBJS:%.o=%.c)

POFILE = $(OBJS:%.o=%.po)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

CPPFLAGS += -I. -I../common
CPPFLAGS += -D_REENTRANT

CFLAGS += $(CCVERBOSE)

%.o:	%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

LDLIBS += \
	  -lcontract \
	  -lnvpair \
	  -lrestart \
	  -lscf \
	  -lsysevent \
	  -lumem \
	  -luutil

FILEMODE = 0555

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(LDFLAGS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTLIBSVCBINPROG)

clean:
	$(RM) $(OBJS)

include $(SRC)/cmd/Makefile.targ
