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
       exec.o \
       periodic.o \
       sched.o \
       smf.o

ALLOBJS = $(OBJS) definit.o

SRCS = $(OBJS:%.o=%.c) \
	$(SRC)/common/definit/definit.c

POFILES = $(OBJS:%.o=%.po)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

CSTD =	$(CSTD_GNU99)

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

CPPFLAGS += -I. -I../common -I$(SRC)/common/definit
CPPFLAGS += -D_REENTRANT

CFLAGS += $(CCVERBOSE)

%.o:	%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

%.o:	$(SRC)/common/definit/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

LDLIBS += \
	  -lcontract \
	  -lkstat \
	  -lrestart \
	  -lscf \
	  -lumem \
	  -luutil

FILEMODE = 0555

.KEEP_STATE:

.PARALLEL: $(ALLOBJS)

all: $(PROG)

$(PROG): $(ALLOBJS)
	$(LINK.c) -o $@ $(ALLOBJS) $(LDLIBS) $(LDFLAGS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTLIBSVCBINPROG)

clean:
	$(RM) $(ALLOBJS)

include $(SRC)/cmd/Makefile.targ
