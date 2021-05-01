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
# Copyright 2023 Jason King
#

PROG = srcpath
MAN1ONBLDFILES = srcpath.1onbld

OBJS = srcpath.o

include $(SRC)/tools/Makefile.tools
include $(SRC)/cmd/Makefile.ctf

$(ROOTONBLDMAN1ONBLDFILES) := FILEMODE=	644

NATIVE_LIBS += libc.so

LDFLAGS = \
	-L$(ROOTONBLDLIBMACH) \
	'-R$$ORIGIN/../../lib/$(MACH)' \
	$(BDIRECT) $(ZLAZYLOAD)

CSTD = $(CSTD_GNU99)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG)

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDDATAFILES) \
	$(ROOTONBLDMAN1ONBLDFILES)

clean:
	$(RM) -f $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(CUSTRDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/tools/Makefile.targ
