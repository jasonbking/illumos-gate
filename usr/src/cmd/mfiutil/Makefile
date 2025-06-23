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
# Copyright 2024 RackTop Systems, Inc.
#


PROG= mfiutil
ROOT_PROG_LINK = $(ROOTUSRSBIN)/mrsasutil $(ROOTUSRSBIN)/lmrcutil
$(ROOT_PROG_LINK) := FILEMODE = 0555

OBJS= mfiutil.o mfi_bbu.o mfi_cmd.o mfi_config.o mfi_drive.o mfi_evt.o \
      mfi_flash.o mfi_patrol.o mfi_show.o mfi_volume.o mfi_foreign.o \
      mfi_properties.o
SRCS= $(OBJS:%.o=%.c)

include ../Makefile.cmd
include ../Makefile.ctf

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE) -DDEBUG -I$(SRC)/uts/common
LDLIBS +=	-lcmdutils -ldevinfo
CSTD=	$(CSTD_GNU99)
SMATCH=off

all: $(PROG)

$(ROOT_PROG_LINK): $(ROOTUSRSBIN)/$(PROG)
	-$(RM) $@
	$(LN) $(ROOTUSRSBIN)/$(PROG) $@

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

install: all $(ROOTUSRSBINPROG) $(ROOT_PROG_LINK)

clean:
	$(RM) $(OBJS) $(PROG)

lint:	lint_SRCS

include ../Makefile.targ
