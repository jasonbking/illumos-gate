#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

CMDDIR=		$(SRC)/cmd/zic

include		$(SRC)/tools/Makefile.tools
include		$(CMDDIR)/Makefile.common

CPPFLAGS +=	-include $(SRC)/head/tzfile.h -I$(CMDDIR) -DZIC_TOOLS_BUILD

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

%.o:		$(CMDDIR)/%.c
		$(COMPILE.c) -o $@ $<

install:	all $(ROOTONBLDMACHPROG)

clean:
		$(RM) $(PROG) $(OBJS)

include		$(SRC)/tools/Makefile.targ
