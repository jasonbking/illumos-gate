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
# Copyright 2022 Jason King
#

PROG =		lldpd
MANIFEST =	lldpd.xml

OBJS =		agent.o 	\
		lldpd.o 	\
		log.o		\
		neighbor.o	\
		pdu.o		\
		timer.o		\
		util.o

SRCS =		$(OBJS:%.o=%.c)

#HDRS=

LIB_INC=	$(SRC)/lib/liblldp/common

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/Makefile.ctf
include		$(SRC)/cmd/cmd-inet/Makefile.cmd-inet

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)/loadbalancer

CHECKHDRS=	$(HDRS:%.h=%.check)

CPPFLAGS +=	-D_REENTRANT -D__EXTENSIONS__
CPPFLAGS +=	-I$(LIB_INC)

CSTD =      	$(CSTD_GNU99)

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber

LDLIBS +=	-luutil

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

include		$(SRC)/cmd/cmd-inet/usr.lib/Makefile.lib

install:	all $(ROOTLIBINETPROG) $(ROOTMANIFEST)

check:	$(CHKMANIFEST) $(CHECKHDRS)

clean:
	$(RM) $(OBJS)

all install clean clobber: $(LLDPSUBDIRS)

include		$(SRC)/cmd/Makefile.targ

$(LLDPSUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
