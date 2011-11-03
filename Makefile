#------------------------------------------------------------------------------
# File: Makefile
#
# Note: This Makefile requires GNU make.
#
# (c) 2001,2000 Stanford University
#
#------------------------------------------------------------------------------

all : sr

CC = gcc

OSTYPE = $(shell uname)

ifeq ($(OSTYPE),CYGWIN_NT-5.1)
ARCH = -D_CYGWIN_
endif

ifeq ($(OSTYPE),Linux)
ARCH = -D_LINUX_
SOCK = -lnsl -lresolv
endif

ifeq ($(OSTYPE),SunOS)
ARCH =  -D_SOLARIS_
SOCK = -lnsl -lsocket -lresolv
endif

ifeq ($(OSTYPE),Darwin)
ARCH = -D_DARWIN_
SOCK = -lresolv
endif

CFLAGS = -g -Wall  -D_DEBUG_ -D_GNU_SOURCE $(ARCH) -Ilib/ -Isrc/

LIBS= $(SOCK) -lm -lpthread
PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER}
PURIFY= purify ${PFLAGS}


# Add any header files you've added here
sr_HDRS = lib/sha1.h lib/sr_dumper.h lib/sr_if.h lib/sr_rt.h lib/sr_utils.h \
          lib/vnscommand.h src/sr_arpcache.h src/sr_protocol.h src/sr_router.h

# Add any source files you've added here
sr_SRCS = lib/sha1.c lib/sr_dumper.c lib/sr_if.c lib/sr_rt.c lib/sr_utils.c \
          lib/sr_vns_comm.c src/sr_arpcache.c src/sr_main.c src/sr_router.c

sr_OBJS = $(patsubst %.c,%.o,$(sr_SRCS))
sr_DEPS = $(patsubst %.c,%.d,$(sr_SRCS))

hurr :
	@echo $(sr_DEPS)

$(sr_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(sr_DEPS) : %.d : %.c
	$(CC) -MM $(CFLAGS) $<  > $@

include $(sr_DEPS)

sr : $(sr_OBJS)
	$(CC) $(CFLAGS) -o sr $(sr_OBJS) $(LIBS)

sr.purify : $(sr_OBJS)
	$(PURIFY) $(CC) $(CFLAGS) -o sr.purify $(sr_OBJS) $(LIBS)

.PHONY : clean clean-deps dist

clean:
	rm -f *.o *~ core sr *.dump *.tar tags

clean-deps:
	rm -f .*.d

dist-clean: clean clean-deps
	rm -f .*.swp sr_stub.tar.gz

dist: dist-clean
	(cd ..; tar -X stub/exclude -cvf sr_stub.tar stub/; gzip sr_stub.tar); \
    mv ../sr_stub.tar.gz .

tags:
	ctags *.c

submit:
	@tar -czf router-submit.tar.gz $(sr_SRCS) $(sr_HDRS) README Makefile

