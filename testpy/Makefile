include ../scripts/msg.mk
include ../scripts/tools.mk

CFLAG = -Wall
CFLAG += -D_WITH_DPRINTF

SRC_DIR = ../src
INCLUDE = -I ../include


UNAME := ${shell uname}
ifeq ($(UNAME), Linux)
# for Linux include file
SRC_DEP = ./src/linux
CFLAG += -D_LINUX
endif

ifeq ($(UNAME), FreeBSD)
# for FreeBSD include file
SRC_DEP = ../src/freebsd
CFLAG += -lprocstat
CFLAG += -D_BSD
endif

ifneq ($(UNAME), Linux)
ifneq ($(UNAME), FreeBSD)
	$(error ("Sorry, unsupported"))
endif
endif


OBJ += $(SRC_DIR)/files.o

OBJ += $(SRC_DEP)/ptrace.o
OBJ += $(SRC_DEP)/parasite_syscall.o
OBJ += $(SRC_DEP)/fds.o
OBJ += $(SRC_DEP)/register.o
OBJ += $(SRC_DEP)/getmap.o


COBJ += $(SRC_DIR)/getmem.o
COBJ += $(SRC_DIR)/getall.o


ROBJ += $(SRC_DIR)/setmem.o
ROBJ += $(SRC_DIR)/breakpoint.o
ROBJ += $(SRC_DIR)/restore.o

%.o: %.c
	$(Q) $(CC) $(INCLUDE) $(CFLAG) -c -o $@ $^

target = run

.PHONY: all
all: $(target)

.PHONY: run
run: testpy injd search.sh
	./injd &

parasite-head.h: pie/parasite-head
	../compel/headgen $< $@

.PHONY: pie/parasite-head
pie/parasite-head:
	 gmake -e -C pie

testpy: $(OBJ) $(ROBJ) $(COBJ) parasite-head.h 
	$(call msg-gen, $@)
	$(Q) $(CC) $(CFLAG) $(INCLUDE) ./testpy.c $^ -o $@


.PHONY: clean
clean:
	$(call msg-clean, "criu")
	$(Q) $(RM) $(target) $(OBJ) $(COBJ) $(ROBJ)
	$(Q) $(RM) pie/parasite-head
	$(Q) gmake -e -C pie clean
