COMPELFLAG	:= -fpie
ASFLAG		:= -c
ASFLAG		+= -Wstrict-prototypes
ASFLAG		+= -D__ASSEMBLY__
ASFLAG		+= -nostdlib
ASFLAG		+= -fomit-frame-pointer
ASFLAG		+= -fno-stack-protector

CFLAG		+= -c

parasite	+= infect.o
parasite	+= syscall.o
parasite	+= parasite-head.o

target		:= parasite-head

INCLUDE		:= -I ./std -I ./ -I ../ -I ../include

LDS		:= ../compel-pack.lds.S

include ../../scripts/msg.mk

all: $(target)
.PHONY: all

parasite-head: $(parasite) $(LDS)
	$(call msg-link, $@)
	$(Q) $(LD) -pie $(parasite) -o $@ -T $(LDS)

%.o: %.S
	$(call msg-cc, $@)
	$(Q) $(CC) $(INCLUDE) $(COMPELFLAG) $(ASFLAG) -o $@ $^

%.o: %.c
	$(call msg-cc, $@)
	$(Q) $(CC) $(INCLUDE) $(COMPELFLAG) $(CFLAG) -o $@ $^

clean:
	$(call msg-clean, "pie")
	$(Q) $(RM) $(target) $(parasite)
.PHONY: clean
