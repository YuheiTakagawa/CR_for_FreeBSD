COMPELFLAG := -fpie
ASFLAG := -c
ASFLAG += -Wstrict-prototypes
ASFLAG += -D__ASSEMBLY__
ASFLAG += -nostdlib
ASFLAG += -fomit-frame-pointer
ASFLAG += -fno-stack-protector

parasite += infect.o
parasite += syscall.o
parasite += parasite-head.o

INCLUDE := -I ../

include ../../scripts/msg.mk

all: parasite-head
.PHONY: all

parasite-head: $(parasite) ../compel-pack.lds.S
	$(call msg-link, $@)
	$(Q) $(LD) -pie $(parasite) -o $@ -T ../compel-pack.lds.S

%.o: %.S
	$(call msg-cc, $@)
	$(Q) $(CC) $(INCLUDE) $(COMPELFLAG) $(ASFLAG) -o $@ $^

%.o: %.c
	$(call msg-cc, $@)
	$(Q) $(CC) $(INCLUDE) $(COMPELFLAG) $(CFLAG) -o $@ $^
