# FreeBSD make is 'devel/gmake'
# This Makefile is for 'gmake'

GNUMAKE=@`sh -c \
	'if (make --version |grep "^GNU Make" 2>&1 >/dev/null); \
	then echo make; else echo gmake; fi' 2>/dev/null`

TARGETMAKEFILE=./Makefile.target

all:
	$(GNUMAKE) -f $(TARGETMAKEFILE) $@

.DEFAULT:
	$(GNUMAKE) -f $(TARGETMAKEFILE) $@
