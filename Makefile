# FreeBSD make is 'devel/gmake'
# This Makefile is for 'gmake'

export GNUMAKE=@`sh -c \
	'if (make --version |grep "^GNU Make" 2>&1 >/dev/null); \
	then echo make; else echo gmake; fi' 2>/dev/null`

TARGETMAKEFILE=./Makefile.target

all:
	$(GNUMAKE) -e --no-print-directory -f $(TARGETMAKEFILE) $@

.DEFAULT:
	$(GNUMAKE) -e  --no-print-directory -f $(TARGETMAKEFILE) $@
