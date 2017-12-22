CC=gcc
CFLAG=-Wall
UNAME=${shell uname}

all: restore.c getall.c
ifeq ($(UNAME),Linux)
#for Linux
	$(CC) $(CFLAG) -o restore restore.c
else
ifeq ($(UNAME),FreeBSD)
	$(CC) $(CFLAG) -o getall getall.c
else
	@echo Sorry, unsupported
endif
endif
