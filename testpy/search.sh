#!/bin/sh

HPID=`ps | grep -v grep |grep -v $0| grep $1 | sed 's/^ *//g' | cut -d' ' -f1`

/CR_for_FreeBSD/testpy/testpy $HPID
