#!/bin/sh

# get process identify of $1 program running
pid=`ps ax | grep $1 | grep -v -e grep -e $0  | cut -d' ' -f1`
echo target is $pid

/CR_for_FreeBSD/getregs $pid
