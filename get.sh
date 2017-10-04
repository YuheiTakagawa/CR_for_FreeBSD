#!/bin/sh

# get process identify of $1 program running
pid=`ps ax |\
    	grep $1 |\
       	grep -v -e grep -e $0  |\
       	cut -d' ' -f1`

echo target is $pid

data=`cat /compat/linux/proc/$pid/maps |\
       	grep -A 1 $1 |\
       	grep -v $1 |\
       	cut -d'-' -f1`

echo data address is $data

stack=`cat /compat/linux/proc/$pid/maps |\
	grep -E  "\\[stack\]"|\
	cut -d'-' -f1`

echo stack address is $stack
/CR_for_FreeBSD/getall $pid $data $stack
