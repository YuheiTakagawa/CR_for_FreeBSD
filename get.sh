#!/bin/sh

# get process identify of $1 program running
export pid=`ps ax |\
    	grep $1 |\
       	grep -v -e grep -e $0 -e restore -e migrate |\
	sed -e 's/  */ /g'|\
	sed 's/^ //'|\
       	cut -d' ' -f1`

echo target is $pid

data=`cat /proc/$pid/map |\
	sed -n 2P |\
	cut -d' ' -f1`

echo data address is $data

stack=`cat /proc/$pid/map |\
	tail -q -r |\
	sed -n 2P  |\
	cut -d' ' -f1`

#stack=7ffffffdf000
echo stack address is $stack
/CR_for_FreeBSD/getall $pid $data $stack

echo $pid
