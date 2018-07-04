#!/bin/sh

if [ $# -ne 1 ]; then
	echo "./auto.sh <PATH>" 1>&2
	exit 1
fi

rm -f /dump/*

#ipfw.sh add 192.168.11.10 192.168.11.1

while :
do
	var=`ls -F /dump/ | grep -v / |wc -l`
	var2=`ps -x |grep scp |grep -v grep |wc -l`
	if [ $var -eq 8 -a $var2 -eq 0 ]
	then
		pid=`ls /dump | cut -d'_' -f1`
		ifconfig enp0s25 192.168.11.1
		ifconfig enp0s25 192.168.11.1
		/CR_for_FreeBSD/crtools restore -e $1 -p $pid
		break
	fi

done

#pid=`ls -lrt /dump/ | tail -n 1| sed 's/  */ /g' | cut -d' ' -f9 | cut -d'_' -f1`
#echo $pid

