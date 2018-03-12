#!/bin/sh
rm /dump/*

while :
do
	var=`ls -F /dump/ | grep -v /|wc -l`
	var2=`ps -x | grep scp | grep -v grep | wc -l`
	if [ $var -eq 5 -a $var2 -eq 0 ]
	then
		pid=`ls /dump | cut -d'_' -f1`
		/CR_for_FreeBSD/restore $1 $pid 

	fi

done
