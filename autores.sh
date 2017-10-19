#!/bin/sh

while :
do
	filepath=`ls /dump | wc -w`
	if [ $filepath -eq 0 ]
	then 
		continue
	fi
	filepath=`ls -tl /dump |\
	       	head -2 |\
		tail -1 |\
	       	awk '{print $(NF-0)}'`
	filetime=`date -r /dump/$filepath +%s`
	nowtime=`date +%s`
	difftime=`expr $nowtime - $filetime`	

	if [ $difftime -lt 10 ]
	then

	pid=`echo $filepath |\
		cut -d'_' -f1`
	echo $pid
	./restore $1 $pid	
	break
	fi

done
