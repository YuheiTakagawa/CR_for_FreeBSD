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
		var1=`ls /dump/$pid* | wc -w`
		var2=`ps x | grep scp| grep -v grep| wc -l`
		if [ $var1 -eq 3 -a $var2 -eq 0 ]
		then
			./restore $1 $pid	
			break
		fi
	fi

done
