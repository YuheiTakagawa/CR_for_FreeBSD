#!/bin/sh

for i in `ls /dump/*stack.img | awk '{print substr($0, 7)}' | cut -d'_' -f1`
do
	/usr/bin/time -p scp /dump/$i* 192.168.11.11:/dumpfreebsd 2>&1 | grep real| cut -d' ' -f2 >> scp_time
	#"res=`time scp /dump/$i* 192.168.11.10:/dumpfreebsd` 
	#aa=`echo "$res"|grep real |cut -d' ' -f1` #| awk '{print substr($0,1)}'`
	#echo $aa
	#(echo $res) 2>&1 > scp_time
done

