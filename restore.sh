#!/bin/sh

#for i in `ls /dump/*stack.img | awk '{print substr($0, 7)}'`
for i  in `seq 1 100`
do
	res=`./restore test/countlinuxsta-file 9495 7ffffffde000 100` 
	aa=`echo "$res" | grep fdstime | awk '{print substr($0,8)}'`
	echo $aa >> restorefds_time_file_linuxfreebsd
	aa=`echo "$res" | grep memtime | awk '{print substr($0,8)}'`
	echo $aa >> restoremem_time_file_linuxfreebsd
	aa=`echo "$res" | grep regtime | awk '{print substr($0,8)}'`
	echo $aa >> restorereg_time_file_linuxfreebsd
done

