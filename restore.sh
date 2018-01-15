#!/bin/sh

for i in `ls /dump/*stack.img | awk '{print substr($0, 7)}'`
do
	res=`./restore test/countlinuxsta $i 7ffffffde000 100` 
	aa=`echo "$res" | grep time | awk '{print substr($0,5)}'`
	echo $aa >> restore_time 
done

