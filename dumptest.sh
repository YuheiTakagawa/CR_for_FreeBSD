#!/bin/sh

for i in `seq 1 1000`
do
	test/countlinuxsta &
	sleep 1
	res=`./get.py count`
	aa=`echo "$res" | grep time | awk '{print substr($0,5)}'`
	echo $aa >> ooooo
done

