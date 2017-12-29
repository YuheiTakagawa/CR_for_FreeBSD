#!/bin/sh

for i in `seq 1 1000`
do
	test/countlinuxsta &
	sleep 3
	res=`./get.py count`
	aa=`echo "$res" | grep time`
	echo $aa >> ooooo
done
