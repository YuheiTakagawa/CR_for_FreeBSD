#!/bin/sh

for i in `seq 1 1000`
do
	test/countlinuxsta-file &
	sleep 1
	res=`./get.py count`
	aa=`echo "$res" | grep alltime | awk '{print substr($0,8)}'`
	echo $aa >> dumpall_time_file_freebsd 
	aa=`echo "$res" | grep fdstime | awk '{print substr($0,8)}'`
	echo $aa >> dumpfds_time_file_freebsd 
	aa=`echo "$res" | grep regtime | awk '{print substr($0,8)}'`
	echo $aa >> dumpreg_time_file_freebsd 
	aa=`echo "$res" | grep memtime | awk '{print substr($0,8)}'`
	echo $aa >> dumpmem_time_file_freebsd 
done

