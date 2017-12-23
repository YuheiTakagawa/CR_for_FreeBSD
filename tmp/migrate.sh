#!/bin/sh

MSG=`./get.sh $1`
echo MSG

pid=`echo $MSG|\
	awk '{print $(NF-0)}'`
echo $pid

scp /dump/$pid\_* $2:/dump/
