#!/bin/sh

pid=`/CR_for_FreeBSD/get.py $1 | tail -n 1`
echo $pid
ifconfig em0 192.168.11.2

scp /dump/$pid\_* root@192.168.11.3:/dump
