#!/bin/sh

pid=`/CR_for_FreeBSD/get.py $1 | tail -n 1`
echo $pid
ifconfig enp0s25 192.168.11.3

scp /dump/$pid\_* root@192.168.11.2:/dump
