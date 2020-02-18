#!/bin/sh

#pid=`/CR_for_FreeBSD/get.py $1 | tail -n 1`
#echo $pid
#ifconfig em0 192.168.11.2

#scp /dump/$pid\_* root@192.168.11.3:/dump

date "+%s%N"
iptables -A INPUT -s 192.168.11.1 -p tcp --tcp-flages SYN SYN -j DROP
iptables -A OUTPUT -s 192.168.11.1 -p tcp --tcp-flags RST,FIN RST,FIN -j DROP

sleep 1

time criu dump --images-dir /root/snapshot-nginx -t $1 --tcp-established --skip-in-flight

time scp -r /root/snapshot-nginx 192.168.11.3:/root

nmcli c m enp1s0 ipv4.method manual ipv4.addresses 192.168.11.4/24

nmcli c up enp1s0
