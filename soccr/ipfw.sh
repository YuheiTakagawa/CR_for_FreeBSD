#!/bin/sh
no=4000
if [ $1 = "add" ]; then
	iptables -I INPUT -s $2 -d $3 -j DROP
	iptables -I INPUT -s $3 -d $2 -j DROP
fi

if [ $1 = "delete" ]; then
	iptables -D INPUT -s $2 -d $3 -j DROP 
	iptables -D INPUT -s $3 -d $2 -j DROP
fi
