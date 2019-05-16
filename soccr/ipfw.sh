#!/bin/sh
no=4000
if [ $1 = "add" ]; then
	ipfw add $no deny ip from $2 to $3
	ipfw add $no deny ip from $3 to $2
fi

if [ $1 = "delete" ]; then
	ipfw delete $no 
fi
