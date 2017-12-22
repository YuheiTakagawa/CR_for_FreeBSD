#!/bin/sh

stack=`cat /proc/$1/maps |\
	grep stack|\
	cut -d'-' -f1`
echo $stack
