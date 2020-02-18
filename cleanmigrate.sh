#!/bin/sh

nmcli c m enp1s0 ipv4.addresses 192.168.11.2
nmcli c up enp1s0
ping -c 1 192.168.11.1

if [ $1 eq 1 ]; then
	nmcli c m enp1s0 ipv4.method auto
	nmcli c up enp1s0
fi
