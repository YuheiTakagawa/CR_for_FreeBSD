#!/bin/sh

nmcli c m enp1s0 ipv4.addresses 192.168.11.2
nmcli c up enp1s0
ping -c 192.168.11.1
