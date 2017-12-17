#!/usr/bin/env python3
import subprocess
import re
import sys

argv = sys.argv
print("cmdline: " + str(argv))
ps = subprocess.check_output(["ps", "ax"]).decode('utf-8')
ps = ps.split("\n")

for i in ps:
    if argv[0] not in i and argv[1] in i:
        pid = i.split()[0]


print("PID: " + pid)

with open("/proc/" + pid + "/map", "r") as f:
    mm = f.read()

mm = mm.split("\n")

# Generally, data segment is 2nd from top
data = mm[1].split()[0]
print("DATA: " + data)

# Generally, stack segment is 2nd from bottom  text has last line '\n'
stack = mm[-3].split()[0]
print("STACK: " + stack)

# get fd information from procstat(1) 
prst = subprocess.check_output(["procstat", "-f", pid]).decode('utf-8')
prst = prst.split("\n")
tmp = prst[0].split()

row = [tmp.index("FD"), tmp.index("OFFSET"), tmp.index("NAME")]

tmp = prst[-2].split()
print("======================")
print("FD: " + tmp[row[0]])
print("OFFSET: " + tmp[row[1]])
print("NAME: " + tmp[row[2]])
print("======================")

ret = subprocess.check_output(["/CR_for_FreeBSD/getall", pid, data, stack])
print(pid)
