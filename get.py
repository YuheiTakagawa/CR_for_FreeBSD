#!/usr/bin/env python3
import subprocess
import re
import sys
import platform

argv = sys.argv
print("cmdline: " + str(argv))
ps = subprocess.check_output(["ps", "ax"]).decode('utf-8')
ps = ps.split("\n")

for i in ps:
    if argv[0] not in i and "migrate.sh" not in i and argv[1] in i:
        pid = i.split()[0]


print("PID: " + pid)

ret = subprocess.check_output(["/CR_for_FreeBSD/crtools", "dump", "-t", "-p", pid])

print(ret.decode('utf-8'))
#subprocess.check_output(["kill", "-TERM", pid])
print("======================")

print(pid)
