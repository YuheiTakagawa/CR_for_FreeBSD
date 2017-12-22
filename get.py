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
    if argv[0] not in i and argv[1] in i:
        pid = i.split()[0]


print("PID: " + pid)

if platform.system() == 'Linux':
	with open("/proc/" + pid + "/maps", "r") as f:
		mm = f.read()
else:
	with open("/proc/" + pid + "/map", "r") as f:
		mm = f.read()

mm = mm.split("\n")

# Generally, data segment is 2nd from top
data = mm[1].split()[0]
print("DATA: " + data)

# Generally, stack segment is 2nd from bottom  text has last line '\n'
stack = mm[-3].split()[0]
print("STACK: " + stack)

ret = subprocess.check_output(["/CR_for_FreeBSD/getall", pid, data, stack])

if platform.system() == 'Linux':
# get fd information from procfs(5)
	prst = subprocess.check_output(["ls", "-l", "/proc/" + pid + "/fd"]).decode('utf-8')
	prst = prst.split("\n")
	tmp = prst[-2].split(" ")
	print(tmp)
	fd = tmp[8]
	name = tmp[10]
	tmp = subprocess.check_output(["cat", "/proc/" + pid + "/fdinfo/" + fd]).decode('utf-8')
	print(tmp)
	tmp = tmp.split("\n")
	print(tmp)
	subprocess.check_output(["kill", "-TERM", pid])

	offset = tmp[0].split(" ")[-1]
	print("======================")
	print("FD: " + fd)
	print("OFFSET: " + offset)
	print("NAME: " + name)
else:
# get fd information from procstat(1) 
	prst = subprocess.check_output(["procstat", "-f", pid]).decode('utf-8')
	subprocess.check_output(["kill", "-TERM", pid])
	prst = prst.split("\n")
	tmp = prst[0].split()

	row = [tmp.index("FD"), tmp.index("OFFSET"), tmp.index("NAME")]

	tmp = prst[-2].split()
	print("======================")
	print("FD: " + tmp[row[0]])
	print("OFFSET: " + tmp[row[1]])
	print("NAME: " + tmp[row[2]])


print("======================")

print(pid)
print(ret.decode('utf-8'))
