# CR\_for\_FreeBSD

This Project is Checkpoint/Restore tools for FreeBSD.  
The same project is CRIU. (https://criu.org/)  
The goal is Containers live migration among heterogeneous OS platform. Now, supporting Linux and FreeBSD.  
*support process is Linux Binary only* 

## install(FreeBSD)
FreeBSD has make command, 'devel/gmake' or 'gmake'.
Please install gmake.  
`pkd install -y gmake`

Enable Linux Binary Compatibility(Linuxulator).  
`kldload linux`  
`kldload linux64`  
`pkg install emulators/linux_base-c6`  

For Linuxulator be enaled at boot time, add this line to /etc/rc.conf:  
`linux_enable="YES"`

This project use procfs. procfs is not standard in FreeBSD.  
`mount -t procfs procfs /proc`  

use protobuf-c
`pkg install protobuf-c`

## install(Linux)
Using `bsd/string.h`in Linux, please install libbsd.
`apt-get install libbsd-dev`

## usage
1. `make`
2. `test/countlinuxsta`
3. `./get.py countlinuxsta` or `./crtools dump -p <PID>` in other tarminal
4. `./crtools restore -e test/countlinuxsta -p <PID>`


## function
- crtools: main function. Crtools checkpoint/restore target process.
  - checkpoint: Get and dump target process' status(cpu, memory, fd, etc.).
  - restore: Read from dump files and restore target process.
- compel: For parasite code injection(https://criu.org/Parasite_code). Parasite code injection compel target process to run any code include systemcall. 
