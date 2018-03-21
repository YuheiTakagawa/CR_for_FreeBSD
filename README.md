# CR\_for\_FreeBSD

This Project is Checkpoint/Restore tools for FreeBSD.  
The same project is CRIU. (https://criu.org/)  
The goal is Containers live migration among heterogeneous OS platform. Now, supporting Linux and FreeBSD.  
*support process is Linux Binary only* 

## install
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


## usage
1. `make`
2. `test/countlinuxsta`
3. `./get.py countlinuxsta` or `./getall <PID>` in other tarminal
4. `./restore test/countlinuxsta <PID>`
