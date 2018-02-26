#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>
 
#include "ptrace.h"
#include "common.h"
#include "breakpoint.h"

/* Reference http://d.hatena.ne.jp/rti7743/20170616/1497628434 */
char code_int3[] = {
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};

Elf64_Addr get_entry_point(char* filepath){
	int fd = open(filepath, O_RDONLY);
	if (fd < 0){
		return 0;
	}

	Elf_Ehdr ehdr;
	Elf_Shdr shdr;
	Elf_Shdr shdr_linksection;
	Elf_Sym  sym;
	int r = read(fd, &ehdr, sizeof(ehdr));
	if(r < 0){
		close(fd);
		return 0;
	}
	if(memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0){
		close(fd);
		return 0;
	}

	/*
	 * e_shnum is number of section header table entry.
	 * loop as much as e_shnum.
	 * 1. read each section header.
	 * 	 address of section header is 
	 * 	 elf header + e_shnum * size section header
	 *
	 * 2. compare shdr_type to SYMTAB to search section header.
	 * 	 SYMTAB shdr has symbol table which express function name.
	 *
	 * 3. get entity of target section header from link.
	 *
	 * 4. Reading and searching symbol table entry which
	 *    has "main" function.
	 *
	 * 5. get address(st_value) searched in step4.
	 */ 
	for(int i = 0 ; i < ehdr.e_shnum ; i++)
	{
		lseek(fd,ehdr.e_shoff + (i * sizeof(shdr)), SEEK_SET);
		r = read(fd, &shdr, sizeof(shdr));
		if ( r < sizeof(shdr)){
			continue;
		}
		if ( ! (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM)){
			continue;
		}

		lseek(fd, ehdr.e_shoff + (shdr.sh_link * sizeof(shdr)), SEEK_SET);
		r = read(fd, &shdr_linksection, sizeof(shdr_linksection));
		if(r < sizeof(shdr_linksection)){
			continue;
		}

		/*
		 * Searching "main" symbol and getting main function address
		 */
		const unsigned int nloop_count = shdr.sh_size / sizeof(sym);
		for(int n = 0 ; n < nloop_count; n++){
			lseek(fd, shdr.sh_offset + (n * sizeof(sym)), SEEK_SET);
			r = read(fd, &sym, sizeof(sym));
			if ( r < sizeof(sym)){
				continue;
			}

			char buf[256];
			lseek(fd, shdr_linksection.sh_offset + sym.st_name, SEEK_SET);
			r = read(fd, buf, 255);
			if ( r < 0 ){
				continue;
			}
			buf[r] = 0; 
			if(!strcmp(buf, "main")){
				printf("main address: 0x%lx\n", sym.st_value);
				return sym.st_value;
			}
		}
	}

	close(fd);
	return 0;
}

void insert_breakpoint(pid_t pid, char *elfpath){
	int status;
	Elf64_Addr entry_point;
	uint8_t code_orig[BUILTIN_SYSCALL_SIZE];

	memcpy(code_orig, code_int3, sizeof(code_orig));

	waitpro(pid, &status);
	entry_point = get_entry_point(elfpath);
	ptrace_swap_area(pid, (void *)entry_point, (void *)code_orig, sizeof(code_orig));
	ptrace_cont(pid);
}
	
