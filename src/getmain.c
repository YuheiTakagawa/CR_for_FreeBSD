#ifndef __GETMAIN_
#define __GETMAIN_
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>


#ifdef __x86_64__
typedef uint64_t Elf_Addr;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym  Elf_Sym;
#else
typedef uint32_t Elf_Addr;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym  Elf_Sym;
#endif

/* Reference http://d.hatena.ne.jp/rti7743/20170616/1497628434 */

Elf64_Addr get_entry_point(char* filepath){
	int fd = open(filepath, O_RDONLY);
	if (fd < 0){
		return 0;
	}

	Elf_Ehdr ehdr;
	Elf_Shdr shdr;
	Elf_Shdr shdr_linksection;
	Elf_Sym  sym;
	int r = read(fd,&ehdr,sizeof(ehdr));
	if(r < 0){
		close(fd);
		return 0;
	}
	if(memcmp(ehdr.e_ident,ELFMAG,SELFMAG) != 0){
		close(fd);
		return 0;
	}

	for(int i = 0 ; i < ehdr.e_shnum ; i++ )
	{
		lseek(fd,ehdr.e_shoff + (i * sizeof(shdr)),SEEK_SET);
		r = read(fd,&shdr,sizeof(shdr));
		if ( r < sizeof(shdr)){
			continue;
		}
		if ( ! (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM)){
			continue;
		}

		lseek(fd,ehdr.e_shoff + (shdr.sh_link * sizeof(shdr)),SEEK_SET);
		r = read(fd,&shdr_linksection,sizeof(shdr_linksection));
		if(r < sizeof(shdr_linksection)){
			continue;
		}

		const unsigned int nloop_count = shdr.sh_size / sizeof(sym);
		for(int n = 0 ; n < nloop_count; n++ ){
			lseek(fd,shdr.sh_offset + (n*sizeof(sym)),SEEK_SET);
			r = read(fd,&sym,sizeof(sym));
			if ( r < sizeof(sym) ){
				continue;
			}

			char buf[256];
			lseek(fd,shdr_linksection.sh_offset + sym.st_name,SEEK_SET);
			r = read(fd,buf,255);
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
#endif
