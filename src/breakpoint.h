#ifndef __GETMAIN_
#define __GETMAIN_
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
extern Elf64_Addr get_entry_point(char* filepath);
extern void insert_breakpoint(pid_t pid, char *elfpath);
	
#endif
