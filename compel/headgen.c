#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define __handle_elf handle_elf_x86_64

#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr

/* Check if pointer is out-of-bound */
static int __ptr_oob(const uintptr_t ptr, const uintptr_t start, const size_t size)
{
	uintptr_t end = start + size;

	return ptr >= end || ptr < start;
}

/* Check if pointed structure's end is out-of-bound */
static int __ptr_struct_end_oob(const uintptr_t ptr, const size_t struct_size,
				 const uintptr_t start, const size_t size)
{
	/* the last byte of the structure should be inside [begin, end) */
	return __ptr_oob(ptr + struct_size - 1, start, size);
}

/* Check if pointed structure is out-of-bound */
static int __ptr_struct_oob(const uintptr_t ptr, const size_t struct_size,
			     const uintptr_t start, const size_t size)
{
	return __ptr_oob(ptr, start, size) ||
		__ptr_struct_end_oob(ptr, struct_size, start, size);
}

static int test_pointer(const void *ptr, const void *start, const size_t size,
			 const char *name, const char *file, const int line)
{
	if (__ptr_oob((const uintptr_t)ptr, (const uintptr_t)start, size)) {
		return 1;
	}
	return 0;
}

#define ptr_func_exit(__ptr)						\
	do {								\
		if (test_pointer((__ptr), mem, size, #__ptr,		\
				 __FILE__, __LINE__)) {			\
			free(sec_hdrs);					\
			return -1;					\
		}							\
	} while (0)


static const unsigned char elf_ident_64_le[] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01,
};

FILE *fout;

#define pr_out(fmt, ...)	\
  do{	\
    if(fout)	\
      fprintf(fout, fmt, ##__VA_ARGS__);	\
  }while(0)


static const char *get_strings_section(Elf_Ehdr *hdr, uintptr_t mem, size_t size)
{
	size_t sec_table_size = ((size_t) hdr->e_shentsize) * hdr->e_shnum;
	uintptr_t sec_table = mem + hdr->e_shoff;
	Elf_Shdr *secstrings_hdr;
	uintptr_t addr;

	if (__ptr_struct_oob(sec_table, sec_table_size, mem, size)) {
		return NULL;
	}

	/*
	 * strings section header's offset in section headers table is
	 * (size of section header * index of string section header)
	 */
	addr = sec_table + ((size_t) hdr->e_shentsize) * hdr->e_shstrndx;
	if (__ptr_struct_oob(addr, sizeof(Elf_Shdr),
			sec_table, sec_table_size)) {
		return NULL;
	}
	secstrings_hdr = (void*)addr;

	addr = mem + secstrings_hdr->sh_offset;
	if (__ptr_struct_oob(addr, secstrings_hdr->sh_size, mem, size)) {
		return NULL;
	}

	return (void*)addr;
}

int __handle_elf(void *mem, size_t size){
	const char *symstrings = NULL;
	Elf64_Shdr *symtab_hdr = NULL;
	Elf64_Sym *symbols = NULL;
	Elf64_Ehdr *hdr = mem;

	Elf64_Shdr *strtab_hdr = NULL;
	Elf64_Shdr **sec_hdrs = NULL;
	const char *secstrings;

	size_t i, k, nr_gotpcrel = 0;
	int ret = -1;
	const char *name;

	sec_hdrs = malloc(sizeof(*sec_hdrs) * hdr->e_shnum);
	if(!sec_hdrs){
		printf("err: No memory for section headers\n");
		ret = -1;
	}

	secstrings = get_strings_section(hdr, (uintptr_t)mem, size);

	for (i = 0; i < hdr->e_shnum; i++){
		Elf64_Shdr *sh = mem + hdr->e_shoff + hdr->e_shentsize*i;
		ptr_func_exit(sh);

		if(sh->sh_type == SHT_SYMTAB)
			symtab_hdr = sh;

		sec_hdrs[i] = sh;
	}

	strtab_hdr = sec_hdrs[symtab_hdr->sh_link];
	ptr_func_exit(strtab_hdr);
	symbols = mem + symtab_hdr->sh_offset;
	ptr_func_exit(symbols);
	symstrings = mem + strtab_hdr->sh_offset;
	ptr_func_exit(symstrings);
	pr_out("/* Autogenerated from %s */\n", "parasite");
	
	for(i = 0; i < symtab_hdr->sh_size / symtab_hdr->sh_entsize; i++){
		Elf64_Sym *sym = &symbols[i];
		Elf64_Shdr *sh_src;

		ptr_func_exit(sym);
		name = &symstrings[sym->st_name];
		ptr_func_exit(name);
		if(!*name)
			continue;

		if(strncmp(name, "__export", 8)){
			continue;
		}

		if((sym->st_shndx && sym->st_shndx < hdr->e_shnum) ||
			sym->st_shndx == SHN_ABS){
			if(sym->st_shndx == SHN_ABS){
				sh_src = NULL;
			}else{
				sh_src = sec_hdrs[sym->st_shndx];
				ptr_func_exit(sh_src);
			}
			pr_out("#define %s_sym%s 0x%lx\n",
			//	"parasite", name, (unsigned long)(sym->st_value + (sh_src ? sh_src->sh_addr : 0)));
					"parasite", name, (unsigned long)(sym->st_value));
		}
	}

	pr_out("static const char %s_blob[] = {\n\t", "parasite");

	for (i = 0, k = 0; i < hdr->e_shnum; i++){
		Elf_Shdr *sh = sec_hdrs[i];
		unsigned char *shdata;
		size_t j;

		if(!(sh->sh_flags & SHF_ALLOC) || ! sh->sh_size)
			continue;

		shdata = mem + sh->sh_offset;

		for (; k < sh->sh_addr; k++){
			if(k && (k % 8) == 0)
				pr_out("\n\t");
			pr_out("0x00,");
		}

		for(j = 0; j < sh->sh_size; j++, k++){
			if(k && (k % 8) == 0)
				pr_out("\n\t");
			pr_out("0x%02x,", shdata[j]);
		}
	}
	pr_out("};\n");
}

int handle_binary(void *mem, size_t size){
	if(memcmp(mem, elf_ident_64_le, sizeof(elf_ident_64_le)) == 0)
		return handle_elf_x86_64(mem, size);
}

int main(int argc, char *argv[]){
	if(argc < 3){
		printf("usage: ./headgen <binary file path> <output path>\n");
	}
	int fd;
	void *mem;
	struct stat st;
	int ret;

	char *input_filename = argv[1];

	fd = open(input_filename, O_RDONLY);
	if(fd < 0){
		printf("Can't open file %s\n", input_filename);
		return -1;
	}

	if(fstat(fd, &st)){
		perror("fstat");
		goto err;
	}
	
	char *output_filename = argv[2];
	fout = fopen(output_filename, "w");
	if(fout == NULL){
		printf("Can't open %s", output_filename);
		goto err;
	}

	mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd, 0);
	if(mem == MAP_FAILED){
		perror("mmap");
		return -1;
	}

	if(handle_binary(mem, st.st_size)){
		close(fd), fd = -1;
		goto err;
	}

	ret = 0;

err:
	if(fd >= 0)
		close(fd);
	return ret;
}
