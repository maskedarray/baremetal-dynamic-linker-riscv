#include <stdint.h>
#include <string.h>
#include "elf.h"
#include <inttypes.h>


#include <stdio.h>
#include <stdlib.h>


const char* get_relocation_type_name(uint32_t relocation_type) {
    switch (relocation_type) {
        case 0: return "R_NONE";
        case 1: return "R_32";
        case 2: return "R_PC32";
        case 3: return "R_GOT32";
        case 4: return "R_PLT32";
        case 5: return "R_COPY";
        case 6: return "R_GLOB_DAT";
        case 7: return "R_JUMP_SLOT";
        case 8: return "R_RELATIVE";
        // Add more relocation types as needed
        default: return "UNKNOWN_RELOCATION_TYPE";
    }
}

void print_relocation_type(uint32_t relocation_type) {
    printf("Relocation Type: %s\n", get_relocation_type_name(relocation_type));
}

void print_sections(Elf32_Ehdr *ehdr, char* shstrtab, Elf32_Shdr* shdr){
    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *section_name = shstrtab + shdr[i].sh_name;
        printf("Name of Section: %s Offset: %x Size: %x\n", section_name, shdr[i].sh_offset, shdr[i].sh_size);
    }
}

void print_elf_header(Elf32_Ehdr *ehdr) {
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ehdr->e_ident[i]);
    }
    printf("\n");
    printf("  Type:          %u\n", ehdr->e_type);
    printf("  Machine:       %u\n", ehdr->e_machine);
    printf("  Version:       %u\n", ehdr->e_version);
    printf("  Entry point:   %x \n", ehdr->e_entry);
    printf("  Program header offset: %d\n", ehdr->e_phoff);
    printf("  Section header offset:  %d\n", ehdr->e_shoff);
    printf("  Flags:         %u\n", ehdr->e_flags);
    printf("  ELF header size:        %u\n", ehdr->e_ehsize);
    printf("  Program header size:    %u\n", ehdr->e_phentsize);
    printf("  Number of program headers: %u\n", ehdr->e_phnum);
    printf("  Section header size:    %u\n", ehdr->e_shentsize);
    printf("  Number of section headers: %u\n", ehdr->e_shnum);
    printf("  Section header string table index: %u\n", ehdr->e_shstrndx);
}

void print_section_type(Elf32_Shdr *shdr, int shnum) {
    for (int i = 0; i < shnum; i++) {
        switch (shdr[i].sh_type) {
            case SHT_NULL:
                printf("Section %d: SHT_NULL\n", i);
                break;
            case SHT_PROGBITS:
                printf("Section %d: SHT_PROGBITS\n", i);
                break;
            case SHT_SYMTAB:
                printf("Section %d: SHT_SYMTAB\n", i);
                break;
            case SHT_STRTAB:
                printf("Section %d: SHT_STRTAB\n", i);
                break;
            case SHT_RELA:
                printf("Section %d: SHT_RELA\n", i);
                break;
            case SHT_HASH:
                printf("Section %d: SHT_HASH\n", i);
                break;
            case SHT_DYNAMIC:
                printf("Section %d: SHT_DYNAMIC\n", i);
                break;
            case SHT_NOTE:
                printf("Section %d: SHT_NOTE\n", i);
                break;
            case SHT_NOBITS:
                printf("Section %d: SHT_NOBITS\n", i);
                break;
            case SHT_REL:
                printf("Section %d: SHT_REL\n", i);
                break;
            case SHT_SHLIB:
                printf("Section %d: SHT_SHLIB\n", i);
                break;
            case SHT_DYNSYM:
                printf("Section %d: SHT_DYNSYM\n", i);
                break;
            case SHT_LOPROC:
                printf("Section %d: SHT_LOPROC\n", i);
                break;
            case SHT_HIPROC:
                printf("Section %d: SHT_HIPROC\n", i);
                break;
            case SHT_LOUSER:
                printf("Section %d: SHT_LOUSER\n", i);
                break;
            case SHT_HIUSER:
                printf("Section %d: SHT_HIUSER\n", i);
                break;
            default:
                printf("Section %d: Unknown section type (0x%x)\n", i, shdr[i].sh_type);
                break;
        }
    }
}