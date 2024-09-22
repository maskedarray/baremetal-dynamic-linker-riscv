#ifndef ELF_H
#define ELF_H

#include <stdint.h>

#define SHT_SYMTAB  2    // Symbol table section
#define SHT_REL     9    // Relocation section


// ELF header structure
typedef struct {
    uint8_t  e_ident[16];    // Magic number and other info
    uint16_t e_type;         // Object file type
    uint16_t e_machine;      // Architecture
    uint32_t e_version;      // Object file version
    uint32_t e_entry;        // Entry point virtual address
    uint32_t e_phoff;        // Program header table file offset
    uint32_t e_shoff;        // Section header table file offset
    uint32_t e_flags;        // Processor-specific flags
    uint16_t e_ehsize;       // ELF header size in bytes
    uint16_t e_phentsize;    // Program header table entry size
    uint16_t e_phnum;        // Program header table entry count
    uint16_t e_shentsize;    // Section header table entry size
    uint16_t e_shnum;        // Section header table entry count
    uint16_t e_shstrndx;     // Section header string table index
} Elf32_Ehdr;

// Section header structure
typedef struct {
    uint32_t sh_name;        // Section name (string table index)
    uint32_t sh_type;        // Section type
    uint32_t sh_flags;       // Section flags
    uint32_t sh_addr;        // Section virtual address at execution
    uint32_t sh_offset;      // Section file offset
    uint32_t sh_size;        // Section size in bytes
    uint32_t sh_link;        // Link to another section
    uint32_t sh_info;        // Additional section information
    uint32_t sh_addralign;   // Section alignment
    uint32_t sh_entsize;     // Entry size if section holds table
} Elf32_Shdr;

// Symbol table entry structure
typedef struct {
    uint32_t st_name;        // Symbol name (string table index)
    uint32_t st_value;       // Symbol value
    uint32_t st_size;        // Symbol size
    uint8_t  st_info;        // Symbol type and binding
    uint8_t  st_other;       // Symbol visibility
    uint16_t st_shndx;       // Section index
} Elf32_Sym;

// Relocation entry structure
typedef struct {
    uint32_t r_offset;       // Address
    uint32_t r_info;         // Relocation type and symbol index
} Elf32_Rel;

#define ELF32_R_SYM(i)    ((i) >> 8)    // Extract symbol index from relocation info
#define ELF32_R_TYPE(i)   ((uint8_t)(i))// Extract relocation type

#endif
