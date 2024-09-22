#include <stdint.h>
#include <string.h>
#include "elf.h"

#include <stdio.h>
#include <stdlib.h>

#define OUTPUT_ELF_FILE "output.elf"

#define INSTR_MEM_BASE   0x20000000  // Base address for instruction memory
#define DATA_MEM_BASE    0x30000000  // Base address for data memory

typedef void (*func_ptr_t)(void);

// Array to store function pointers for function1, function2, function3
func_ptr_t func_array[3];

// Function to parse and load the ELF object file
int load_elf(uint8_t *elf_data, uint32_t elf_size) {
    // Step 1: Parse ELF Header
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_data;
    
    // Verify ELF magic number (0x7F 'E' 'L' 'F')
    if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' || 
        ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
        return -1;  // Invalid ELF file
    }

    // Step 2: Locate Section Headers
    Elf32_Shdr *shdr = (Elf32_Shdr *)(elf_data + ehdr->e_shoff);
    Elf32_Shdr *strtab_shdr = &shdr[ehdr->e_shstrndx]; // Section header string table
    char *shstrtab = (char *)(elf_data + strtab_shdr->sh_offset);

    // Step 3: Iterate through sections to find .text and .data
    void *instr_mem = (void *)INSTR_MEM_BASE;
    void *data_mem = (void *)DATA_MEM_BASE;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *section_name = shstrtab + shdr[i].sh_name;
        if (strcmp(section_name, ".text") == 0) {
            // .text section (instruction memory)
            memcpy(instr_mem, elf_data + shdr[i].sh_offset, shdr[i].sh_size);
        } else if (strcmp(section_name, ".data") == 0) {
            // .data section (data memory)
            memcpy(data_mem, elf_data + shdr[i].sh_offset, shdr[i].sh_size);
        }
    }

    // Step 4: Handle Symbol Table and Relocation
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            // Symbol table section
            Elf32_Sym *symtab = (Elf32_Sym *)(elf_data + shdr[i].sh_offset);
            char *strtab = (char *)(elf_data + shdr[shdr[i].sh_link].sh_offset);
            int sym_count = shdr[i].sh_size / sizeof(Elf32_Sym);

            // Find function1, function2, function3 symbols
            for (int j = 0; j < sym_count; j++) {
                char *sym_name = strtab + symtab[j].st_name;
                if (strcmp(sym_name, "function1") == 0) {
                    func_array[0] = (func_ptr_t)(INSTR_MEM_BASE + symtab[j].st_value);
                } else if (strcmp(sym_name, "function2") == 0) {
                    func_array[1] = (func_ptr_t)(INSTR_MEM_BASE + symtab[j].st_value);
                } else if (strcmp(sym_name, "function3") == 0) {
                    func_array[2] = (func_ptr_t)(INSTR_MEM_BASE + symtab[j].st_value);
                }
            }
        }
    }

    // Step 5: Process relocations (if any)
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_REL) {
            // Relocation section
            Elf32_Rel *rel = (Elf32_Rel *)(elf_data + shdr[i].sh_offset);
            Elf32_Shdr *target_shdr = &shdr[shdr[i].sh_info];
            uint8_t *target_section = elf_data + target_shdr->sh_offset;
            int rel_count = shdr[i].sh_size / sizeof(Elf32_Rel);

            // Apply relocations
            for (int j = 0; j < rel_count; j++) {
                uint32_t *target_addr = (uint32_t *)(target_section + rel[j].r_offset);
                uint32_t sym_idx = ELF32_R_SYM(rel[j].r_info);
                uint32_t rel_type = ELF32_R_TYPE(rel[j].r_info);

                Elf32_Sym *sym = (Elf32_Sym *)(elf_data + shdr[shdr[i].sh_link].sh_offset) + sym_idx;

                if (rel_type == 1 /* R_386_32 */) {
                    *target_addr += (sym->st_value + INSTR_MEM_BASE);
                }
            }
        }
    }

    return 0;  // Success
}



int main() {
    // Step 1: Open the input ELF file from the current directory
    FILE *input_file = fopen("input.elf", "rb");
    if (!input_file) {
        perror("Error opening input ELF file");
        return -1;
    }

    // Step 2: Determine the size of the ELF file
    fseek(input_file, 0, SEEK_END);
    uint32_t elf_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Step 3: Allocate memory to read the ELF file
    uint8_t *elf_data = (uint8_t *)malloc(elf_size);
    if (!elf_data) {
        perror("Memory allocation failed");
        fclose(input_file);
        return -1;
    }

    // Step 4: Read the ELF file into memory
    fread(elf_data, 1, elf_size, input_file);
    fclose(input_file);

    // Step 5: Load the ELF file (perform adjustments, etc.)
    if (load_elf(elf_data, elf_size) != 0) {
        fprintf(stderr, "Failed to load ELF file\n");
        free(elf_data);
        return -1;
    }

    // Step 6: Save the adjusted ELF to output file
    FILE *output_file = fopen(OUTPUT_ELF_FILE, "wb");
    if (!output_file) {
        perror("Error opening output ELF file");
        free(elf_data);
        return -1;
    }

    fwrite(elf_data, 1, elf_size, output_file);
    fclose(output_file);

    // Step 7: Cleanup and exit
    free(elf_data);
    printf("ELF file loaded and saved successfully!\n");

    return 0;
}





