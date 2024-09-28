#include <stdint.h>
#include <string.h>
#include "elf.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include "prints.h"

#define OUTPUT_ELF_FILE "output.o"


uint32_t func_array[3];


void emit_output_files(Elf32_Shdr *data_section, Elf32_Shdr *bss_section, Elf32_Shdr *text_section, uint8_t *elf_data) {
    // Save combined .data and .bss sections
    FILE *data_bss_file = fopen("data.bin", "wb");
    if (data_bss_file == NULL) {
        DEBUG1 printf("Failed to open file for .data and .bss");
        return;
    }

    // Write the .data section to the file
    size_t data_size = data_section->sh_size;
    uint8_t *data_start = elf_data + data_section->sh_offset;

    if (fwrite(data_start, 1, data_size, data_bss_file) != data_size) {
        DEBUG1 printf("Error writing .data section");
        fclose(data_bss_file);
        return;
    }

    DEBUG2 printf(".data section written, size: %zu bytes\n", data_size);

    // zero out the bss section
    size_t bss_size = bss_section->sh_size;
    uint8_t *bss_zeroes = calloc(1, bss_size);  // Allocate zeroed-out memory

    if (fwrite(bss_zeroes, 1, bss_size, data_bss_file) != bss_size) {
        DEBUG1 printf("Error writing .bss section");
        free(bss_zeroes);
        fclose(data_bss_file);
        return;
    }

    DEBUG2 printf(".bss section written, size: %zu bytes (zeroes)\n", bss_size);

    // Clean up for data_bss file
    free(bss_zeroes);
    fclose(data_bss_file);
    DEBUG2 printf(".data and .bss sections saved successfully.\n");

    // Save .text section
    FILE *text_file = fopen("text.bin", "wb");
    if (text_file == NULL) {
        DEBUG1 printf("Failed to open file for .text");
        return;
    }

    // Write the .text section to the file
    size_t text_size = text_section->sh_size;
    uint8_t *text_start = elf_data + text_section->sh_offset;

    if (fwrite(text_start, 1, text_size, text_file) != text_size) {
        DEBUG1 printf("Error writing .text section");
        fclose(text_file);
        return;
    }

    DEBUG2 printf(".text section written, size: %zu bytes\n", text_size);

    fclose(text_file);
}

// Function to relocate the elf file
int load_elf(uint8_t *elf_data, uint32_t elf_size) {

    uint32_t new_data_base_addr = 0x81800000;
    uint32_t new_text_base_addr = 0x81000000;
    
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_data;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(elf_data + ehdr->e_shoff);
    Elf32_Shdr *strtab_shdr = &shdr[ehdr->e_shstrndx]; // Section header string table
    char *shstrtab = (char *)(elf_data + strtab_shdr->sh_offset);

#ifdef VERIFY_ELF_MAGIC
    // Verify ELF magic number (0x7F 'E' 'L' 'F')
    if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' || 
        ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
        return -1;  // Invalid ELF file
    }
#endif
    
    DEBUG2 printf("starting location of loaded elf: %x\n", elf_data);
    DEBUG2 printf("Size of elf header structure: %d\n", sizeof(Elf32_Ehdr));
    DEBUG1 print_elf_header(ehdr);
    DEBUG2 print_sections(ehdr, shstrtab, shdr);
    DEBUG2 print_section_type(shdr, ehdr->e_shnum);

    
    // Pointers to sections to be used in relocation
    Elf32_Shdr *data_section = NULL;
    Elf32_Shdr *bss_section = NULL;
    Elf32_Shdr *text_section = NULL;
    Elf32_Shdr *symtab_section = NULL;
    Elf32_Shdr *rela_shdr = NULL;
    // Write the address of sections to the pointers
    for (int i = 0; i < ehdr->e_shnum; i++) {
        printf("%s\n",  (char *)(shstrtab + shdr[i].sh_name));
        if (shdr[i].sh_type == SHT_PROGBITS && strcmp(".data", (char *)(shstrtab + shdr[i].sh_name)) == 0) {
            data_section = &shdr[i];
        } else if (shdr[i].sh_type == SHT_NOBITS && strcmp(".bss", (char *)(shstrtab + shdr[i].sh_name)) == 0) {
            bss_section = &shdr[i];
        } else if (shdr[i].sh_type == SHT_PROGBITS && strcmp(".text", (char *)(shstrtab + shdr[i].sh_name)) == 0) {
            text_section = &shdr[i];
            shdr[i].sh_addr = new_text_base_addr;
        } else if (shdr[i].sh_type == SHT_SYMTAB && strcmp(".symtab", (char *)(shstrtab + shdr[i].sh_name)) == 0) {
            symtab_section = &shdr[i];
        } else if (shdr[i].sh_type == SHT_RELA && strcmp(".rela.text", (char *)(shstrtab + shdr[i].sh_name)) == 0) {
            rela_shdr = &shdr[i];
        }
    }
    
    DEBUG1 {
        if (!data_section || !symtab_section || !rela_shdr || !bss_section || !text_section) { // TODO: remove from final build
            printf("Section not found.\n"); 
            return;
        }
    }

    // Step 2: Update symbol table entries for .data and .bss symbols
    Elf32_Sym *symtab = (Elf32_Sym *)(elf_data + symtab_section->sh_offset);
    int sym_count = symtab_section->sh_size / sizeof(Elf32_Sym);
    for (int i = 0; i < sym_count; i++) {
        char* sym_name = (char *)(elf_data + shdr[symtab_section->sh_link].sh_offset + symtab[i].st_name);

        // Update the data section symbols
        if (symtab[i].st_shndx == (data_section - shdr)) {
            symtab[i].st_value += new_data_base_addr;

            DEBUG2 printf("Updated symbol: %s\n", sym_name);
            DEBUG2 printf("  Old Address: 0x%08x\n", symtab[i].st_value - (new_data_base_addr - data_section->sh_addr));
            DEBUG2 printf("  New Address: 0x%08x\n", symtab[i].st_value);
        } 
        // Update the bss section symbols
        else if (symtab[i].st_shndx == (bss_section - shdr)){
            symtab[i].st_value += new_data_base_addr + data_section->sh_size;

            DEBUG2 printf("Updated symbol: %s\n", sym_name);
            DEBUG2 printf("  Old Address: 0x%08x\n", symtab[i].st_value - (new_data_base_addr - data_section->sh_addr));
            DEBUG2 printf("  New Address: 0x%08x\n", symtab[i].st_value);
        } 
        // Since we are iterating over symbol table, find the addresses of functions which are to be passed to PMU
        if (strcmp(sym_name, "complexFunction1") == 0) {
            func_array[0] = new_text_base_addr + symtab[i].st_value;
        } else if (strcmp(sym_name, "complexFunction2") == 0) {
            func_array[1] = new_text_base_addr + symtab[i].st_value;
        } else if (strcmp(sym_name, "complexFunction3") == 0) {
            func_array[2] = new_text_base_addr + symtab[i].st_value;
        }
    }



    // Get pointers for relocation
    Elf32_Rela *rela_section = (Elf32_Rela *)(elf_data + rela_shdr->sh_offset);
    Elf32_Shdr *target_shdr = &shdr[rela_shdr->sh_info];   // This should point to the .text section
    uint8_t *target_section = elf_data + target_shdr->sh_offset;
    int rel_count = rela_shdr->sh_size / sizeof(Elf32_Rela);    // Number of relocations to process


    DEBUG2 printf("relocation section offset: %x\n", rela_shdr->sh_offset);   
    DEBUG2 printf("rela_section section starting address: %x\n", rela_section);
    DEBUG2 printf("target shdr sh_info %x\n",rela_shdr->sh_info);
    DEBUG2 printf("Absolute address of target section %x \n",target_section );
    DEBUG2 printf("Relocation section size %x \n",rela_shdr->sh_size );   
    DEBUG2 printf("relocation count = %d\n", rel_count);

    // Iterate over relocation count to apply relocations
    for (int j = 0; j < rel_count; j++) {
        uint32_t *target_addr = (uint32_t *)(target_section + rela_section[j].r_offset);
        uint32_t sym_idx = ELF32_R_SYM(rela_section[j].r_info);
        uint32_t rel_type = ELF32_R_TYPE(rela_section[j].r_info);
        Elf32_Sym *sym = (Elf32_Sym *)(elf_data + shdr[rela_shdr->sh_link].sh_offset) + sym_idx;
        int str_table_index = shdr[rela_shdr->sh_link].sh_link;

        char *sym_name = (char *)(elf_data + shdr[str_table_index].sh_offset + sym->st_name);

        DEBUG1 printf("Accessing symbol table using index: %d with offset %x and address %x\n", rela_shdr->sh_link, shdr[rela_shdr->sh_link].sh_offset, elf_data + shdr[rela_shdr->sh_link].sh_offset);
        DEBUG1 printf("size of elf32_sym: %x, sym at index %d and address: %x\n", sizeof(Elf32_Sym), rela_shdr->sh_link, sym);
        DEBUG1 printf("Relocation %d:\n", j);
        DEBUG1 printf("  Relocation Offset: 0x%08x\n", rela_section[j].r_offset);
        DEBUG1 printf("  Symbol Index: %u\n", sym_idx);
        DEBUG1 printf("  Relocation Type: %u\n", rel_type);
        DEBUG1 printf("  Target Address: 0x%08x\n", (unsigned int)target_addr);
        DEBUG1 printf("  Symbol Value (st_value): 0x%08x\n", sym->st_value);
        DEBUG1 printf("  Symbol Size (st_size): %u\n", sym->st_size);
        DEBUG1 printf("  Symbol Section Index (st_shndx): %u\n", sym->st_shndx);
        DEBUG1 printf("  Symbol Name Offset (st_name): 0x%08x\n", sym->st_name);
        DEBUG1 printf("  String Table Section Index: %d\n", str_table_index);
        DEBUG1 printf("  String Table Offset: 0x%08x\n", shdr[str_table_index].sh_offset);
        DEBUG1 printf("  Symbol Name: %s\n", sym_name);

        uint32_t imm ;
        switch (rel_type) {
            case R_RISCV_NONE: {
                // Do nothing
                break;
            }

            case R_RISCV_32:     {  // TODO: Test
                DEBUG1 printf("  Applying R_RISCV_32 relocation\n");
                *target_addr = sym->st_value + rela_section[j].r_addend;
                break;
            }

            case R_RISCV_BRANCH:  {  // Tested
                // Not a function, continue to next relocation
                // It could be a local label. We do not need to change local labels
                if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC) continue;
                   
                uint32_t imm = (sym->st_value + rela_section[j].r_addend - ((uint32_t)target_addr - (uint32_t)elf_data - text_section->sh_offset));
                *target_addr = ((*target_addr & 0x1FFF07F) | \
                    (((imm & 0x1FFE) & 0x1000) << 31) | \
                    (((imm & 0x1FFE) & 0xFC0) << 25) | \
                    (((imm & 0x1FFE) & 0x1E) << 8) | \
                    (((imm & 0x1FFE) & 0x800) << 7));
                
                DEBUG1 printf("  Applying R_RISCV_BRANCH relocation\n");
                DEBUG1 printf("addend: %x, pc addr: %x, relative offset: %x\n", rela_section[j].r_addend, ((uint32_t)target_addr - (uint32_t)elf_data - text_section->sh_offset), imm);
                DEBUG1 printf("After applying relocation instruction became: %x, 0x1e: %x\n", *target_addr, ((imm & 0x1FFE) & 0x1E));
                break;
            }

            case R_RISCV_JAL:  { // Tested
                // Not a function, continue to next relocation
                // It could be a local label. We do not need to change local labels
                if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC) continue;
                    
                imm = (sym->st_value + rela_section[j].r_addend - ((uint32_t)target_addr - (uint32_t)elf_data - text_section->sh_offset));
                *target_addr = ((*target_addr & 0xFFF) | \
                    ((imm & 0x100000) << 31) | \ 
                    ((imm & 0x7FE) << 21) | \
                    ((imm & 0x800) << 20) | \
                    ((imm & 0xFF000) << 12) \
                    );
                
                DEBUG1 printf("  Applying R_RISCV_JAL relocation\n");
                break;
            }

            case R_RISCV_CALL_PLT: { // Tested
                // Not a function, continue to next relocation
                // It could be a local label. We do not need to change local labels
                if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC) continue;

                imm = (sym->st_value + rela_section[j].r_addend - ((uint32_t)target_addr - (uint32_t)elf_data - text_section->sh_offset));
                uint32_t upper_20 = imm & 0xFFFFF000;
                uint32_t lower_12 = imm & 0xFFF;
                if (lower_12 & 0x800){   // This means the msb of lower 12 bits is high and we increment the upper 20 bits and then take 2's complement of lower 12 bits
                    upper_20 = upper_20 + 0x1000;
                    lower_12 -= 0x1000 ;
                }
                // This relocation is a combination of auipc + jalr instruction
                *target_addr = (*target_addr & 0xFFF) | upper_20;
                target_addr++; // TODO: with compressed instructions code this will not work
                *target_addr = (*target_addr & 0xFFFFF) | (lower_12 << 20);

                DEBUG1 printf("  Applying R_RISCV_CALL relocation\n");
                break;
            }

            case R_RISCV_PCREL_HI20: {  // TODO: Test
                imm = (sym->st_value + rela_section[j].r_addend - ((uint32_t)target_addr - (uint32_t)elf_data - text_section->sh_offset));
                *target_addr = (*target_addr & 0xFFF) | \
                    ((imm >> 12) << 12);

                DEBUG1 printf("  Applying R_RISCV_PCREL_HI20 relocation\n");
                DEBUG1 printf("  After applying R_RISCV_PCREL_HI20 relocation, target_addr: 0x%x\n", *target_addr);
                break;
            }

            case R_RISCV_PCREL_LO12_I: {    // TODO: Test
                imm = (sym->st_value - ((uint32_t)target_addr - (uint32_t)elf_data - text_section->sh_offset));
                *target_addr = (*target_addr & 0xFFF) | \
                    ((imm & 0xFFF) << 20);

                DEBUG1 printf("  Applying R_RISCV_PCREL_LO12_I relocation\n");
                DEBUG1 printf("  After applying R_RISCV_PCREL_LO12_I relocation, target_addr: 0x%x\n", *target_addr);
                break;
            }

            case R_RISCV_PCREL_LO12_S: {    // TODO: Test
                int32_t offset = (sym->st_value - (uint32_t)target_addr) & 0xFFF;
                imm = (sym->st_value - ((uint32_t)target_addr - (uint32_t)elf_data - text_section->sh_offset));
                DEBUG1 printf("  Applying R_RISCV_PCREL_LO12_S relocation\n");
                *target_addr = (*target_addr & 0x1FFF07F) | \
                    ((imm & 0xFE0) << 20) | \
                    ((imm & 0x1F) << 7);

                DEBUG1 printf("  After applying R_RISCV_PCREL_LO12_S relocation, target_addr: 0x%x\n", *target_addr);
                break;
            }

            case R_RISCV_HI20:  {// Tested
                DEBUG1 printf("  Applying R_RISCV_HI20 relocation, target_addr pointer: %x, target_addr: %x, sym->st_value: %x, r_addend: %d\n", target_addr, *target_addr, sym->st_value, rela_section[j].r_addend);
                *target_addr = ((*target_addr & 0xFFF) | \
                    ((sym->st_value + rela_section[j].r_addend) >> 12) << 12);
                DEBUG1 printf("  After applying R_RISCV_HI20 relocation, target_addr: %x\n", *target_addr);
                break;
            }

            case R_RISCV_LO12_I:   { // Tested
                imm = (sym->st_value + rela_section[j].r_addend);
                *target_addr = ((*target_addr & 0xFFFFF) | \
                    ((imm & 0xFFF) << 20));
                
                DEBUG1 printf("  Applying R_RISCV_LO12_I relocation, target_addr pointer: %x, target_addr: %x, sym->st_value: %x, r_addend: %d\n", target_addr, *target_addr, sym->st_value, rela_section[j].r_addend);
                DEBUG1 printf("  After applying R_RISCV_LO12_I relocation, target_addr: %x\n", *target_addr);
                break;
            }

            case R_RISCV_LO12_S:  {  // Tested
                imm = (sym->st_value + rela_section[j].r_addend);
                *target_addr = ((*target_addr & 0x1FFF07F) | \
                    ((imm & 0xFE0) << 25) | \
                    ((imm & 0x1F) << 7));

                DEBUG1 printf("  Applying R_RISCV_LO12_S relocation\n");
                break;
            }

            default: {
                DEBUG1 printf("  Unsupported relocation type: %d\n", rel_type);
                break;
            }
        }
    }


    emit_output_files (data_section, bss_section,text_section, elf_data);

    // Step 4: Update section header for .text .data with new address
    text_section->sh_addr = new_text_base_addr;
    data_section->sh_addr = new_data_base_addr;

    DEBUG1 printf(".sdata section relocated to new address: 0x%08x\n", data_section->sh_addr);
    DEBUG1 printf("function1: %x, function2: %x, function3: %x\n", func_array[0], func_array[1], func_array[2]);

    return 0;  // Success
}



int main() {
    // Step 1: Open the input ELF file from the current directory
    FILE *input_file = fopen("combined_dummy.o", "rb");
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

    // Step 5: Relocate the loaded elf file
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





