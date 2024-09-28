
CC = /home/a26rahma/work/alsaqr/llvm-testing/gcc-stuff/riscv-gnu-toolchain/output/bin/riscv32-unknown-elf-

all: clean main dummy

dummy:
	$(CC)gcc -march=rv32im -static -fno-common -fno-section-anchors -fno-zero-initialized-in-bss -O0 -I./dummyheader.h -c dummy.o dummy.c
	$(CC)ld --no-relax -r -T linker.ld -o combined_dummy.o dummy.o
	$(CC)objdump -D combined_dummy.o > combined_dummy.asm

main:
	gcc -O2 -o main.o main.c

readsections:
	$(CC)readelf -a dummy.o
	$(CC)readelf -S output.elf

generateasm:
	$(CC)objdump -D dummy.o > dummy.asm
	$(CC)objdump -D output.o > output.asm

clean:
	rm -rf dummy.o input.elf output.elf main.o combined_dummy.o output.asm *.bin *.asm