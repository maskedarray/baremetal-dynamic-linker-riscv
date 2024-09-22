

dummy:
	gcc -c dummy.o dummy.c
	gcc -o input.elf dummy.o -nostartfiles

main:
	gcc -o main.o main.c

readsections:
	readelf -S input.elf
	readelf -S output.elf

generateasm:
	objdump -d input.elf
	objdump -d output.elf