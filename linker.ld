SECTIONS {
    .text : { *(.text) }
    .data : {
        *(.data)
        *(.sdata)
        *(.sdata1)
    }
    .bss : {
        *(.bss)
        *(.sbss)
        *(.sbss1)
    }
}