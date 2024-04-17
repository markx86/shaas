ENTRY(_start)

LOAD_ADDR = 0x400000;

PHDRS
{
	everything PT_LOAD FILEHDR PHDRS AT(LOAD_ADDR) FLAGS(0x4 | 0x1);
}

SECTIONS
{
	. = LOAD_ADDR + 0x80;

	.load :
	{
		*(.text*)
		*(.rodata*)
		*(.data.rel.ro.*)
	} :everything

	/DISCARD/ : {
		*(.bss*)
		*(.data*)
		*(.note*)
		*(.eh_frame*)
		*(.comment*)
	}
}
