ENTRY(alignstack)
SECTIONS
{
	.text :
	{
    	*(.text.alignstack)
		*(.text.handleKatz)
	}
}
