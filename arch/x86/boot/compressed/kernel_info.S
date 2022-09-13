/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/bootparam.h>

	.section ".rodata.kernel_info", "a"

	.global kernel_info

kernel_info:
	/* Header, Linux top (structure). */
	.ascii	"LToP"
	/* Size. */
	.long	kernel_info_var_len_data - kernel_info
	/* Size total. */
	.long	kernel_info_end - kernel_info

	/* Maximal allowed type for setup_data and setup_indirect structs. */
	.long	SETUP_TYPE_MAX

kernel_info_var_len_data:
#ifdef CONFIG_UNACCEPTED_MEMORY
accepted_memory_struct:
	/*
	 * Presence of this struct means that this kernel supports the
	 * unaccepted memory type.
	 */
	.ascii "UMem"
	.long   accepted_memory_struct_end - accepted_memory_struct
	/*
	 * Any bootloader must know how much memory must be accepted before
	 * booting the kernel, since the kernel needs enough space to get
	 * to the point of understanding the memory map for unaccepted
	 * memory. This is to be filled in by Intel.
	 */
accepted_memory_struct_end:
#endif
  /* Empty for time being... */
kernel_info_end:
