// SPDX-License-Identifier: GPL-2.0-only
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>

#include <asm/e820/api.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/unaccepted_memory.h>
#include <asm/sev.h>

/* Protects unaccepted memory bitmap and nr_unaccepted */
static DEFINE_SPINLOCK(unaccepted_memory_lock);
static unsigned long nr_unaccepted;

void accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long *unaccepted_memory;
	unsigned long flags;
	unsigned long range_start, range_end;

	if (!boot_params.unaccepted_memory)
		return;

	unaccepted_memory = __va(boot_params.unaccepted_memory);
	range_start = start / PMD_SIZE;

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	for_each_set_bitrange_from(range_start, range_end, unaccepted_memory,
				   DIV_ROUND_UP(end, PMD_SIZE)) {
		unsigned long len = range_end - range_start;

		/* Platform-specific memory-acceptance call goes here */
		if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
			snp_accept_memory(range_start * PMD_SIZE, range_end * PMD_SIZE);
		else
			panic("Cannot accept memory");
		bitmap_clear(unaccepted_memory, range_start, len);
		count_vm_events(ACCEPT_MEMORY, len * PMD_SIZE / PAGE_SIZE);

		/* In early boot nr_unaccepted is not yet initialized */
		if (nr_unaccepted) {
			WARN_ON(nr_unaccepted < len);
			nr_unaccepted -= len;
		}
	}
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);
}

bool memory_is_unaccepted(phys_addr_t start, phys_addr_t end)
{
	unsigned long *unaccepted_memory = __va(boot_params.unaccepted_memory);
	unsigned long flags;
	bool ret = false;

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	while (start < end) {
		if (test_bit(start / PMD_SIZE, unaccepted_memory)) {
			ret = true;
			break;
		}

		start += PMD_SIZE;
	}
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);

	return ret;
}

void unaccepted_meminfo(struct seq_file *m)
{
	seq_printf(m, "UnacceptedMem:  %8lu kB\n",
		   (READ_ONCE(nr_unaccepted) * PMD_SIZE) >> 10);
}

static int __init unaccepted_meminfo_init(void)
{
	unsigned long *unaccepted_memory;
	unsigned long flags, bitmap_size;

	if (!boot_params.unaccepted_memory)
		return 0;

	bitmap_size = e820__end_of_ram_pfn() * PAGE_SIZE / PMD_SIZE;
	unaccepted_memory = __va(boot_params.unaccepted_memory);

	spin_lock_irqsave(&unaccepted_memory_lock, flags);
	nr_unaccepted = bitmap_weight(unaccepted_memory, bitmap_size);
	spin_unlock_irqrestore(&unaccepted_memory_lock, flags);

	return 0;
}
fs_initcall(unaccepted_meminfo_init);
