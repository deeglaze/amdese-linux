// SPDX-License-Identifier: GPL-2.0-only
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/spinlock.h>

#include <asm/io.h>
#include <asm/setup.h>
#include <asm/unaccepted_memory.h>

/* Protects unaccepted memory bitmap */
static DEFINE_SPINLOCK(unaccepted_memory_lock);

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
		panic("Cannot accept memory");
		bitmap_clear(unaccepted_memory, range_start, len);
		count_vm_events(ACCEPT_MEMORY, len * PMD_SIZE / PAGE_SIZE);
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
