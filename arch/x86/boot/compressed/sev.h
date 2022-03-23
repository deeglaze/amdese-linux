/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_COMPRESSED_SEV_H
#define BOOT_COMPRESSED_SEV_H

#include <linux/types.h>

#ifdef CONFIG_AMD_MEM_ENCRYPT
struct boot_params;

void sev_enable(struct boot_params *bp);
void sev_es_shutdown_ghcb(void);
extern bool sev_es_check_ghcb_fault(unsigned long address);
void snp_set_page_private(unsigned long paddr);
void snp_set_page_shared(unsigned long paddr);
void sev_prep_identity_maps(unsigned long top_level_pgt);
bool sev_snp_enabled(void);
void snp_set_range_private(phys_addr_t start, phys_addr_t end);
#else
static inline void sev_enable(struct boot_params *bp) { }
static inline void sev_es_shutdown_ghcb(void) { }
static inline bool sev_es_check_ghcb_fault(unsigned long address)
{
	return false;
}
static inline void snp_set_page_private(unsigned long paddr) { }
static inline void snp_set_page_shared(unsigned long paddr) { }
static inline void sev_prep_identity_maps(unsigned long top_level_pgt) { }
static inline bool sev_snp_enabled(void) { return false; }
static inline void snp_set_range_private(phys_addr_t start, phys_addr_t end) { }
#endif

unsigned long sev_verify_cbit(unsigned long cr3);

#endif /* BOOT_COMPRESSED_SEV_H */
