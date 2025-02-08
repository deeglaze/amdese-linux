/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation
 */

#ifndef __TPM_FTPM_TEE_H__
#define __TPM_FTPM_TEE_H__

#include <linux/tee_drv.h>
#include <linux/tpm.h>
#include <linux/uuid.h>

/**
 * struct ftpm_tee_private - fTPM's private data
 * @chip:     struct tpm_chip instance registered with tpm framework.
 * @state:    internal state
 * @session:  fTPM TA session identifier.
 * @resp_len: cached response buffer length.
 * @resp_buf: cached response buffer.
 * @ctx:      TEE context handler.
 * @shm:      Memory pool shared with fTPM TA in TEE.
 */
struct ftpm_tee_private {
	struct tpm_chip *chip;
	u32 session;
	size_t resp_len;
	u8 resp_buf[FTPM_MAX_RESPONSE_SIZE];
	struct tee_context *ctx;
	struct tee_shm *shm;
};

#endif /* __TPM_FTPM_TEE_H__ */
