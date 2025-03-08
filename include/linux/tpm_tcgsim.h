/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 James.Bottomley@HansenPartnership.com
 * Copyright (C) 2025 Red Hat, Inc. All Rights Reserved.
 *
 * Generic interface usable by TPM drivers interacting with devices
 * implemented through the TCG Simulator.
 */
#ifndef _TPM_TCGSIM_H_
#define _TPM_TCGSIM_H_

#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

/*
 * The current TCG Simulator TPM commands we support.  The complete list is
 * in the TcpTpmProtocol header:
 *
 * https://github.com/TrustedComputingGroup/TPM/blob/main/TPMCmd/Simulator/include/TpmTcpProtocol.h
 */

#define TPM_SEND_COMMAND		8
#define TPM_SIGNAL_CANCEL_ON		9
#define TPM_SIGNAL_CANCEL_OFF		10
/*
 * Any platform specific commands should be placed here and should start
 * at 0x8000 to avoid clashes with the TCG Simulator protocol.  They should
 * follow the same self describing buffer format below.
 */

#define TPM_TCGSIM_MAX_BUFFER		4096 /* max req/resp buffer size */

/**
 * struct tpm_req - generic request header for single word command
 *
 * @cmd:	The command to send
 */
struct tpm_req {
	u32 cmd;
} __packed;

/**
 * struct tpm_resp - generic response header
 *
 * @size:	The response size (zero if nothing follows)
 *
 * Note: most TCG Simulator commands simply return zero here with no indication
 * of success or failure.
 */
struct tpm_resp {
	u32 size;
} __packed;

/**
 * struct tpm_send_cmd_req - Structure for a TPM_SEND_COMMAND request
 *
 * @hdr:	The request header whit the command (must be TPM_SEND_COMMAND)
 * @locality:	The locality
 * @inbuf_size:	The size of the input buffer following
 * @inbuf:	A buffer of size inbuf_size
 *
 * Note that TCG Simulator expects @inbuf_size to be equal to the size of the
 * specific TPM command, otherwise an TPM_RC_COMMAND_SIZE error is
 * returned.
 */
struct tpm_send_cmd_req {
	struct tpm_req hdr;
	u8 locality;
	u32 inbuf_size;
	u8 inbuf[];
} __packed;

/**
 * struct tpm_send_cmd_req - Structure for a TPM_SEND_COMMAND response
 *
 * @hdr:	The response header whit the following size
 * @outbuf:	A buffer of size hdr.size
 */
struct tpm_send_cmd_resp {
	struct tpm_resp hdr;
	u8 outbuf[];
} __packed;

/**
 * tpm_tcgsim_fill_send_cmd() - fill a struct tpm_send_cmd_req to be sent to the
 * TCG Simulator.
 * @req: The struct tpm_send_cmd_req to fill
 * @locality: The locality
 * @buf: The buffer from where to copy the payload of the command
 * @len: The size of the buffer
 *
 * Return: 0 on success, negative error code on failure.
 */
static inline int
tpm_tcgsim_fill_send_cmd(struct tpm_send_cmd_req *req, u8 locality,
			 const u8 *buf, size_t len)
{
	if (len > TPM_TCGSIM_MAX_BUFFER - sizeof(*req))
		return -EINVAL;

	req->hdr.cmd = TPM_SEND_COMMAND;
	req->locality = locality;
	req->inbuf_size = len;

	memcpy(req->inbuf, buf, len);

	return 0;
}

/**
 * tpm_tcgsim_parse_send_cmd() - Parse a struct tpm_send_cmd_resp received from
 * the TCG Simulator
 * @resp: The struct tpm_send_cmd_resp to parse
 * @buf: The buffer where to copy the response
 * @len: The size of the buffer
 *
 * Return: buffer size filled with the response on success, negative error
 * code on failure.
 */
static inline int
tpm_tcgsim_parse_send_cmd(const struct tpm_send_cmd_resp *resp, u8 *buf,
			  size_t len)
{
	if (len < resp->hdr.size)
		return -E2BIG;

	if (resp->hdr.size > TPM_TCGSIM_MAX_BUFFER - sizeof(*resp))
		return -EINVAL;  // Invalid response from the platform TPM

	memcpy(buf, resp->outbuf, resp->hdr.size);

	return resp->hdr.size;
}

#endif /* _TPM_TCGSIM_H_ */
