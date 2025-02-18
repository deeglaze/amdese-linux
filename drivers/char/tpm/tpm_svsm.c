// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Red Hat, Inc. All Rights Reserved.
 *
 * Driver for the vTPM defined by the AMD SVSM spec [1].
 *
 * The specification defines a protocol that a SEV-SNP guest OS can use to
 * discover and talk to a vTPM emulated by the Secure VM Service Module (SVSM)
 * in the guest context, but at a more privileged level (usually VMPL0).
 *
 * The vTPM is emulated through the TCG reference implementation, so this
 * driver leverages tpm_tcgsim.h to fill commands and parse responses.
 *
 * [1] "Secure VM Service Module for SEV-SNP Guests"
 *     Publication # 58019 Revision: 1.00
 *     https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/58019.pdf
 */

#include <asm/sev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/tpm_tcgsim.h>

#include "tpm.h"

struct tpm_svsm_priv {
	u8 buffer[TPM_TCGSIM_MAX_BUFFER];
	u8 locality;
};

static int tpm_svsm_send_recv(struct tpm_chip *chip, u8 *buf, size_t buf_len,
			      size_t to_send)
{
	struct tpm_svsm_priv *priv = dev_get_drvdata(&chip->dev);
	int ret;

	ret = tpm_tcgsim_fill_send_cmd((struct tpm_send_cmd_req *)priv->buffer,
				       priv->locality, buf, to_send);
	if (ret)
		return ret;

	ret = snp_svsm_vtpm_send_command(priv->buffer);
	if (ret)
		return ret;

	return tpm_tcgsim_parse_send_cmd((struct tpm_send_cmd_resp *)priv->buffer,
					 buf, buf_len);
}

static struct tpm_class_ops tpm_chip_ops = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.send_recv = tpm_svsm_send_recv,
};

static int __init tpm_svsm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct tpm_svsm_priv *priv;
	struct tpm_chip *chip;
	int err;

	if (!snp_svsm_vtpm_probe())
		return -ENODEV;

	priv = devm_kmalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/*
	 * FIXME: before implementing locality we need to agree what it means
	 * for the SNP SVSM vTPM
	 */
	priv->locality = 0;

	chip = tpmm_chip_alloc(dev, &tpm_chip_ops);
	if (IS_ERR(chip))
		return PTR_ERR(chip);

	dev_set_drvdata(&chip->dev, priv);

	err = tpm2_probe(chip);
	if (err)
		return err;

	err = tpm_chip_register(chip);
	if (err)
		return err;

	dev_info(dev, "SNP SVSM vTPM %s device\n",
		 (chip->flags & TPM_CHIP_FLAG_TPM2) ? "2.0" : "1.2");

	return 0;
}

static void __exit tpm_svsm_remove(struct platform_device *pdev)
{
	struct tpm_chip *chip = platform_get_drvdata(pdev);

	tpm_chip_unregister(chip);
}

/*
 * tpm_svsm_remove() lives in .exit.text. For drivers registered via
 * module_platform_driver_probe() this is ok because they cannot get unbound
 * at runtime. So mark the driver struct with __refdata to prevent modpost
 * triggering a section mismatch warning.
 */
static struct platform_driver tpm_svsm_driver __refdata = {
	.remove = __exit_p(tpm_svsm_remove),
	.driver = {
		.name = "tpm-svsm",
	},
};

module_platform_driver_probe(tpm_svsm_driver, tpm_svsm_probe);

MODULE_DESCRIPTION("SNP SVSM vTPM Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:tpm-svsm");
