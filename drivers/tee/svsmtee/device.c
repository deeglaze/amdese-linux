/* SPDX-License-Identifier: MIT */

#include <linux/align.h>
#include <linux/cleanup.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/tee_core.h>
#include <linux/tee_drv.h>
#include <linux/tpm.h>
#include <linux/types.h>
#include <uapi/linux/tee.h>
#include <vdso/page.h>

#include <asm/sev.h>

#define DRIVER_NAME "svsmtee"
#define DRIVER_AUTHOR "Coconut-SVSM authors"

#define FTPM_REQUIRED_SIZE (FTPM_MAX_COMMAND_SIZE + FTPM_MAX_RESPONSE_SIZE)
#define SVSM_TEMP_BUF_SIZE ALIGN(sizeof(struct svsm_vtpm_cmd) + FTPM_REQUIRED_SIZE, PAGE_SIZE)
#define SVSM_MIN_POOL_SIZE ALIGN(FTPM_REQUIRED_SIZE + SVSM_TEMP_BUF_SIZE, PAGE_SIZE)
#define SVSM_MIN_POOL_PAGES (SVSM_MIN_POOL_SIZE >> PAGE_SHIFT)
#define SVSM_POOL_ORDER 3
#define SVSM_POOL_PAGES (1 << SVSM_POOL_ORDER)

static DEFINE_MUTEX(session_list_mutex);

/**
 * struct svsmtee - main service struct
 * @teedev:		client device
 * @pool:		the tee shared memory pool
 * @comm_buffer:	reserved memory for the shared memory pool
 */
struct svsmtee {
	struct tee_device *teedev;
	struct tee_shm_pool *pool;
	unsigned long comm_buffer;
};

struct svsmtee_driver_data {
	struct svsmtee *svsmtee;
};

struct svsmtee_context_data {
	u64 vtpm_supported_commands;
	u64 vtpm_supported_features;

	struct list_head sess_list;
};

/*
 * A session is for communicating with a specific trusted application.
 * There is no session info array or bitmap since only a single session is supported.
 * There is no TA handle concept since it's implicitly fTPM.
 */
struct svsmtee_ta_session {
	struct list_head list_node;
	struct tee_shm *temp_buf;
	struct kref refcount;
};

static struct svsmtee_driver_data *drv_data;

static void svsmtee_get_version(struct tee_device *teedev,
			       struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_SVSMTEE,
		.impl_caps = 0,
		.gen_caps = TEE_GEN_CAP_PRIVILEGED,
	};
	*vers = v;
}

static struct svsmtee_ta_session *alloc_session(struct tee_context *ctx, u32 session)
{
	struct svsmtee_context_data *ctxdata = ctx->data;
	struct svsmtee_ta_session *sess __free(kfree) = NULL;

	/* Only a single session and single TA is supported */
	if (session)
		return ERR_PTR(-EINVAL);

	list_for_each_entry(sess, &ctxdata->sess_list, list_node) {
		kref_get(&sess->refcount);
		return_ptr(sess);
	}

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return ERR_PTR(-ENOMEM);

	sess->temp_buf = tee_shm_alloc_kernel_buf(ctx, SVSM_TEMP_BUF_SIZE);
	if (IS_ERR(sess->temp_buf)) {
		pr_err("%s: session temp_buf allocation failed\n", __func__);
		return (struct svsmtee_ta_session *)(sess->temp_buf);
	}

	kref_init(&sess->refcount);
	list_add(&sess->list_node, &ctxdata->sess_list);

	return_ptr(sess);
}

static int svsmtee_open(struct tee_context *ctx)
{
	struct svsm_vtpm_query_result qres;
	struct svsmtee_context_data *ctxdata __free(kfree) = NULL;;
	int ret;

	ctxdata = kzalloc(sizeof(*ctxdata), GFP_KERNEL);
	if (!ctxdata)
		return -ENOMEM;

	/* There's no other reason than vTPM to use SVSM-TEE, so fail it vTPM query fails */
	ret = snp_issue_svsm_vtpm_query(&qres);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&ctxdata->sess_list);
	ctxdata->vtpm_supported_commands = qres.supported_commands;
	ctxdata->vtpm_supported_features = qres.supported_features;

	ctx->data = no_free_ptr(ctxdata);

	return 0;
}

static void destroy_session(struct kref *ref)
{
	struct svsmtee_ta_session *sess = container_of(ref, struct svsmtee_ta_session, refcount);

	tee_shm_free(sess->temp_buf);
	list_del(&sess->list_node);
	kfree(sess);
}

static void svsmtee_release(struct tee_context *ctx)
{
	struct svsmtee_context_data *ctxdata = ctx->data;

	kfree(ctxdata);
	ctx->data = NULL;
}

/* From drivers/char/tpm/tpm_ftpm_tee.c */
static const uuid_t ftpm_ta_uuid =
	UUID_INIT(0xBC50D971, 0xD4C9, 0x42C4,
		  0x82, 0xCB, 0x34, 0x3F, 0xB7, 0xF3, 0x78, 0x96);

static int svsmtee_open_session(struct tee_context *ctx,
			 struct tee_ioctl_open_session_arg *arg,
			 struct tee_param *param)
{
	struct svsmtee_context_data *ctxdata = ctx->data;
	struct svsmtee_ta_session *sess;
	uuid_t uuid;

	if (!ctxdata)
		return -EINVAL;

	import_uuid(&uuid, &arg->uuid[0]);
	/* No other trusted applications in SVSM are currently supported. */
	if (!uuid_equal(&uuid, &ftpm_ta_uuid))
		return -EINVAL;

	{
		guard(mutex)(&session_list_mutex);
		sess = alloc_session(ctx, arg->session);
	}
	if (IS_ERR(sess))
		return PTR_ERR(sess);

	return 0;
}

static int svsmtee_close_session(struct tee_context *ctx, u32 session)
{
	struct svsmtee_context_data *ctxdata = ctx->data;
	struct svsmtee_ta_session *sess = NULL;

	if (!ctxdata)
		return -EINVAL;

	/* Only a single session is supported */
	if (session)
		return -EINVAL;

	{
		guard(mutex)(&session_list_mutex);
		list_for_each_entry(sess, &ctxdata->sess_list, list_node)
			break;
	}

	if (!sess)
		return -EINVAL;

	kref_put_mutex(&sess->refcount, destroy_session, &session_list_mutex);

	return 0;
}

static int svsmtee_optee_ta_submit_command(struct tee_context *ctx,
					   struct tee_ioctl_invoke_arg *arg,
					   struct tee_param *param,
					   struct svsmtee_ta_session *sess)
{
	struct svsm_vtpm_cmd *cmd;
	struct svsmtee_context_data *ctxdata = ctx->data;
	int ret = 0;

	if (!(ctxdata->vtpm_supported_commands & BIT_ULL(SVSM_TPM_SEND_COMMAND)))
		return -ENOTTY;

	if (arg->num_params < 2 || !sess)
		return -EINVAL;

	cmd = (struct svsm_vtpm_cmd *)tee_shm_get_va(sess->temp_buf, 0);
	cmd->platform_cmd = SVSM_TPM_SEND_COMMAND;
	cmd->u.send_command_req.locality = 0;
	cmd->u.send_command_req.cmd_size = param[0].u.memref.size;
	memcpy(cmd->u.send_command_req.cmd,
		(u8*)param[0].u.memref.shm->kaddr + param[0].u.memref.shm_offs,
		param[0].u.memref.size);

	ret = snp_issue_svsm_vtpm_cmd(cmd);
	if (ret)
		return ret;

	if (cmd->u.send_command_rsp.rsp_size > param[1].u.memref.size) {
		pr_err("%s: vTPM response size (0x%x) larger than fTPM supports (0x%lx)\n",
			__func__, cmd->u.send_command_rsp.rsp_size,
			param[1].u.memref.size);
		return -ENOMEM;
	}
	memcpy((u8*)param[1].u.memref.shm->kaddr + param[1].u.memref.shm_offs,
		cmd->u.send_command_rsp.rsp,
		cmd->u.send_command_rsp.rsp_size);
	return ret;
}

static struct svsmtee_ta_session *find_session(struct svsmtee_context_data *ctxdata, u32 session)
{
	struct svsmtee_ta_session *sess;

	if (session)
		return ERR_PTR(-EINVAL);

	list_for_each_entry(sess, &ctxdata->sess_list, list_node)
		break;

	if (!sess)
		return ERR_PTR(-EINVAL);

	return sess;
}

static int svsmtee_invoke_func(struct tee_context *ctx,
			       struct tee_ioctl_invoke_arg *arg,
			       struct tee_param *param)
{
	struct svsmtee_context_data *ctxdata = ctx->data;
	struct svsmtee_ta_session *sess;

	{
		guard(mutex)(&session_list_mutex);
		sess = find_session(ctxdata, arg->session);
	}
	if (IS_ERR(sess))
		return PTR_ERR(sess);

	switch (arg->func) {
	case FTPM_OPTEE_TA_SUBMIT_COMMAND:
		return svsmtee_optee_ta_submit_command(ctx, arg, param, sess);
	default:
		return -EINVAL;
	}
}

static int svsmtee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	return -EINVAL;
}

static const struct tee_driver_ops svsmtee_ops = {
	.get_version = svsmtee_get_version,
	.open = svsmtee_open,
	.release = svsmtee_release,
	.open_session = svsmtee_open_session,
	.close_session = svsmtee_close_session,
	.invoke_func = svsmtee_invoke_func,
	.cancel_req = svsmtee_cancel_req,
};

static const struct tee_desc svsmtee_desc = {
	.name = DRIVER_NAME "-clnt",  /* client */
	.ops = &svsmtee_ops,
	.owner = THIS_MODULE,
};

DEFINE_FREE(free_tee_shm_pool, struct tee_shm_pool *, if (_T) tee_shm_pool_free(_T));

static int __init svsmtee_driver_init(void)
{
	struct svsmtee_driver_data *devdata  __free(kfree) = NULL;
	struct tee_device *teedev __free(kfree) = NULL;
	struct tee_shm_pool *pool __free(free_tee_shm_pool) = NULL;
	struct svsmtee *svsmtee __free(kfree) = NULL;
	unsigned long comm_buffer;
	int ret;


	devdata = kzalloc(sizeof(*drv_data), GFP_KERNEL);
	if (!devdata)
		return -ENOMEM;

	svsmtee = kzalloc(sizeof(*svsmtee), GFP_KERNEL);
	if (!svsmtee)
		return -ENOMEM;

	BUILD_BUG_ON(SVSM_MIN_POOL_PAGES > SVSM_POOL_PAGES);
	/* Only allocate enough space for a single allocation at a time. */
	comm_buffer = __get_free_pages(GFP_KERNEL, SVSM_POOL_ORDER);
	if (!comm_buffer) {
		pr_err("svsm-tee: temporary memory allocation failed\n");
		return -ENOMEM;
	}

	/*
	 * The fTPM device allocation only needs a page, page-aligned.
	 * The SVSM invocation needs its own memory for the vTPM call protocol representation.
	 */
	pool = tee_shm_pool_alloc_res_mem(comm_buffer, __pa((void *)comm_buffer),
					SVSM_POOL_PAGES << PAGE_SHIFT, /*min_alloc_order=*/PAGE_SHIFT);
	if (IS_ERR(pool)) {
		pr_err("svsm-tee: shared pool configuration error\n");
		ret = PTR_ERR(pool);
		goto e_free_commbuf;
	}

	teedev = tee_device_alloc(&svsmtee_desc, NULL, pool, svsmtee);
	if (IS_ERR(teedev)) {
		ret = PTR_ERR(teedev);
		goto e_free_commbuf;
	}

	ret = tee_device_register(teedev);
	if (ret) {
		tee_device_unregister(svsmtee->teedev);
		goto e_free_commbuf;
	}

	svsmtee->comm_buffer = comm_buffer;
	svsmtee->pool = no_free_ptr(pool);
	svsmtee->teedev = no_free_ptr(teedev);
	devdata->svsmtee = no_free_ptr(svsmtee);
	drv_data = no_free_ptr(devdata);

	pr_info("svsm-tee driver initialization successful\n");
	return 0;

e_free_commbuf:
	free_pages(comm_buffer, SVSM_POOL_PAGES);
	return ret;
}
module_init(svsmtee_driver_init);

static void __exit svsmtee_driver_exit(void)
{
	struct svsmtee *svsmtee;

	if (!drv_data || !drv_data->svsmtee)
		return;

	svsmtee = drv_data->svsmtee;

	tee_device_unregister(svsmtee->teedev);
	tee_shm_pool_free(svsmtee->pool);
	free_pages((unsigned long)svsmtee->comm_buffer, SVSM_POOL_PAGES);
	kfree(svsmtee);
	kfree(drv_data);
	drv_data = NULL;
}
module_exit(svsmtee_driver_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION("SVSM-TEE driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("Dual MIT/GPL");
