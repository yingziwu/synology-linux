#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#if defined(MY_DEF_HERE)
/*
 * Copyright (C) 2016 Marvell
 *
 * Antoine Tenart <antoine.tenart@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <crypto/aes.h>
#include <linux/dmapool.h>

#include "safexcel.h"

enum safexcel_cipher_direction {
	SAFEXCEL_ENCRYPT,
	SAFEXCEL_DECRYPT,
};

struct safexcel_cipher_ctx {
	struct safexcel_context base;
	struct safexcel_crypto_priv *priv;

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	enum safexcel_cipher_direction direction;
#endif /* MY_DEF_HERE */
	u32 mode;

	__le32 key[8];
	unsigned int key_len;
};

#if defined(MY_DEF_HERE)
struct safexcel_cipher_reqctx {
	enum safexcel_cipher_direction direction;
};

#endif /* MY_DEF_HERE */
/* Build cipher token */
static void safexcel_cipher_token(struct safexcel_cipher_ctx *ctx,
				  struct crypto_async_request *async,
				  struct safexcel_command_desc *cdesc,
				  u32 length)
{
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct safexcel_token *token;
	unsigned offset = 0;

	if (ctx->mode == CONTEXT_CONTROL_CRYPTO_MODE_CBC) {
		offset = AES_BLOCK_SIZE / sizeof(u32);
		memcpy(cdesc->control_data.token, req->info, AES_BLOCK_SIZE);

		cdesc->control_data.options |= EIP197_OPTION_4_TOKEN_IV_CMD;
	}

	token = (struct safexcel_token *)(cdesc->control_data.token + offset);

	token[0].opcode = EIP197_TOKEN_OPCODE_DIRECTION;
	token[0].packet_length = length;
	token[0].stat = EIP197_TOKEN_STAT_LAST_PACKET;
	token[0].instructions = EIP197_TOKEN_INS_LAST |
				EIP197_TOKEN_INS_TYPE_CRYTO |
				EIP197_TOKEN_INS_TYPE_OUTPUT;
}

static int safexcel_aes_setkey(struct crypto_ablkcipher *ctfm, const u8 *key,
			       unsigned int len)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_aes_ctx aes;
	int ret, i;

	ret = crypto_aes_expand_key(&aes, key, len);
	if (ret) {
		crypto_ablkcipher_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return ret;
	}

	for (i = 0; i < len / sizeof(u32); i++) {
		if (ctx->key[i] != cpu_to_le32(aes.key_enc[i])) {
			ctx->base.needs_inv = true;
			break;
		}
	}

	for (i = 0; i < len / sizeof(u32); i++)
		ctx->key[i] = cpu_to_le32(aes.key_enc[i]);

	ctx->key_len = len;

	return 0;
}

/* Build cipher context control data */
static int safexcel_context_control(struct safexcel_cipher_ctx *ctx,
#if defined(MY_DEF_HERE)
				    struct crypto_async_request *async,
#endif /* MY_DEF_HERE */
				    struct safexcel_command_desc *cdesc)
{
	struct safexcel_crypto_priv *priv = ctx->priv;
#if defined(MY_DEF_HERE)
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct safexcel_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
#endif /* MY_DEF_HERE */
	int ctrl_size;

#if defined(MY_DEF_HERE)
	if (rctx->direction == SAFEXCEL_ENCRYPT)
#else /* MY_DEF_HERE */
	if (ctx->direction == SAFEXCEL_ENCRYPT)
#endif /* MY_DEF_HERE */
		cdesc->control_data.control0 |= CONTEXT_CONTROL_TYPE_CRYPTO_OUT;
	else
		cdesc->control_data.control0 |= CONTEXT_CONTROL_TYPE_CRYPTO_IN;

	cdesc->control_data.control0 |= CONTEXT_CONTROL_KEY_EN;
	cdesc->control_data.control1 |= ctx->mode;

	switch (ctx->key_len) {
	case AES_KEYSIZE_128:
		cdesc->control_data.control0 |= CONTEXT_CONTROL_CRYPTO_ALG_AES128;
		ctrl_size = 4;
		break;
	case AES_KEYSIZE_192:
		cdesc->control_data.control0 |= CONTEXT_CONTROL_CRYPTO_ALG_AES192;
		ctrl_size = 6;
		break;
	case AES_KEYSIZE_256:
		cdesc->control_data.control0 |= CONTEXT_CONTROL_CRYPTO_ALG_AES256;
		ctrl_size = 8;
		break;
	default:
		dev_err(priv->dev, "aes keysize not supported: %u\n",
			ctx->key_len);
		return -EINVAL;
	}
	cdesc->control_data.control0 |= CONTEXT_CONTROL_SIZE(ctrl_size);

	return 0;
}

/* Handle a cipher result descriptor */
static int safexcel_handle_result(struct safexcel_crypto_priv *priv, int ring,
				  struct crypto_async_request *async,
				  bool *should_complete, int *ret)
{
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct safexcel_result_desc *rdesc;
	int ndesc = 0;

	*ret = 0;

	spin_lock_bh(&priv->ring[ring].egress_lock);
	do {
		rdesc = safexcel_ring_next_rptr(priv, &priv->ring[ring].rdr);
		if (IS_ERR(rdesc)) {
			dev_err(priv->dev,
				"cipher: result: could not retrieve the result descriptor\n");
			*ret = PTR_ERR(rdesc);
			break;
		}

		if (rdesc->result_data.error_code) {
			dev_err(priv->dev,
				"cipher: result: result descriptor error (%d)\n",
				rdesc->result_data.error_code);
			*ret = -EIO;
		}

		ndesc++;
	} while (!rdesc->last_seg);

	safexcel_complete(priv, ring);
	spin_unlock_bh(&priv->ring[ring].egress_lock);

	if (req->src == req->dst) {
		dma_unmap_sg(priv->dev, req->src,
			     sg_nents_for_len(req->src, req->nbytes),
			     DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_sg(priv->dev, req->src,
			     sg_nents_for_len(req->src, req->nbytes),
			     DMA_TO_DEVICE);
		dma_unmap_sg(priv->dev, req->dst,
			     sg_nents_for_len(req->dst, req->nbytes),
			     DMA_FROM_DEVICE);
	}

	*should_complete = true;

	return ndesc;
}

/* Send cipher command to the engine */
static int safexcel_aes_send(struct crypto_async_request *async,
			     int ring, struct safexcel_request *request,
			     int *commands, int *results)
{
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	struct safexcel_command_desc *cdesc;
	struct safexcel_result_desc *rdesc;
	struct scatterlist *sg;
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	phys_addr_t ctxr_phys;
#endif /* MY_DEF_HERE */
	int nr_src, nr_dst, n_cdesc = 0, n_rdesc = 0, queued = req->nbytes;
	int i, ret = 0;

	if (req->src == req->dst) {
		nr_src = sg_nents_for_len(req->src, req->nbytes);
		nr_dst = nr_src;

		if (dma_map_sg(priv->dev, req->src, nr_src, DMA_BIDIRECTIONAL) <= 0)
			return -EINVAL;
	} else {
		nr_src = sg_nents_for_len(req->src, req->nbytes);
		nr_dst = sg_nents_for_len(req->dst, req->nbytes);

		if (dma_map_sg(priv->dev, req->src, nr_src, DMA_TO_DEVICE) <= 0)
			return -EINVAL;

		if (dma_map_sg(priv->dev, req->dst, nr_dst, DMA_FROM_DEVICE) <= 0) {
			dma_unmap_sg(priv->dev, req->src, nr_src,
				     DMA_TO_DEVICE);
			return -EINVAL;
		}
	}

#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
	ctxr_phys = dma_to_phys(priv->dev, ctx->base.ctxr_dma);

#endif /* MY_DEF_HERE */
	memcpy(ctx->base.ctxr->data, ctx->key, ctx->key_len);

	spin_lock_bh(&priv->ring[ring].egress_lock);

	/* command descriptors */
	for_each_sg(req->src, sg, nr_src, i) {
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
		phys_addr_t sg_phys = dma_to_phys(priv->dev, sg_dma_address(sg));
#endif /* MY_DEF_HERE */
		int len = sg_dma_len(sg);

		/* Do not overflow the request */
		if (queued - len < 0)
			len = queued;

		cdesc = safexcel_add_cdesc(priv, ring, !n_cdesc, !(queued - len),
#if defined(MY_DEF_HERE)
					   sg_dma_address(sg), len, req->nbytes,
					   ctx->base.ctxr_dma);

#else /* MY_DEF_HERE */
					   sg_phys, len, req->nbytes, ctxr_phys);
#endif /* MY_DEF_HERE */
		if (IS_ERR(cdesc)) {
			/* No space left in the command descriptor ring */
			ret = PTR_ERR(cdesc);
			goto cdesc_rollback;
		}
		n_cdesc++;

		if (n_cdesc == 1) {
#if defined(MY_DEF_HERE)
			safexcel_context_control(ctx, async, cdesc);
#else /* MY_DEF_HERE */
			safexcel_context_control(ctx, cdesc);
#endif /* MY_DEF_HERE */
			safexcel_cipher_token(ctx, async, cdesc, req->nbytes);
		}

		queued -= len;
		if (!queued)
			break;
	}

	/* result descriptors */
	for_each_sg(req->dst, sg, nr_dst, i) {
		bool first = !i, last = (i == nr_dst - 1);
#if defined(MY_DEF_HERE)
//do nothing
#else /* MY_DEF_HERE */
		phys_addr_t sg_phys = dma_to_phys(priv->dev, sg_dma_address(sg));
#endif /* MY_DEF_HERE */
		u32 len = sg_dma_len(sg);

#if defined(MY_DEF_HERE)
		rdesc = safexcel_add_rdesc(priv, ring, first, last,
					   sg_dma_address(sg), len);
#else /* MY_DEF_HERE */
		rdesc = safexcel_add_rdesc(priv, ring, first, last, sg_phys, len);
#endif /* MY_DEF_HERE */
		if (IS_ERR(rdesc)) {
			/* No space left in the result descriptor ring */
			ret = PTR_ERR(rdesc);
			goto rdesc_rollback;
		}
		n_rdesc++;
	}

	ctx->base.handle_result = safexcel_handle_result;
	request->req = &req->base;
	list_add_tail(&request->list, &priv->ring[ring].list);

	spin_unlock_bh(&priv->ring[ring].egress_lock);

	*commands = n_cdesc;
	*results = n_rdesc;
	return 0;

rdesc_rollback:
	for (i = 0; i < n_rdesc; i++)
		safexcel_ring_rollback_wptr(priv, &priv->ring[ring].rdr);
cdesc_rollback:
	for (i = 0; i < n_cdesc; i++)
		safexcel_ring_rollback_wptr(priv, &priv->ring[ring].cdr);

	spin_unlock_bh(&priv->ring[ring].egress_lock);

	if (req->src == req->dst) {
		dma_unmap_sg(priv->dev, req->src, nr_src, DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_sg(priv->dev, req->src, nr_src, DMA_TO_DEVICE);
		dma_unmap_sg(priv->dev, req->dst, nr_dst, DMA_FROM_DEVICE);
	}

	return ret;
}

/* Handle a cipher invalidation descriptor */
static int safexcel_handle_inv_result(struct safexcel_crypto_priv *priv,
				      int ring,
				      struct crypto_async_request *async,
				      bool *should_complete, int *ret)
{
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct safexcel_result_desc *rdesc;
	int ndesc = 0, enq_ret;

	*ret = 0;

	spin_lock_bh(&priv->ring[ring].egress_lock);
	do {
		rdesc = safexcel_ring_next_rptr(priv, &priv->ring[ring].rdr);
		if (IS_ERR(rdesc)) {
			dev_err(priv->dev,
				"cipher: invalidate: could not retrieve the result descriptor\n");
			*ret = PTR_ERR(rdesc);
			break;
		}

		if (rdesc->result_data.error_code) {
			dev_err(priv->dev, "cipher: invalidate: result descriptor error (%d)\n",
				rdesc->result_data.error_code);
			*ret = -EIO;
		}

		ndesc++;
	} while (!rdesc->last_seg);

	safexcel_complete(priv, ring);
	spin_unlock_bh(&priv->ring[ring].egress_lock);

	if (ctx->base.exit_inv) {
		dma_pool_free(priv->context_pool, ctx->base.ctxr,
			      ctx->base.ctxr_dma);

		*should_complete = true;

		return ndesc;
	}

	ctx->base.needs_inv = false;
	ctx->base.ring = safexcel_select_ring(priv);
	ctx->base.send = safexcel_aes_send;

	spin_lock_bh(&priv->ring[ctx->base.ring].queue_lock);
#if defined(MY_DEF_HERE)
	enq_ret = ablkcipher_enqueue_request(&priv->ring[ctx->base.ring].queue, req);
#else /* MY_DEF_HERE */
	enq_ret = crypto_enqueue_request(&priv->ring[ctx->base.ring].queue, async);
#endif /* MY_DEF_HERE */
	spin_unlock_bh(&priv->ring[ctx->base.ring].queue_lock);

	if (enq_ret != -EINPROGRESS)
		*ret = enq_ret;

#if defined(MY_DEF_HERE)
	queue_work(priv->ring[ctx->base.ring].workqueue,
		   &priv->ring[ctx->base.ring].work_data.work);
#else /* MY_DEF_HERE */
	if (!priv->ring[ctx->base.ring].need_dequeue)
		safexcel_dequeue(priv, ctx->base.ring);
#endif /* MY_DEF_HERE */

	*should_complete = false;

	return ndesc;
}

/* Send cipher invalidation command to the engine */
static int safexcel_cipher_send_inv(struct crypto_async_request *async,
				    int ring, struct safexcel_request *request,
				    int *commands, int *results)
{
	struct ablkcipher_request *req = ablkcipher_request_cast(async);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

	ctx->base.handle_result = safexcel_handle_inv_result;

	ret = safexcel_invalidate_cache(async, &ctx->base, priv,
					ctx->base.ctxr_dma, ring, request);
	if (unlikely(ret))
		return ret;

	*commands = 1;
	*results = 1;

	return 0;
}

/* Upon context exit, send invalidation command */
static int safexcel_cipher_exit_inv(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	struct ablkcipher_request req;
	struct safexcel_inv_result result = { 0 };
	int ret;

	memset(&req, 0, sizeof(struct ablkcipher_request));

	/* create invalidation request */
	init_completion(&result.completion);
	ablkcipher_request_set_callback(&req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					safexcel_inv_complete, &result);

	ablkcipher_request_set_tfm(&req, __crypto_ablkcipher_cast(tfm));
	ctx = crypto_tfm_ctx(req.base.tfm);
	ctx->base.exit_inv = true;
	ctx->base.send = safexcel_cipher_send_inv;

	spin_lock_bh(&priv->ring[ctx->base.ring].queue_lock);
#if defined(MY_DEF_HERE)
	ret = ablkcipher_enqueue_request(&priv->ring[ctx->base.ring].queue, &req);
#else /* MY_DEF_HERE */
	ret = crypto_enqueue_request(&priv->ring[ctx->base.ring].queue, &req.base);
#endif /* MY_DEF_HERE */
	spin_unlock_bh(&priv->ring[ctx->base.ring].queue_lock);

#if defined(MY_DEF_HERE)
	queue_work(priv->ring[ctx->base.ring].workqueue,
		   &priv->ring[ctx->base.ring].work_data.work);
#else /* MY_DEF_HERE */
	if (!priv->ring[ctx->base.ring].need_dequeue)
		safexcel_dequeue(priv, ctx->base.ring);
#endif /* MY_DEF_HERE */

	wait_for_completion_interruptible(&result.completion);

	if (result.error) {
		dev_warn(priv->dev,
			"cipher: sync: invalidate: completion error %d\n",
			 result.error);
		return result.error;
	}

	return ret;
}

#if defined(MY_DEF_HERE)
/* Encrypt/Decrypt operation - Insert request to Crypto API queue */
#else /* MY_DEF_HERE */
/* Encrypt/Decrypt operation - Insert request to Crypro API queue */
#endif /* MY_DEF_HERE */
static int safexcel_aes(struct ablkcipher_request *req,
			enum safexcel_cipher_direction dir, u32 mode)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
#if defined(MY_DEF_HERE)
	struct safexcel_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
#endif /* MY_DEF_HERE */
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

#if defined(MY_DEF_HERE)
	rctx->direction = dir;
#else /* MY_DEF_HERE */
	ctx->direction = dir;
#endif /* MY_DEF_HERE */
	ctx->mode = mode;

#if defined(MY_DEF_HERE)
	/*
	 * Check if the context exists, if yes:
	 *	- EIP197: check if it needs to be invalidated
	 *	- EIP97: Nothing to be done
	 * If context not exists, allocate it (for both EIP97 & EIP197)
	 * and set the send routine for the new allocated context.
	 * If it's EIP97 with existing context, the send routine is already set.
	 */
#endif /* MY_DEF_HERE */
	if (ctx->base.ctxr) {
#if defined(MY_DEF_HERE)
		if (priv->eip_type == EIP197 && ctx->base.needs_inv)
#else /* MY_DEF_HERE */
		if (ctx->base.needs_inv)
#endif /* MY_DEF_HERE */
			ctx->base.send = safexcel_cipher_send_inv;
	} else {
		ctx->base.ring = safexcel_select_ring(priv);
		ctx->base.send = safexcel_aes_send;
		ctx->base.ctxr = dma_pool_zalloc(priv->context_pool,
						 EIP197_GFP_FLAGS(req->base),
						 &ctx->base.ctxr_dma);
		if (!ctx->base.ctxr)
			return -ENOMEM;
	}

	spin_lock_bh(&priv->ring[ctx->base.ring].queue_lock);
#if defined(MY_DEF_HERE)
	ret = ablkcipher_enqueue_request(&priv->ring[ctx->base.ring].queue, req);
#else /* MY_DEF_HERE */
	ret = crypto_enqueue_request(&priv->ring[ctx->base.ring].queue, &req->base);
#endif /* MY_DEF_HERE */
	spin_unlock_bh(&priv->ring[ctx->base.ring].queue_lock);

#if defined(MY_DEF_HERE)
	queue_work(priv->ring[ctx->base.ring].workqueue,
		   &priv->ring[ctx->base.ring].work_data.work);
#else /* MY_DEF_HERE */
	if (!priv->ring[ctx->base.ring].need_dequeue)
		safexcel_dequeue(priv, ctx->base.ring);
#endif /* MY_DEF_HERE */

	return ret;
}

static int safexcel_ecb_aes_encrypt(struct ablkcipher_request *req)
{
	return safexcel_aes(req, SAFEXCEL_ENCRYPT,
			    CONTEXT_CONTROL_CRYPTO_MODE_ECB);
}

static int safexcel_ecb_aes_decrypt(struct ablkcipher_request *req)
{
	return safexcel_aes(req, SAFEXCEL_DECRYPT,
			    CONTEXT_CONTROL_CRYPTO_MODE_ECB);
}

static int safexcel_ablkcipher_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_alg_template *tmpl =
		container_of(tfm->__crt_alg, struct safexcel_alg_template, alg.crypto);

	ctx->priv = tmpl->priv;

#if defined(MY_DEF_HERE)
	tfm->crt_ablkcipher.reqsize = sizeof(struct safexcel_cipher_reqctx);

#endif /* MY_DEF_HERE */
	return 0;
}

static void safexcel_ablkcipher_cra_exit(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

	/* context not allocated, skip invalidation */
	if (!ctx->base.ctxr)
		return;

#if defined(MY_DEF_HERE)
	/*
	 * EIP197 has internal cache which needs to be invalidated
	 * when the context is closed.
	 * dma_pool_free will be called in the invalidation result
	 * handler (different context).
	 * EIP97 doesn't have internal cache, so no need to invalidate
	 * it and we can just release the dma pool.
	 */
	if (priv->eip_type == EIP197) {
		ret = safexcel_cipher_exit_inv(tfm);
		if (ret != -EINPROGRESS)
			dev_warn(priv->dev, "cipher: invalidation error %d\n",
				 ret);
	} else {
		dma_pool_free(priv->context_pool, ctx->base.ctxr,
			      ctx->base.ctxr_dma);
	}
#else /* MY_DEF_HERE */
	ret = safexcel_cipher_exit_inv(tfm);
	if (ret != -EINPROGRESS)
		dev_warn(priv->dev, "cipher: invalidation error %d\n", ret);
#endif /* MY_DEF_HERE */
}

struct safexcel_alg_template safexcel_alg_ecb_aes = {
	.type = SAFEXCEL_ALG_TYPE_CIPHER,
	.alg.crypto = {
		.cra_name = "ecb(aes)",
		.cra_driver_name = "safexcel-ecb-aes",
		.cra_priority = 300,
		.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC |
			     CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
		.cra_alignmask = 0,
		.cra_type = &crypto_ablkcipher_type,
		.cra_module = THIS_MODULE,
		.cra_init = safexcel_ablkcipher_cra_init,
		.cra_exit = safexcel_ablkcipher_cra_exit,
		.cra_u = {
			.ablkcipher = {
				.min_keysize = AES_MIN_KEY_SIZE,
				.max_keysize = AES_MAX_KEY_SIZE,
				.setkey = safexcel_aes_setkey,
				.encrypt = safexcel_ecb_aes_encrypt,
				.decrypt = safexcel_ecb_aes_decrypt,
			},
		},
	},
};

static int safexcel_cbc_aes_encrypt(struct ablkcipher_request *req)
{
	return safexcel_aes(req, SAFEXCEL_ENCRYPT,
			    CONTEXT_CONTROL_CRYPTO_MODE_CBC);
}

static int safexcel_cbc_aes_decrypt(struct ablkcipher_request *req)
{
	return safexcel_aes(req, SAFEXCEL_DECRYPT,
			    CONTEXT_CONTROL_CRYPTO_MODE_CBC);
}

struct safexcel_alg_template safexcel_alg_cbc_aes = {
	.type = SAFEXCEL_ALG_TYPE_CIPHER,
	.alg.crypto = {
		.cra_name = "cbc(aes)",
		.cra_driver_name = "safexcel-cbc-aes",
		.cra_priority = 300,
		.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC |
			     CRYPTO_ALG_KERN_DRIVER_ONLY,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
		.cra_alignmask = 0,
		.cra_type = &crypto_ablkcipher_type,
		.cra_module = THIS_MODULE,
		.cra_init = safexcel_ablkcipher_cra_init,
		.cra_exit = safexcel_ablkcipher_cra_exit,
		.cra_u = {
			.ablkcipher = {
				.min_keysize = AES_MIN_KEY_SIZE,
				.max_keysize = AES_MAX_KEY_SIZE,
				.ivsize = AES_BLOCK_SIZE,
				.setkey = safexcel_aes_setkey,
				.encrypt = safexcel_cbc_aes_encrypt,
				.decrypt = safexcel_cbc_aes_decrypt,
			},
		},
	},
};
#endif /* MY_DEF_HERE */
