#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/scatterlist.h>

#include <cryptodev.h>
#include <uio.h>

struct {
	softc_device_decl	sc_dev;
} swcr_softc;

#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)

#define SW_TYPE_CIPHER		0
#define SW_TYPE_HMAC		1
#define SW_TYPE_AUTH2		2
#define SW_TYPE_HASH		3
#define SW_TYPE_COMP		4
#define SW_TYPE_BLKCIPHER	5

#ifdef MY_ABC_HERE
struct ocf_request {
    struct ablkcipher_request *req;
    struct completion complete;
    int error;
};
#endif

struct swcr_data {
	int					sw_type;
	int					sw_alg;
	struct crypto_tfm	*sw_tfm;
	union {
		struct {
			char *sw_key;
			int  sw_klen;
			int  sw_mlen;
		} hmac;
		void *sw_comp_buf;
	} u;
	struct swcr_data	*sw_next;
};

#ifndef CRYPTO_TFM_MODE_CBC
 
#define	CRYPTO_TFM_MODE_CBC	0
#define	CRYPTO_TFM_MODE_ECB	0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
	 
	struct blkcipher_desc
	{
		struct crypto_tfm *tfm;
		void *info;
	};
	#define ecb(X)								#X
	#define cbc(X)								#X
	#define crypto_has_blkcipher(X, Y, Z)		crypto_alg_available(X, 0)
	#define crypto_blkcipher_cast(X)			X
	#define crypto_blkcipher_tfm(X)				X
	#define crypto_alloc_blkcipher(X, Y, Z)		crypto_alloc_tfm(X, mode)
	#define crypto_blkcipher_ivsize(X)			crypto_tfm_alg_ivsize(X)
	#define crypto_blkcipher_blocksize(X)		crypto_tfm_alg_blocksize(X)
	#define crypto_blkcipher_setkey(X, Y, Z)	crypto_cipher_setkey(X, Y, Z)
	#define crypto_blkcipher_encrypt_iv(W, X, Y, Z)	\
				crypto_cipher_encrypt_iv((W)->tfm, X, Y, Z, (u8 *)((W)->info))
	#define crypto_blkcipher_decrypt_iv(W, X, Y, Z)	\
				crypto_cipher_decrypt_iv((W)->tfm, X, Y, Z, (u8 *)((W)->info))

	struct hash_desc
	{
		struct crypto_tfm *tfm;
	};
	#define hmac(X)							#X
	#define crypto_has_hash(X, Y, Z)		crypto_alg_available(X, 0)
	#define crypto_hash_cast(X)				X
	#define crypto_hash_tfm(X)				X
	#define crypto_alloc_hash(X, Y, Z)		crypto_alloc_tfm(X, mode)
	#define crypto_hash_digestsize(X)		crypto_tfm_alg_digestsize(X)
	#define crypto_hash_digest(W, X, Y, Z)	\
				crypto_digest_digest((W)->tfm, X, sg_num, Z)

	#define crypto_has_cipher(X, Y, Z)		crypto_alg_available(X, 0)

	#define crypto_has_comp(X, Y, Z)		crypto_alg_available(X, 0)
	#define crypto_comp_tfm(X)				X
	#define crypto_comp_cast(X)				X
	#define crypto_alloc_comp(X, Y, Z)		crypto_alloc_tfm(X, mode)
#else
	#define ecb(X)	"ecb(" #X ")"
	#define cbc(X)	"cbc(" #X ")"
	#define hmac(X)	"hmac(" #X ")"
#endif  

struct crypto_details
{
	char *alg_name;
	int mode;
	int sw_type;
};

static struct crypto_details crypto_details[CRYPTO_ALGORITHM_MAX + 1] = {
	{ NULL,              0,                   0 },
	 
	{ cbc(des),          CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ cbc(des3_ede),     CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ cbc(blowfish),     CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ cbc(cast5),        CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ cbc(skipjack),     CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ hmac(md5),         0,                   SW_TYPE_HMAC },
	{ hmac(sha1),        0,                   SW_TYPE_HMAC },
	{ hmac(ripemd160),   0,                   SW_TYPE_HMAC },
	{ "md5-kpdk??",      0,                   SW_TYPE_HASH },
	{ "sha1-kpdk??",     0,                   SW_TYPE_HASH },
	{ cbc(aes),          CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ ecb(arc4),         CRYPTO_TFM_MODE_ECB, SW_TYPE_BLKCIPHER },
	{ "md5",             0,                   SW_TYPE_HASH },
	{ "sha1",            0,                   SW_TYPE_HASH },
	{ hmac(digest_null), 0,                   SW_TYPE_HMAC },
	{ cbc(cipher_null),  CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ "deflate",         0,                   SW_TYPE_COMP },
	{ hmac(sha256),      0,                   SW_TYPE_HMAC },
	{ hmac(sha384),      0,                   SW_TYPE_HMAC },
	{ hmac(sha512),      0,                   SW_TYPE_HMAC },
	{ cbc(camellia),     CRYPTO_TFM_MODE_CBC, SW_TYPE_BLKCIPHER },
	{ "sha256",          0,                   SW_TYPE_HASH },
	{ "sha384",          0,                   SW_TYPE_HASH },
	{ "sha512",          0,                   SW_TYPE_HASH },
	{ "ripemd160",       0,                   SW_TYPE_HASH },
};

int32_t swcr_id = -1;
module_param(swcr_id, int, 0444);
MODULE_PARM_DESC(swcr_id, "Read-Only OCF ID for cryptosoft driver");

int swcr_fail_if_compression_grows = 1;
module_param(swcr_fail_if_compression_grows, int, 0644);
MODULE_PARM_DESC(swcr_fail_if_compression_grows,
                "Treat compression that results in more data as a failure");

static struct swcr_data **swcr_sessions = NULL;
static u_int32_t swcr_sesnum = 0;

static	int swcr_process(device_t, struct cryptop *, int);
static	int swcr_newsession(device_t, u_int32_t *, struct cryptoini *);
static	int swcr_freesession(device_t, u_int64_t);

static device_method_t swcr_methods = {
	 
	DEVMETHOD(cryptodev_newsession,	swcr_newsession),
	DEVMETHOD(cryptodev_freesession,swcr_freesession),
	DEVMETHOD(cryptodev_process,	swcr_process),
};

#define debug swcr_debug
int swcr_debug = 0;
module_param(swcr_debug, int, 0644);
MODULE_PARM_DESC(swcr_debug, "Enable debug");

#ifdef MY_ABC_HERE
static void ocf_async_done(struct crypto_async_request *async_req,
                                int error)
{
    struct ocf_request *ocf_req = async_req->data;

    if (error == -EINPROGRESS) {
        WARN_ON(1);
        return;
    }

    ocf_req->error = error;
    complete(&ocf_req->complete);
}

static void ocf_async_wait(struct ocf_request *ocf_req,
                                int rc)
{
    switch (rc) {
    case 0:
         
        break;
    case -EBUSY:
    case -EINPROGRESS:
         
        wait_for_completion(&ocf_req->complete);

        if (ocf_req->error) {
            printk("error from async request: %d \n", ocf_req->error);
            WARN_ON(1);
        }

        break;
    default:
        break;
    }

    kfree(ocf_req->req);
    ocf_req->req = NULL;
}
#endif

static int
swcr_newsession(device_t dev, u_int32_t *sid, struct cryptoini *cri)
{
	struct swcr_data **swd;
	u_int32_t i;
	int error;
	char *algo;
	int mode, sw_type;

	dprintk("%s()\n", __FUNCTION__);
	if (sid == NULL || cri == NULL) {
		dprintk("%s,%d - EINVAL\n", __FILE__, __LINE__);
		return EINVAL;
	}

	if (swcr_sessions) {
		for (i = 1; i < swcr_sesnum; i++)
			if (swcr_sessions[i] == NULL)
				break;
	} else
		i = 1;		 

	if (swcr_sessions == NULL || i == swcr_sesnum) {
		if (swcr_sessions == NULL) {
			i = 1;  
			swcr_sesnum = CRYPTO_SW_SESSIONS;
		} else
			swcr_sesnum *= 2;

		swd = kmalloc(swcr_sesnum * sizeof(struct swcr_data *), SLAB_ATOMIC);
		if (swd == NULL) {
			 
			if (swcr_sesnum == CRYPTO_SW_SESSIONS)
				swcr_sesnum = 0;
			else
				swcr_sesnum /= 2;
			dprintk("%s,%d: ENOBUFS\n", __FILE__, __LINE__);
			return ENOBUFS;
		}
		memset(swd, 0, swcr_sesnum * sizeof(struct swcr_data *));

		if (swcr_sessions) {
			memcpy(swd, swcr_sessions,
			    (swcr_sesnum / 2) * sizeof(struct swcr_data *));
			kfree(swcr_sessions);
		}

		swcr_sessions = swd;
	}

	swd = &swcr_sessions[i];
	*sid = i;

	while (cri) {
		*swd = (struct swcr_data *) kmalloc(sizeof(struct swcr_data),
				SLAB_ATOMIC);
		if (*swd == NULL) {
			swcr_freesession(NULL, i);
			dprintk("%s,%d: ENOBUFS\n", __FILE__, __LINE__);
			return ENOBUFS;
		}
		memset(*swd, 0, sizeof(struct swcr_data));

		if (cri->cri_alg > CRYPTO_ALGORITHM_MAX) {
			printk("cryptosoft: Unknown algorithm 0x%x\n", cri->cri_alg);
			swcr_freesession(NULL, i);
			return EINVAL;
		}

		algo = crypto_details[cri->cri_alg].alg_name;
		if (!algo || !*algo) {
			printk("cryptosoft: Unsupported algorithm 0x%x\n", cri->cri_alg);
			swcr_freesession(NULL, i);
			return EINVAL;
		}

		mode = crypto_details[cri->cri_alg].mode;
		sw_type = crypto_details[cri->cri_alg].sw_type;

		switch (cri->cri_alg) {
		case CRYPTO_NULL_CBC:
			cri->cri_klen = 0;  
			break;
		default:
			break;
		}

		if (sw_type == SW_TYPE_BLKCIPHER) {
			dprintk("%s crypto_alloc_blkcipher(%s, 0x%x)\n", __FUNCTION__,
					algo, mode);

#ifdef MY_ABC_HERE
			(*swd)->sw_tfm = crypto_ablkcipher_tfm(
								crypto_alloc_ablkcipher(algo, 0, 0));
#else
			(*swd)->sw_tfm = crypto_blkcipher_tfm(
								crypto_alloc_blkcipher(algo, 0,
									CRYPTO_ALG_ASYNC));
#endif
			if (!(*swd)->sw_tfm) {
				dprintk("cryptosoft: crypto_alloc_blkcipher failed(%s,0x%x)\n",
						algo,mode);
				swcr_freesession(NULL, i);
				return EINVAL;
			}

			if (debug) {
				dprintk("%s key:cri->cri_klen=%d,(cri->cri_klen + 7)/8=%d",
						__FUNCTION__,cri->cri_klen,(cri->cri_klen + 7)/8);
				for (i = 0; i < (cri->cri_klen + 7) / 8; i++)
				{
					dprintk("%s0x%x", (i % 8) ? " " : "\n    ",
							cri->cri_key[i] & 0xff);
				}
				dprintk("\n");
			}
#ifdef MY_ABC_HERE
			error = crypto_ablkcipher_setkey(
							(struct crypto_ablkcipher *)((*swd)->sw_tfm), cri->cri_key,
							(cri->cri_klen + 7) / 8);
#else
			error = crypto_blkcipher_setkey(
						crypto_blkcipher_cast((*swd)->sw_tfm), cri->cri_key,
							(cri->cri_klen + 7) / 8);
#endif
			if (error) {
				printk("cryptosoft: setkey failed %d (crt_flags=0x%x)\n", error,
						(*swd)->sw_tfm->crt_flags);
				swcr_freesession(NULL, i);
				return error;
			}
		} else if (sw_type == SW_TYPE_HMAC || sw_type == SW_TYPE_HASH) {
			dprintk("%s crypto_alloc_hash(%s, 0x%x)\n", __FUNCTION__,
					algo, mode);

			(*swd)->sw_tfm = crypto_hash_tfm(
								crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC));

			if (!(*swd)->sw_tfm) {
				dprintk("cryptosoft: crypto_alloc_hash failed(%s,0x%x)\n",
						algo, mode);
				swcr_freesession(NULL, i);
				return EINVAL;
			}

			(*swd)->u.hmac.sw_klen = (cri->cri_klen + 7) / 8;
			(*swd)->u.hmac.sw_key = (char *)kmalloc((*swd)->u.hmac.sw_klen,
				SLAB_ATOMIC);
			if ((*swd)->u.hmac.sw_key == NULL) {
				swcr_freesession(NULL, i);
				dprintk("%s,%d: ENOBUFS\n", __FILE__, __LINE__);
				return ENOBUFS;
			}
			memcpy((*swd)->u.hmac.sw_key, cri->cri_key, (*swd)->u.hmac.sw_klen);
			if (cri->cri_mlen) {
				(*swd)->u.hmac.sw_mlen = cri->cri_mlen;
			} else {
				(*swd)->u.hmac.sw_mlen =
						crypto_hash_digestsize(
								crypto_hash_cast((*swd)->sw_tfm));
			}
		} else if (sw_type == SW_TYPE_COMP) {
			(*swd)->sw_tfm = crypto_comp_tfm(
					crypto_alloc_comp(algo, 0, CRYPTO_ALG_ASYNC));
			if (!(*swd)->sw_tfm) {
				dprintk("cryptosoft: crypto_alloc_comp failed(%s,0x%x)\n",
						algo, mode);
				swcr_freesession(NULL, i);
				return EINVAL;
			}
			(*swd)->u.sw_comp_buf = kmalloc(CRYPTO_MAX_DATA_LEN, SLAB_ATOMIC);
			if ((*swd)->u.sw_comp_buf == NULL) {
				swcr_freesession(NULL, i);
				dprintk("%s,%d: ENOBUFS\n", __FILE__, __LINE__);
				return ENOBUFS;
			}
		} else {
			printk("cryptosoft: Unhandled sw_type %d\n", sw_type);
			swcr_freesession(NULL, i);
			return EINVAL;
		}

		(*swd)->sw_alg = cri->cri_alg;
		(*swd)->sw_type = sw_type;

		cri = cri->cri_next;
		swd = &((*swd)->sw_next);
	}
	return 0;
}

static int
swcr_freesession(device_t dev, u_int64_t tid)
{
	struct swcr_data *swd;
	u_int32_t sid = CRYPTO_SESID2LID(tid);

	dprintk("%s()\n", __FUNCTION__);
	if (sid > swcr_sesnum || swcr_sessions == NULL ||
			swcr_sessions[sid] == NULL) {
		dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
		return(EINVAL);
	}

	if (sid == 0)
		return(0);

	while ((swd = swcr_sessions[sid]) != NULL) {
		swcr_sessions[sid] = swd->sw_next;
		if (swd->sw_tfm)
			crypto_free_tfm(swd->sw_tfm);
		if (swd->sw_type == SW_TYPE_COMP) {
			if (swd->u.sw_comp_buf)
				kfree(swd->u.sw_comp_buf);
		} else {
			if (swd->u.hmac.sw_key)
				kfree(swd->u.hmac.sw_key);
		}
		kfree(swd);
	}
	return 0;
}

static int
swcr_process(device_t dev, struct cryptop *crp, int hint)
{
	struct cryptodesc *crd;
	struct swcr_data *sw;
	u_int32_t lid;
#define SCATTERLIST_MAX 16
	struct scatterlist sg[SCATTERLIST_MAX];
	int sg_num, sg_len, skip;
	struct sk_buff *skb = NULL;
	struct uio *uiop = NULL;

	dprintk("%s()\n", __FUNCTION__);
	 
	if (crp == NULL) {
		dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
		return EINVAL;
	}

	crp->crp_etype = 0;

	if (crp->crp_desc == NULL || crp->crp_buf == NULL) {
		dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
		crp->crp_etype = EINVAL;
		goto done;
	}

	lid = crp->crp_sid & 0xffffffff;
	if (lid >= swcr_sesnum || lid == 0 || swcr_sessions == NULL ||
			swcr_sessions[lid] == NULL) {
		crp->crp_etype = ENOENT;
		dprintk("%s,%d: ENOENT\n", __FILE__, __LINE__);
		goto done;
	}

	if (crp->crp_flags & CRYPTO_F_SKBUF) {
		skb = (struct sk_buff *) crp->crp_buf;
		if (skb_shinfo(skb)->nr_frags >= SCATTERLIST_MAX) {
			printk("%s,%d: %d nr_frags > SCATTERLIST_MAX", __FILE__, __LINE__,
					skb_shinfo(skb)->nr_frags);
			goto done;
		}
	} else if (crp->crp_flags & CRYPTO_F_IOV) {
		uiop = (struct uio *) crp->crp_buf;
		if (uiop->uio_iovcnt > SCATTERLIST_MAX) {
			printk("%s,%d: %d uio_iovcnt > SCATTERLIST_MAX", __FILE__, __LINE__,
					uiop->uio_iovcnt);
			goto done;
		}
	}

	for (crd = crp->crp_desc; crd; crd = crd->crd_next) {
		 
		for (sw = swcr_sessions[lid]; sw && sw->sw_alg != crd->crd_alg;
				sw = sw->sw_next)
			;

		if (sw == NULL) {
			crp->crp_etype = EINVAL;
			dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
			goto done;
		}

		skip = crd->crd_skip;

		memset(sg, 0, sizeof(sg));
		if (crp->crp_flags & CRYPTO_F_SKBUF) {
			int i, len;

			sg_num = 0;
			sg_len = 0;

			if (skip < skb_headlen(skb)) {
				len = skb_headlen(skb) - skip;
				if (len + sg_len > crd->crd_len)
					len = crd->crd_len - sg_len;
				sg_set_page(&sg[sg_num],
					virt_to_page(skb->data + skip), len,
					offset_in_page(skb->data + skip));
				sg_len += len;
				sg_num++;
				skip = 0;
			} else
				skip -= skb_headlen(skb);

			for (i = 0; sg_len < crd->crd_len &&
						i < skb_shinfo(skb)->nr_frags &&
						sg_num < SCATTERLIST_MAX; i++) {
				if (skip < skb_shinfo(skb)->frags[i].size) {
					len = skb_shinfo(skb)->frags[i].size - skip;
					if (len + sg_len > crd->crd_len)
						len = crd->crd_len - sg_len;
					sg_set_page(&sg[sg_num],
						skb_shinfo(skb)->frags[i].page,
						len,
						skb_shinfo(skb)->frags[i].page_offset + skip);
					sg_len += len;
					sg_num++;
					skip = 0;
				} else
					skip -= skb_shinfo(skb)->frags[i].size;
			}
		} else if (crp->crp_flags & CRYPTO_F_IOV) {
			int len;

			sg_len = 0;
			for (sg_num = 0; sg_len <= crd->crd_len &&
					sg_num < uiop->uio_iovcnt &&
					sg_num < SCATTERLIST_MAX; sg_num++) {
				if (skip <= uiop->uio_iov[sg_num].iov_len) {
					len = uiop->uio_iov[sg_num].iov_len - skip;
					if (len + sg_len > crd->crd_len)
						len = crd->crd_len - sg_len;
					sg_set_page(&sg[sg_num],
						virt_to_page(uiop->uio_iov[sg_num].iov_base+skip),
						len,
						offset_in_page(uiop->uio_iov[sg_num].iov_base+skip));
					sg_len += len;
					skip = 0;
				} else 
					skip -= uiop->uio_iov[sg_num].iov_len;
			}
		} else {
			sg_len = (crp->crp_ilen - skip);
			if (sg_len > crd->crd_len)
				sg_len = crd->crd_len;
			sg_set_page(&sg[0], virt_to_page(crp->crp_buf + skip),
				sg_len, offset_in_page(crp->crp_buf + skip));
			sg_num = 1;
		}

		switch (sw->sw_type) {
		case SW_TYPE_BLKCIPHER: {
			unsigned char iv[EALG_MAX_BLOCK_LEN];
			unsigned char *ivp = iv;
#ifdef MY_ABC_HERE
			struct ocf_request ocf_req = {0};
#endif

			int ivsize = 
#ifdef MY_ABC_HERE
				crypto_ablkcipher_ivsize((struct crypto_ablkcipher *)(sw->sw_tfm));
#else
				crypto_blkcipher_ivsize(crypto_blkcipher_cast(sw->sw_tfm));
#endif
#ifndef MY_ABC_HERE
			struct blkcipher_desc desc;
#endif

#ifdef MY_ABC_HERE
			if (sg_len < crypto_ablkcipher_blocksize((struct crypto_ablkcipher *)sw->sw_tfm)) {
#else
			if (sg_len < crypto_blkcipher_blocksize(
					crypto_blkcipher_cast(sw->sw_tfm))) {
#endif
				crp->crp_etype = EINVAL;
				dprintk("%s,%d: EINVAL len %d < %d\n", __FILE__, __LINE__,
#ifdef MY_ABC_HERE
						sg_len, crypto_ablkcipher_blocksize((struct crypto_ablkcipher *)sw->sw_tfm));
#else
						sg_len, crypto_blkcipher_blocksize(
							crypto_blkcipher_cast(sw->sw_tfm)));
#endif
				goto done;
			}

			if (ivsize > sizeof(iv)) {
				crp->crp_etype = EINVAL;
				dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
				goto done;
			}

			if (crd->crd_flags & CRD_F_KEY_EXPLICIT) {
				int i, error;

				if (debug) {
					dprintk("%s key:", __FUNCTION__);
					for (i = 0; i < (crd->crd_klen + 7) / 8; i++)
						dprintk("%s0x%x", (i % 8) ? " " : "\n    ",
								crd->crd_key[i] & 0xff);
					dprintk("\n");
				}
#ifdef MY_ABC_HERE
				error = crypto_ablkcipher_setkey((struct crypto_ablkcipher *)sw->sw_tfm, crd->crd_key,
							(crd->crd_klen + 7) / 8);
#else
				error = crypto_blkcipher_setkey(
							crypto_blkcipher_cast(sw->sw_tfm), crd->crd_key,
							(crd->crd_klen + 7) / 8);
#endif
				if (error) {
					dprintk("cryptosoft: setkey failed %d (crt_flags=0x%x)\n",
							error, sw->sw_tfm->crt_flags);
					crp->crp_etype = -error;
				}
			}

#ifdef MY_ABC_HERE
			init_completion(&ocf_req.complete);

			if (NULL == (ocf_req.req = kmalloc(sizeof(struct ablkcipher_request), GFP_KERNEL))) {
				WARN_ON(1);
				goto done;
			}

			ablkcipher_request_set_tfm(ocf_req.req, (struct crypto_ablkcipher *)(sw->sw_tfm));
			ablkcipher_request_set_callback(ocf_req.req, CRYPTO_TFM_REQ_MAY_BACKLOG |
							CRYPTO_TFM_REQ_MAY_SLEEP,
							ocf_async_done,
							&ocf_req);
#else
			memset(&desc, 0, sizeof(desc));
			desc.tfm = crypto_blkcipher_cast(sw->sw_tfm);
#endif

			if (crd->crd_flags & CRD_F_ENCRYPT) {  

				if (crd->crd_flags & CRD_F_IV_EXPLICIT) {
					ivp = crd->crd_iv;
				} else {
					get_random_bytes(ivp, ivsize);
				}
				 
				if ((crd->crd_flags & CRD_F_IV_PRESENT) == 0) {
					crypto_copyback(crp->crp_flags, crp->crp_buf,
							crd->crd_inject, ivsize, (caddr_t)ivp);
				}
#ifdef MY_ABC_HERE
				ablkcipher_request_set_crypt(ocf_req.req, sg, sg, sg_len, ivp);
				ocf_async_wait(&ocf_req, crypto_ablkcipher_encrypt(ocf_req.req));
#else
				desc.info = ivp;
				crypto_blkcipher_encrypt_iv(&desc, sg, sg, sg_len);
#endif

			} else {  

				if (crd->crd_flags & CRD_F_IV_EXPLICIT) {
					ivp = crd->crd_iv;
				} else {
					crypto_copydata(crp->crp_flags, crp->crp_buf,
							crd->crd_inject, ivsize, (caddr_t)ivp);
				}
#ifdef MY_ABC_HERE
				ablkcipher_request_set_crypt(ocf_req.req, sg, sg, sg_len, ivp);
				ocf_async_wait(&ocf_req,
							   crypto_ablkcipher_decrypt(ocf_req.req));
#else
				desc.info = ivp;
				crypto_blkcipher_decrypt_iv(&desc, sg, sg, sg_len);
#endif
			}
			} break;
		case SW_TYPE_HMAC:
		case SW_TYPE_HASH:
			{
			char result[HASH_MAX_LEN];
			struct hash_desc desc;

			if (crp->crp_ilen - crd->crd_inject < sw->u.hmac.sw_mlen) {
				dprintk(
			"cryptosoft: EINVAL crp_ilen=%d, len=%d, inject=%d digestsize=%d\n",
						crp->crp_ilen, crd->crd_skip + sg_len, crd->crd_inject,
						sw->u.hmac.sw_mlen);
				crp->crp_etype = EINVAL;
				goto done;
			}

			memset(&desc, 0, sizeof(desc));
			desc.tfm = crypto_hash_cast(sw->sw_tfm);

			memset(result, 0, sizeof(result));

			if (sw->sw_type == SW_TYPE_HMAC) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
				crypto_hmac(sw->sw_tfm, sw->u.hmac.sw_key, &sw->u.hmac.sw_klen,
						sg, sg_num, result);
#else
				crypto_hash_setkey(desc.tfm, sw->u.hmac.sw_key,
						sw->u.hmac.sw_klen);
				crypto_hash_digest(&desc, sg, sg_len, result);
#endif  
				
			} else {  
				crypto_hash_digest(&desc, sg, sg_len, result);
			}

			crypto_copyback(crp->crp_flags, crp->crp_buf,
					crd->crd_inject, sw->u.hmac.sw_mlen, result);
			}
			break;

		case SW_TYPE_COMP: {
			void *ibuf = NULL;
			void *obuf = sw->u.sw_comp_buf;
			int ilen = sg_len, olen = CRYPTO_MAX_DATA_LEN;
			int ret = 0;

			if (sg_num > 1) {
				int blk;

				ibuf = obuf;
				for (blk = 0; blk < sg_num; blk++) {
					memcpy(obuf, sg_virt(&sg[blk]),
							sg[blk].length);
					obuf += sg[blk].length;
				}
				olen -= sg_len;
			} else
				ibuf = sg_virt(&sg[0]);

			if (crd->crd_flags & CRD_F_ENCRYPT) {  
				ret = crypto_comp_compress(crypto_comp_cast(sw->sw_tfm),
						ibuf, ilen, obuf, &olen);
				if (!ret && olen > crd->crd_len) {
					dprintk("cryptosoft: ERANGE compress %d into %d\n",
							crd->crd_len, olen);
					if (swcr_fail_if_compression_grows)
						ret = ERANGE;
				}
			} else {  
				ret = crypto_comp_decompress(crypto_comp_cast(sw->sw_tfm),
						ibuf, ilen, obuf, &olen);
				if (!ret && (olen + crd->crd_inject) > crp->crp_olen) {
					dprintk("cryptosoft: ETOOSMALL decompress %d into %d, "
							"space for %d,at offset %d\n",
							crd->crd_len, olen, crp->crp_olen, crd->crd_inject);
					ret = ETOOSMALL;
				}
			}
			if (ret)
				dprintk("%s,%d: ret = %d\n", __FILE__, __LINE__, ret);

			crp->crp_etype = ret < 0 ? -ret : ret;
			if (ret == 0) {
				 
				crypto_copyback(crp->crp_flags, crp->crp_buf,
						crd->crd_inject, olen, obuf);
				crp->crp_olen = olen;
			}

			} break;

		default:
			 
			dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
			crp->crp_etype = EINVAL;
			goto done;
		}
	}

done:
	crypto_done(crp);
	return 0;
}

static int
cryptosoft_init(void)
{
	int i, sw_type, mode;
	char *algo;

	dprintk("%s(%p)\n", __FUNCTION__, cryptosoft_init);

	softc_device_init(&swcr_softc, "cryptosoft", 0, swcr_methods);

	swcr_id = crypto_get_driverid(softc_get_device(&swcr_softc),
			CRYPTOCAP_F_SOFTWARE | CRYPTOCAP_F_SYNC);
	if (swcr_id < 0) {
		printk("Software crypto device cannot initialize!");
		return -ENODEV;
	}

#define	REGISTER(alg) \
		crypto_register(swcr_id, alg, 0,0);

	for (i = CRYPTO_ALGORITHM_MIN; i <= CRYPTO_ALGORITHM_MAX; ++i)
	{
		
		algo = crypto_details[i].alg_name;
		if (!algo || !*algo)
		{
			dprintk("%s:Algorithm %d not supported\n", __FUNCTION__, i);
			continue;
		}

		mode = crypto_details[i].mode;
		sw_type = crypto_details[i].sw_type;

		switch (sw_type)
		{
			case SW_TYPE_CIPHER:
				if (crypto_has_cipher(algo, 0, CRYPTO_ALG_ASYNC))
				{
					REGISTER(i);
				}
				else
				{
					dprintk("%s:CIPHER algorithm %d:'%s' not supported\n",
								__FUNCTION__, i, algo);
				}
				break;
			case SW_TYPE_HMAC:
				if (crypto_has_hash(algo, 0, CRYPTO_ALG_ASYNC))
				{
					REGISTER(i);
				}
				else
				{
					dprintk("%s:HMAC algorithm %d:'%s' not supported\n",
								__FUNCTION__, i, algo);
				}
				break;
			case SW_TYPE_HASH:
				if (crypto_has_hash(algo, 0, CRYPTO_ALG_ASYNC))
				{
					REGISTER(i);
				}
				else
				{
					dprintk("%s:HASH algorithm %d:'%s' not supported\n",
								__FUNCTION__, i, algo);
				}
				break;
			case SW_TYPE_COMP:
				if (crypto_has_comp(algo, 0, CRYPTO_ALG_ASYNC))
				{
					REGISTER(i);
				}
				else
				{
					dprintk("%s:COMP algorithm %d:'%s' not supported\n",
								__FUNCTION__, i, algo);
				}
				break;
			case SW_TYPE_BLKCIPHER:
#ifdef MY_ABC_HERE
				if (crypto_has_ablkcipher(algo, 0, 0))
#else
				if (crypto_has_blkcipher(algo, 0, CRYPTO_ALG_ASYNC))
#endif
				{
					REGISTER(i);
				}
				else
				{
					dprintk("%s:BLKCIPHER algorithm %d:'%s' not supported\n",
								__FUNCTION__, i, algo);
				}
				break;
			default:
				dprintk(
				"%s:Algorithm Type %d not supported (algorithm %d:'%s')\n",
					__FUNCTION__, sw_type, i, algo);
				break;
		}
	}

	return(0);
}

static void
cryptosoft_exit(void)
{
	dprintk("%s()\n", __FUNCTION__);
	crypto_unregister_all(swcr_id);
	swcr_id = -1;
}

late_initcall(cryptosoft_init);
module_exit(cryptosoft_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("David McCullough <david_mccullough@securecomputing.com>");
MODULE_DESCRIPTION("Cryptosoft (OCF module for kernel crypto)");
