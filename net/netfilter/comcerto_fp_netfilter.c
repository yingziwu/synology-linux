#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>

static unsigned int fp_netfilter_pre_routing(int family, unsigned int hooknum, struct sk_buff *skb)
{
	struct nf_conn *ct;
	u_int8_t protonum;
	enum ip_conntrack_info ctinfo;
	struct comcerto_fp_info *fp_info;
	int dir;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto done;

	protonum = nf_ct_protonum(ct);
#if defined(MY_ABC_HERE)
	if ((protonum != IPPROTO_TCP) && (protonum != IPPROTO_UDP) && (protonum != IPPROTO_IPIP))
#else
	if ((protonum != IPPROTO_TCP) && (protonum != IPPROTO_UDP))
#endif
		goto done;

	dir = CTINFO2DIR(ctinfo);

	if (dir == IP_CT_DIR_ORIGINAL) {
		fp_info = &ct->fp_info[IP_CT_DIR_ORIGINAL];
	} else {
		fp_info = &ct->fp_info[IP_CT_DIR_REPLY];
	}

	if (fp_info->mark && (fp_info->mark != skb->mark))
		if (printk_ratelimit())
#if defined(MY_ABC_HERE)
			printk(KERN_DEBUG "ct: mark changed %x, %x\n", fp_info->mark, skb->mark);
#else
			printk(KERN_INFO "ct: mark changed %x, %x\n", fp_info->mark, skb->mark);
#endif

	if (fp_info->ifindex && (fp_info->ifindex != skb->dev->ifindex))
		if (printk_ratelimit())
#if defined(MY_ABC_HERE)
			printk(KERN_DEBUG "ct: ifindex changed %d, %d\n", fp_info->ifindex, skb->dev->ifindex);
#else
			printk(KERN_INFO "ct: ifindex changed %d, %d\n", fp_info->ifindex, skb->dev->ifindex);
#endif

	if (fp_info->iif && (fp_info->iif != skb->skb_iif))
		if (printk_ratelimit())
#if defined(MY_ABC_HERE)
			printk(KERN_DEBUG "ct: iif changed %d, %d\n", fp_info->iif, skb->skb_iif);
#else
			printk(KERN_INFO "ct: iif changed %d, %d\n", fp_info->iif, skb->skb_iif);
#endif

	fp_info->mark = skb->mark;
	fp_info->ifindex = skb->dev->ifindex;
	fp_info->iif = skb->skb_iif;

done:
	return NF_ACCEPT;
}

static unsigned int fp_ipv4_netfilter_pre_routing(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
{

	return fp_netfilter_pre_routing(PF_INET, hooknum, skb);
}

static unsigned int fp_ipv6_netfilter_pre_routing(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
{

	return fp_netfilter_pre_routing(PF_INET6, hooknum, skb);
}

static struct nf_hook_ops fp_netfilter_ops[] __read_mostly = {
	{
		.hook		= fp_ipv4_netfilter_pre_routing,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_LAST,
	},
	{
		.hook		= fp_ipv6_netfilter_pre_routing,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_LAST,
	},
};

static int __init fp_netfilter_init(void)
{
	int rc;

	rc = nf_register_hooks(fp_netfilter_ops, ARRAY_SIZE(fp_netfilter_ops));
	if (rc < 0) {
		printk(KERN_ERR "fp_netfilter_ops: can't register hooks.\n");
		goto err0;
	}

	return 0;

err0:
	return rc;
}

static void __exit fp_netfilter_exit(void)
{
	nf_unregister_hooks(fp_netfilter_ops, ARRAY_SIZE(fp_netfilter_ops));
}

module_init(fp_netfilter_init);
module_exit(fp_netfilter_exit);
