#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/icmpv6.h>
#include <linux/init.h>
#include <linux/route.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter_ipv6.h>
#if defined(MY_ABC_HERE)
#include <linux/netfilter/nf_conntrack_proto_gre.h>
#endif
#include <linux/slab.h>

#include <asm/uaccess.h>
#include <linux/atomic.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ip6_tunnel.h>
#include <net/xfrm.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

MODULE_AUTHOR("Ville Nuorvala");
MODULE_DESCRIPTION("IPv6 tunneling device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETDEV("ip6tnl0");

#ifdef IP6_TNL_DEBUG
#define IP6_TNL_TRACE(x...) printk(KERN_DEBUG "%s:" x "\n", __func__)
#else
#define IP6_TNL_TRACE(x...) do {;} while(0)
#endif

#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT 20

#define HASH_SIZE  32

#define HASH(addr) ((__force u32)((addr)->s6_addr32[0] ^ (addr)->s6_addr32[1] ^ \
		     (addr)->s6_addr32[2] ^ (addr)->s6_addr32[3]) & \
		    (HASH_SIZE - 1))

#if defined(MY_ABC_HERE)
#define for_each_ip6_tunnel_rcu(start) \
	for (t = rcu_dereference(start); t; t = rcu_dereference(t->next))
#endif

static int ip6_tnl_dev_init(struct net_device *dev);
static void ip6_tnl_dev_setup(struct net_device *dev);

static int ip6_tnl_net_id __read_mostly;
struct ip6_tnl_net {
	 
	struct net_device *fb_tnl_dev;
	 
	struct ip6_tnl __rcu *tnls_r_l[HASH_SIZE];
	struct ip6_tnl __rcu *tnls_wc[1];
	struct ip6_tnl __rcu **tnls[2];
};

struct pcpu_tstats {
	unsigned long	rx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_packets;
	unsigned long	tx_bytes;
};

static struct net_device_stats *ip6_get_stats(struct net_device *dev)
{
	struct pcpu_tstats sum = { 0 };
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_tstats *tstats = per_cpu_ptr(dev->tstats, i);

		sum.rx_packets += tstats->rx_packets;
		sum.rx_bytes   += tstats->rx_bytes;
		sum.tx_packets += tstats->tx_packets;
		sum.tx_bytes   += tstats->tx_bytes;
	}
	dev->stats.rx_packets = sum.rx_packets;
	dev->stats.rx_bytes   = sum.rx_bytes;
	dev->stats.tx_packets = sum.tx_packets;
	dev->stats.tx_bytes   = sum.tx_bytes;
	return &dev->stats;
}

#if defined(MY_ABC_HERE)
static struct kmem_cache *mr_kmem __read_mostly;
int mr_kmem_alloced = 0;

static inline size_t  ip6_4rd_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ip6_4rd_map_msg));
}

static int ip6_4rd_fill_node( struct sk_buff *skb, struct ip6_tnl_4rd_map_rule *mr,
			u32 pid, u32 seq,int type, unsigned int flags, int reset, unsigned int ifindex)
{
	struct ip6_4rd_map_msg *mr_msg;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, pid , seq, type, sizeof(*mr_msg), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	mr_msg = nlmsg_data(nlh);
	if(reset)
	{
		memset(mr_msg,0,sizeof(*mr_msg));
		mr_msg->reset = 1;
		mr_msg->ifindex = ifindex;
		
	}
	else
	{
		 
		memset(mr_msg,0,sizeof(*mr_msg));
		mr_msg->prefix = mr->prefix;
		mr_msg->prefixlen = mr->prefixlen ;
		ipv6_addr_copy(&mr_msg->relay_prefix, &mr->relay_prefix);
		ipv6_addr_copy(&mr_msg->relay_suffix, &mr->relay_suffix);
		mr_msg->relay_prefixlen = mr->relay_prefixlen ;
		mr_msg->relay_suffixlen = mr->relay_suffixlen ;
		mr_msg->psid_offsetlen = mr->psid_offsetlen ;
		mr_msg->eabit_len = mr->eabit_len ;
		mr_msg->entry_num = mr->entry_num ;
		mr_msg->ifindex = ifindex;
	}
	return nlmsg_end(skb, nlh);

}

static int inet6_dump4rd_mrule(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	unsigned int h, s_h;
	int s_idx, s_ip_idx;
	int idx, ip_idx;
	struct ip6_tnl_4rd_map_rule *mr ;
	int err = 0;

	struct ip6_tnl *t;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];
	s_ip_idx = ip_idx = cb->args[2];

	for (h = s_h; h < HASH_SIZE ; h++, s_idx = 0) {
		idx = 0;
		for_each_ip6_tunnel_rcu(ip6n->tnls_r_l[h])
		{
			if (idx < s_idx)
				goto cont_tunnel;
			if (idx > s_idx)
				s_ip_idx = 0;
			ip_idx = 0;
			read_lock(&t->ip4rd.map_lock);
			list_for_each_entry (mr, &t->ip4rd.map_list, mr_list){
				if (ip_idx < s_ip_idx)
					goto cont_mr;
				err = ip6_4rd_fill_node(skb, mr,NETLINK_CB(cb->skb).pid,
						cb->nlh->nlmsg_seq,RTM_NEW4RD, NLM_F_MULTI , 0, t->dev->ifindex);
				if (err < 0) {
					WARN_ON(err == -EMSGSIZE);
					kfree_skb(skb);
					read_unlock(&t->ip4rd.map_lock);
					goto out;
				}
cont_mr:
				ip_idx++;
			}
			read_unlock(&t->ip4rd.map_lock);
cont_tunnel:
			idx++;	
		}
	}
out:
	cb->args[0] = h;
	cb->args[1] = idx;
	cb->args[2] = ip_idx;
	
	return skb->len;
}

void ip6_4rd_notify(int event, struct ip6_tnl_4rd_map_rule *mr ,struct net_device *dev, int reset)
{
	struct sk_buff *skb;
	struct net *net = dev_net(dev);
	int err;

	err = -ENOBUFS;

	skb = nlmsg_new(ip6_4rd_nlmsg_size(), gfp_any());
	if (skb == NULL)
		goto errout;

	err = ip6_4rd_fill_node(skb, mr,0,0,event,  0, reset, dev->ifindex);
	if (err < 0) {
		 
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, 0, RTNLGRP_IPV6_IFADDR,
		    NULL, gfp_any());
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_IPV6_IFADDR, err);
}

static inline void
ip6_tnl_4rd_mr_destroy(char *f, struct ip6_tnl_4rd_map_rule *mr)
{
	list_del(&mr->mr_list);
	kmem_cache_free(mr_kmem, mr);
	--mr_kmem_alloced;
}

static int
ip6_tnl_4rd_mr_create(struct ip6_tnl_4rd *ip4rd, struct ip6_tnl_4rd_parm *parm, struct net_device *dev)
{
	struct ip6_tnl_4rd_map_rule *mr ;
	int err = 0;

       write_lock_bh(&parm->map_lock);
       list_for_each_entry (mr, &parm->map_list, mr_list){
               if( mr->entry_num == ip4rd->entry_num ){
                       printk(KERN_DEBUG "ip6_tnl_4rd_mr_create: map rule found update");
                       mr->prefix = ip4rd->prefix ;
                       ipv6_addr_copy(&mr->relay_prefix, &ip4rd->relay_prefix);
                       ipv6_addr_copy(&mr->relay_suffix, &ip4rd->relay_suffix);
                       mr->prefixlen = ip4rd->prefixlen ;
                       mr->relay_prefixlen = ip4rd->relay_prefixlen ;
                       mr->relay_suffixlen = ip4rd->relay_suffixlen ;
                       mr->psid_offsetlen = ip4rd->psid_offsetlen ;
                       mr->eabit_len = ip4rd->eabit_len ;
                       mr->entry_num = ip4rd->entry_num ;
                       goto out;
               }
       }

       mr = kmem_cache_alloc(mr_kmem, GFP_KERNEL);

       if (!mr) {
               printk(KERN_INFO "ip6_tnl_4rd_mr_create: kmem_cache_alloc fail");
               err = -1 ;
               goto out;
       }

       mr->prefix = ip4rd->prefix ;
       ipv6_addr_copy(&mr->relay_prefix, &ip4rd->relay_prefix);
       ipv6_addr_copy(&mr->relay_suffix, &ip4rd->relay_suffix);
       mr->prefixlen = ip4rd->prefixlen ;
       mr->relay_prefixlen = ip4rd->relay_prefixlen ;
       mr->relay_suffixlen = ip4rd->relay_suffixlen ;
       mr->psid_offsetlen = ip4rd->psid_offsetlen ;
       mr->eabit_len = ip4rd->eabit_len ;
       mr->entry_num = ip4rd->entry_num ;

       ++mr_kmem_alloced;
       list_add_tail(&mr->mr_list, &parm->map_list);

out:
	ip6_4rd_notify(RTM_NEW4RD,mr, dev,0);  
	write_unlock_bh(&parm->map_lock);
	return err;
}

static void
ip6_tnl_4rd_mr_delete_all(struct ip6_tnl_4rd_parm *parm, struct net_device *dev)
{
	struct ip6_tnl_4rd_map_rule *mr, *mr_rule;

	write_lock_bh(&parm->map_lock);
	list_for_each_entry_safe (mr, mr_rule, &parm->map_list, mr_list){
		ip6_tnl_4rd_mr_destroy("all", mr);
	}
	ip6_4rd_notify(RTM_DEL4RD,mr, dev ,1);
	write_unlock_bh(&parm->map_lock);

}

static int
ip6_tnl_4rd_mr_delete(__u16 entry_num , struct ip6_tnl_4rd_parm *parm, struct net_device *dev)
{
	struct ip6_tnl_4rd_map_rule *mr, *mr_rule;
	int err = -1 ;

	write_lock_bh(&parm->map_lock);
	list_for_each_entry_safe (mr, mr_rule, &parm->map_list, mr_list){
		if( mr->entry_num == entry_num ){
			printk(KERN_DEBUG "ip6_tnl_4rd_mr_delete: map rule found delete");
			ip6_tnl_4rd_mr_destroy("one", mr);
			err = 0 ;
			break;
		}
	}
	ip6_4rd_notify(RTM_DEL4RD,mr,dev,0);
	write_unlock_bh(&parm->map_lock);
	return err ;
}

static void
ip6_tnl_4rd_mr_show(struct ip6_tnl_4rd_parm *parm)
{
	struct ip6_tnl_4rd_map_rule *mr;

       printk(KERN_DEBUG "-- 4rd mapping rule list\n");
       printk(KERN_DEBUG "-- entry num = %d \n",mr_kmem_alloced);

	read_lock(&parm->map_lock);
	list_for_each_entry(mr, &parm->map_list, mr_list){
		printk(KERN_DEBUG "%03d : %03d.%03d.%03d.%03d/%02d %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x/%03d %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x/%03d eabit:%03d offset:%03d \n",
			mr->entry_num,
			(ntohl(mr->prefix) >> 24) & 0xff,
			(ntohl(mr->prefix) >> 16) & 0xff,
			(ntohl(mr->prefix) >>  8) & 0xff,
			ntohl(mr->prefix) & 0xff,
			mr->prefixlen,
			mr->relay_prefix.s6_addr[0],
			mr->relay_prefix.s6_addr[1],
			mr->relay_prefix.s6_addr[2],
			mr->relay_prefix.s6_addr[3],
			mr->relay_prefix.s6_addr[4],
			mr->relay_prefix.s6_addr[5],
			mr->relay_prefix.s6_addr[6],
			mr->relay_prefix.s6_addr[7],
			mr->relay_prefix.s6_addr[8],
			mr->relay_prefix.s6_addr[9],
			mr->relay_prefix.s6_addr[10],
			mr->relay_prefix.s6_addr[11],
			mr->relay_prefix.s6_addr[12],
			mr->relay_prefix.s6_addr[13],
			mr->relay_prefix.s6_addr[14],
			mr->relay_prefix.s6_addr[15],
			mr->relay_prefixlen,
			mr->relay_suffix.s6_addr[0],
			mr->relay_suffix.s6_addr[1],
			mr->relay_suffix.s6_addr[2],
			mr->relay_suffix.s6_addr[3],
			mr->relay_suffix.s6_addr[4],
			mr->relay_suffix.s6_addr[5],
			mr->relay_suffix.s6_addr[6],
			mr->relay_suffix.s6_addr[7],
			mr->relay_suffix.s6_addr[8],
			mr->relay_suffix.s6_addr[9],
			mr->relay_suffix.s6_addr[10],
			mr->relay_suffix.s6_addr[11],
			mr->relay_suffix.s6_addr[12],
			mr->relay_suffix.s6_addr[13],
			mr->relay_suffix.s6_addr[14],
			mr->relay_suffix.s6_addr[15],
			mr->relay_suffixlen,
			mr->eabit_len,
			mr->psid_offsetlen );
	}
	read_unlock(&parm->map_lock);
}

static int
ip6_tnl_4rd_modify_daddr(struct in6_addr *daddr6, __be32 daddr4, __be16 dport4,
		struct ip6_tnl_4rd_map_rule *mr)
{
       int i, pbw0, pbi0, pbi1;
       __u32 daddr[4];
       __u32 port_set_id = 0;
       __u32 mask;
       __u32 da = ntohl(daddr4);
       __u16 dp = ntohs(dport4);
       __u32 diaddr[4];
       int port_set_id_len = ( mr->eabit_len ) - ( 32 - mr->prefixlen ) ;

       if ( port_set_id_len < 0) {
               printk(KERN_DEBUG "ip6_tnl_4rd_modify_daddr: PSID length ERROR %d\n", port_set_id_len);
               return -1;
       }

       if ( port_set_id_len > 0) {
               mask = 0xffffffff >> (32 - port_set_id_len);
               port_set_id = ( dp >> (16 - mr->psid_offsetlen - port_set_id_len ) & mask ) ;
       }

       for (i = 0; i < 4; ++i)
               daddr[i] = ntohl(mr->relay_prefix.s6_addr32[i])
                       | ntohl(mr->relay_suffix.s6_addr32[i]);

       if( mr->prefixlen < 32 ) {
               pbw0 = mr->relay_prefixlen >> 5;
               pbi0 = mr->relay_prefixlen & 0x1f;
               daddr[pbw0] |= (da << mr->prefixlen) >> pbi0;
               pbi1 = pbi0 - mr->prefixlen;
               if (pbi1 > 0)
                       daddr[pbw0+1] |= da << (32 - pbi1);
	}
       if ( port_set_id_len > 0) {
	       pbw0 = (mr->relay_prefixlen + 32 - mr->prefixlen) >> 5;
	       pbi0 = (mr->relay_prefixlen + 32 - mr->prefixlen) & 0x1f;
	       daddr[pbw0] |= (port_set_id << (32 - port_set_id_len)) >> pbi0;
	       pbi1 = pbi0 - (32 - port_set_id_len);
	       if (pbi1 > 0)
		       daddr[pbw0+1] |= port_set_id << (32 - pbi1);
       }

       memset(diaddr, 0, sizeof(diaddr));

       diaddr[2] = ( da >> 8 ) ;
       diaddr[3] = ( da << 24 ) ;
       diaddr[3] |= ( port_set_id << 8 ) ;

       for (i = 0; i < 4; ++i)
               daddr[i] = daddr[i] | diaddr[i] ;

       for (i = 0; i < 4; ++i)
               daddr6->s6_addr32[i] = htonl(daddr[i]);

       printk(KERN_DEBUG "ip6_tnl_4rd_modify_daddr: %08x %08x %08x %08x  PSID:%04x\n",
               daddr[0], daddr[1], daddr[2], daddr[3], port_set_id);

       return 0;
}

static int
ip6_tnl_4rd_rcv_helper(struct sk_buff *skb, struct ip6_tnl *t)
{
       int err = 0;
       struct iphdr *iph;

       iph = ip_hdr(skb);

       switch (iph->protocol) {
       case IPPROTO_TCP:
       case IPPROTO_UDP:
       case IPPROTO_ICMP:
       case IPPROTO_GRE:
               break;
       default:
               err = -1;
               break;
       }

       return err;
}

static int
ip6_tnl_4rd_xmit_helper(struct sk_buff *skb, struct flowi6 *fl6,
		struct ip6_tnl *t)
{
       int err = 0;
       struct iphdr *iph, *icmpiph;
       __be16  *idp;
       struct tcphdr *tcph, *icmptcph;
       struct udphdr *udph, *icmpudph;
       struct icmphdr *icmph;
       struct gre_hdr *greh;
       __u32 mask;
       __be16 *sportp = NULL;
       __be32 daddr;
       __be16 dport;
       u8 *ptr;
       int no_dst_chg = 0;
       struct ip6_tnl_4rd_map_rule *mr,*mr_tmp;
       int mr_prefixlen ;
       int count ;

       iph = ip_hdr(skb);

       daddr = iph->daddr;
       idp = &iph->id;

       ptr = (u8 *)iph;
       ptr += iph->ihl * 4;
       switch (iph->protocol) {
       case IPPROTO_TCP:
               tcph = (struct tcphdr *)ptr;
               sportp = &tcph->source;
               dport = tcph->dest;
               break;
       case IPPROTO_UDP:
               udph = (struct udphdr *)ptr;
               sportp = &udph->source;
               dport = udph->dest;
               break;
       case IPPROTO_ICMP:
               icmph = (struct icmphdr *)ptr;
               switch (icmph->type) {
               case ICMP_DEST_UNREACH:
               case ICMP_SOURCE_QUENCH:
               case ICMP_REDIRECT:
               case ICMP_TIME_EXCEEDED:
               case ICMP_PARAMETERPROB:
                       ptr = (u8 *)icmph;
                       ptr += sizeof(struct icmphdr);
                       icmpiph = (struct iphdr*)ptr;
                       if (ntohs(iph->tot_len) < icmpiph->ihl * 4 + 12) {
                               err = -1;
                               goto out;
                       }
                       daddr = icmpiph->saddr;
                       ptr += icmpiph->ihl * 4;
                       switch (icmpiph->protocol) {
                       case IPPROTO_TCP:
                               icmptcph = (struct tcphdr *)ptr;
                               sportp = &icmptcph->dest;
                               dport = icmptcph->source;
                               break;
                       case IPPROTO_UDP:
                               icmpudph = (struct udphdr *)ptr;
                               sportp = &icmpudph->dest;
                               dport = icmpudph->source;
                               break;
                       default:
                               err = -1;
                               goto out;
                       }
                       break;
               default:
                       no_dst_chg = 1;
                       break;
               }
               break;
       case IPPROTO_GRE:
               greh = (struct gre_hdr *)ptr;
               if(greh->protocol != GRE_PROTOCOL_PPTP){
                       err = -1;
                       goto out;
               }
               no_dst_chg = 1;
               break;
       default:
               err = -1;
               goto out;
       }

       if ( no_dst_chg == 0 ){

               count = 0;
               mr_prefixlen = 0;

               read_lock(&t->ip4rd.map_lock);
               list_for_each_entry (mr, &t->ip4rd.map_list, mr_list){
                       mask = 0xffffffff << (32 - mr->prefixlen) ;
                       if( (htonl(daddr) & mask ) == htonl( mr->prefix) ) {
                               if ( mr->prefixlen >= mr_prefixlen ){
                                       mr_prefixlen = mr->prefixlen ;
                                       mr_tmp = mr;
                                       count++;
                               }
                       }
               }

               if (count){
                       err = ip6_tnl_4rd_modify_daddr(&fl6->daddr, daddr, dport, mr_tmp );
                       if (err){
                                       read_unlock(&t->ip4rd.map_lock);
                                       goto out;
                       }
               }
               read_unlock(&t->ip4rd.map_lock);

               if(sportp && idp){
                       *idp=*sportp;
               }
       }

       iph->check = 0;
       iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

       skb->local_df = 1;

out:
	return err;
}

static void
ip6_tnl_4rd_update_parms(struct ip6_tnl *t)
{
	int pbw0, pbi0, pbi1;
	__u32 d;

	t->ip4rd.port_set_id_len = t->ip4rd.relay_suffixlen
				- t->ip4rd.relay_prefixlen
				- (32 - t->ip4rd.prefixlen);
	pbw0 = (t->ip4rd.relay_suffixlen - t->ip4rd.port_set_id_len) >> 5;
	pbi0 = (t->ip4rd.relay_suffixlen - t->ip4rd.port_set_id_len) & 0x1f;
	d = (ntohl(t->parms.laddr.s6_addr32[pbw0]) << pbi0)
		>> (32 - t->ip4rd.port_set_id_len);
	pbi1 = pbi0 - (32 - t->ip4rd.port_set_id_len);

	if (pbi1 > 0)
		d |= ntohl(t->parms.laddr.s6_addr32[pbw0+1]) >> (32 - pbi1);
	t->ip4rd.port_set_id = d;

	t->ip4rd.laddr4 = t->ip4rd.prefix;
	pbw0 = t->ip4rd.relay_prefixlen >> 5;
	pbi0 = t->ip4rd.relay_prefixlen & 0x1f;
	d = (ntohl(t->parms.laddr.s6_addr32[pbw0]) << pbi0)
		>> t->ip4rd.prefixlen;
	pbi1 = pbi0 - t->ip4rd.prefixlen;
	if (pbi1 > 0)
		d |= ntohl(t->parms.laddr.s6_addr32[pbw0+1]) >> (32 - pbi1);
	t->ip4rd.laddr4 |= htonl(d);
	if (t->ip4rd.port_set_id_len < 0) {
		d = ntohl(t->ip4rd.laddr4);
		d &= 0xffffffff << -t->ip4rd.port_set_id_len;
		t->ip4rd.laddr4 = htonl(d);
	}

}
#endif

static inline struct dst_entry *ip6_tnl_dst_check(struct ip6_tnl *t)
{
	struct dst_entry *dst = t->dst_cache;

	if (dst && dst->obsolete &&
	    dst->ops->check(dst, t->dst_cookie) == NULL) {
		t->dst_cache = NULL;
		dst_release(dst);
		return NULL;
	}

	return dst;
}

static inline void ip6_tnl_dst_reset(struct ip6_tnl *t)
{
	dst_release(t->dst_cache);
	t->dst_cache = NULL;
}

static inline void ip6_tnl_dst_store(struct ip6_tnl *t, struct dst_entry *dst)
{
	struct rt6_info *rt = (struct rt6_info *) dst;
	t->dst_cookie = rt->rt6i_node ? rt->rt6i_node->fn_sernum : 0;
	dst_release(t->dst_cache);
	t->dst_cache = dst;
}

#if !defined(MY_ABC_HERE)
#define for_each_ip6_tunnel_rcu(start) \
	for (t = rcu_dereference(start); t; t = rcu_dereference(t->next))
#endif

static struct ip6_tnl *
ip6_tnl_lookup(struct net *net, const struct in6_addr *remote, const struct in6_addr *local)
{
#if defined(MY_ABC_HERE)
 
#else
	unsigned int h0 = HASH(remote);
#endif
	unsigned int h1 = HASH(local);
	struct ip6_tnl *t;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

#if defined(MY_ABC_HERE)
	for_each_ip6_tunnel_rcu(ip6n->tnls_r_l[h1]) {
#else
	for_each_ip6_tunnel_rcu(ip6n->tnls_r_l[h0 ^ h1]) {
#endif
		if (ipv6_addr_equal(local, &t->parms.laddr) &&
		    ipv6_addr_equal(remote, &t->parms.raddr) &&
		    (t->dev->flags & IFF_UP))
			return t;
#if defined(MY_ABC_HERE)
                if (t->ip4rd.prefix &&
                   ipv6_addr_equal(local, &t->parms.laddr) &&
                 
                   (t->dev->flags & IFF_UP))
                       return t;
#endif
	}
	t = rcu_dereference(ip6n->tnls_wc[0]);
	if (t && (t->dev->flags & IFF_UP))
		return t;

	return NULL;
}

static struct ip6_tnl __rcu **
ip6_tnl_bucket(struct ip6_tnl_net *ip6n, const struct ip6_tnl_parm *p)
{
#if !defined(MY_ABC_HERE)
	const struct in6_addr *remote = &p->raddr;
#endif
	const struct in6_addr *local = &p->laddr;
	unsigned h = 0;
	int prio = 0;

#if defined(MY_ABC_HERE)
	if (!ipv6_addr_any(local)) {        
#else
	if (!ipv6_addr_any(remote) || !ipv6_addr_any(local)) {
#endif
		prio = 1;
#if defined(MY_ABC_HERE)
		h = HASH(local);	
#else
		h = HASH(remote) ^ HASH(local);
#endif
	}
	return &ip6n->tnls[prio][h];
}

static void
ip6_tnl_link(struct ip6_tnl_net *ip6n, struct ip6_tnl *t)
{
	struct ip6_tnl __rcu **tp = ip6_tnl_bucket(ip6n, &t->parms);

	rcu_assign_pointer(t->next , rtnl_dereference(*tp));
	rcu_assign_pointer(*tp, t);
}

static void
ip6_tnl_unlink(struct ip6_tnl_net *ip6n, struct ip6_tnl *t)
{
	struct ip6_tnl __rcu **tp;
	struct ip6_tnl *iter;

	for (tp = ip6_tnl_bucket(ip6n, &t->parms);
	     (iter = rtnl_dereference(*tp)) != NULL;
	     tp = &iter->next) {
		if (t == iter) {
			rcu_assign_pointer(*tp, t->next);
			break;
		}
	}
}

static void ip6_dev_free(struct net_device *dev)
{
	free_percpu(dev->tstats);
	free_netdev(dev);
}

static struct ip6_tnl *ip6_tnl_create(struct net *net, struct ip6_tnl_parm *p)
{
	struct net_device *dev;
	struct ip6_tnl *t;
	char name[IFNAMSIZ];
	int err;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	if (p->name[0])
		strlcpy(name, p->name, IFNAMSIZ);
	else
		sprintf(name, "ip6tnl%%d");

	dev = alloc_netdev(sizeof (*t), name, ip6_tnl_dev_setup);
	if (dev == NULL)
		goto failed;

	dev_net_set(dev, net);

	t = netdev_priv(dev);
	t->parms = *p;
	err = ip6_tnl_dev_init(dev);
	if (err < 0)
		goto failed_free;

	if ((err = register_netdevice(dev)) < 0)
		goto failed_free;

	strcpy(t->parms.name, dev->name);

#if defined(MY_ABC_HERE)
	rwlock_init(&t->ip4rd.map_lock);
	INIT_LIST_HEAD(&t->ip4rd.map_list); 
#endif

	dev_hold(dev);
	ip6_tnl_link(ip6n, t);
	return t;

failed_free:
	ip6_dev_free(dev);
failed:
	return NULL;
}

static struct ip6_tnl *ip6_tnl_locate(struct net *net,
		struct ip6_tnl_parm *p, int create)
{
	const struct in6_addr *remote = &p->raddr;
	const struct in6_addr *local = &p->laddr;
	struct ip6_tnl __rcu **tp;
	struct ip6_tnl *t;
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	for (tp = ip6_tnl_bucket(ip6n, p);
	     (t = rtnl_dereference(*tp)) != NULL;
	     tp = &t->next) {
		if (ipv6_addr_equal(local, &t->parms.laddr) &&
		    ipv6_addr_equal(remote, &t->parms.raddr))
			return t;
	}
	if (!create)
		return NULL;
	return ip6_tnl_create(net, p);
}

static void
ip6_tnl_dev_uninit(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	if (dev == ip6n->fb_tnl_dev)
		RCU_INIT_POINTER(ip6n->tnls_wc[0], NULL);
	else
		ip6_tnl_unlink(ip6n, t);
	ip6_tnl_dst_reset(t);
	dev_put(dev);
}

static __u16
parse_tlv_tnl_enc_lim(struct sk_buff *skb, __u8 * raw)
{
	const struct ipv6hdr *ipv6h = (const struct ipv6hdr *) raw;
	__u8 nexthdr = ipv6h->nexthdr;
	__u16 off = sizeof (*ipv6h);

	while (ipv6_ext_hdr(nexthdr) && nexthdr != NEXTHDR_NONE) {
		__u16 optlen = 0;
		struct ipv6_opt_hdr *hdr;
		if (raw + off + sizeof (*hdr) > skb->data &&
		    !pskb_may_pull(skb, raw - skb->data + off + sizeof (*hdr)))
			break;

		hdr = (struct ipv6_opt_hdr *) (raw + off);
		if (nexthdr == NEXTHDR_FRAGMENT) {
			struct frag_hdr *frag_hdr = (struct frag_hdr *) hdr;
			if (frag_hdr->frag_off)
				break;
			optlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH) {
			optlen = (hdr->hdrlen + 2) << 2;
		} else {
			optlen = ipv6_optlen(hdr);
		}
		if (nexthdr == NEXTHDR_DEST) {
			__u16 i = off + 2;
			while (1) {
				struct ipv6_tlv_tnl_enc_lim *tel;

				if (i + sizeof (*tel) > off + optlen)
					break;

				tel = (struct ipv6_tlv_tnl_enc_lim *) &raw[i];
				 
				if (tel->type == IPV6_TLV_TNL_ENCAP_LIMIT &&
				    tel->length == 1)
					return i;
				 
				if (tel->type)
					i += tel->length + 2;
				else
					i++;
			}
		}
		nexthdr = hdr->nexthdr;
		off += optlen;
	}
	return 0;
}

static int
ip6_tnl_err(struct sk_buff *skb, __u8 ipproto, struct inet6_skb_parm *opt,
	    u8 *type, u8 *code, int *msg, __u32 *info, int offset)
{
	const struct ipv6hdr *ipv6h = (const struct ipv6hdr *) skb->data;
	struct ip6_tnl *t;
	int rel_msg = 0;
	u8 rel_type = ICMPV6_DEST_UNREACH;
	u8 rel_code = ICMPV6_ADDR_UNREACH;
	__u32 rel_info = 0;
	__u16 len;
	int err = -ENOENT;

	rcu_read_lock();
	if ((t = ip6_tnl_lookup(dev_net(skb->dev), &ipv6h->daddr,
					&ipv6h->saddr)) == NULL)
		goto out;

	if (t->parms.proto != ipproto && t->parms.proto != 0)
		goto out;

	err = 0;

	switch (*type) {
		__u32 teli;
		struct ipv6_tlv_tnl_enc_lim *tel;
		__u32 mtu;
	case ICMPV6_DEST_UNREACH:
		if (net_ratelimit())
			printk(KERN_WARNING
			       "%s: Path to destination invalid "
			       "or inactive!\n", t->parms.name);
		rel_msg = 1;
		break;
	case ICMPV6_TIME_EXCEED:
		if ((*code) == ICMPV6_EXC_HOPLIMIT) {
			if (net_ratelimit())
				printk(KERN_WARNING
				       "%s: Too small hop limit or "
				       "routing loop in tunnel!\n",
				       t->parms.name);
			rel_msg = 1;
		}
		break;
	case ICMPV6_PARAMPROB:
		teli = 0;
		if ((*code) == ICMPV6_HDR_FIELD)
			teli = parse_tlv_tnl_enc_lim(skb, skb->data);

		if (teli && teli == *info - 2) {
			tel = (struct ipv6_tlv_tnl_enc_lim *) &skb->data[teli];
			if (tel->encap_limit == 0) {
				if (net_ratelimit())
					printk(KERN_WARNING
					       "%s: Too small encapsulation "
					       "limit or routing loop in "
					       "tunnel!\n", t->parms.name);
				rel_msg = 1;
			}
		} else if (net_ratelimit()) {
			printk(KERN_WARNING
			       "%s: Recipient unable to parse tunneled "
			       "packet!\n ", t->parms.name);
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		mtu = *info - offset;
		if (mtu < IPV6_MIN_MTU)
			mtu = IPV6_MIN_MTU;
		t->dev->mtu = mtu;

		if ((len = sizeof (*ipv6h) + ntohs(ipv6h->payload_len)) > mtu) {
			rel_type = ICMPV6_PKT_TOOBIG;
			rel_code = 0;
			rel_info = mtu;
			rel_msg = 1;
		}
		break;
	}

	*type = rel_type;
	*code = rel_code;
	*info = rel_info;
	*msg = rel_msg;

out:
	rcu_read_unlock();
	return err;
}

static int
ip4ip6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
	   u8 type, u8 code, int offset, __be32 info)
{
	int rel_msg = 0;
	u8 rel_type = type;
	u8 rel_code = code;
	__u32 rel_info = ntohl(info);
	int err;
	struct sk_buff *skb2;
	const struct iphdr *eiph;
	struct rtable *rt;
	struct flowi4 fl4;

	err = ip6_tnl_err(skb, IPPROTO_IPIP, opt, &rel_type, &rel_code,
			  &rel_msg, &rel_info, offset);
	if (err < 0)
		return err;

	if (rel_msg == 0)
		return 0;

	switch (rel_type) {
	case ICMPV6_DEST_UNREACH:
		if (rel_code != ICMPV6_ADDR_UNREACH)
			return 0;
		rel_type = ICMP_DEST_UNREACH;
		rel_code = ICMP_HOST_UNREACH;
		break;
	case ICMPV6_PKT_TOOBIG:
		if (rel_code != 0)
			return 0;
		rel_type = ICMP_DEST_UNREACH;
		rel_code = ICMP_FRAG_NEEDED;
		break;
	default:
		return 0;
	}

	if (!pskb_may_pull(skb, offset + sizeof(struct iphdr)))
		return 0;

	skb2 = skb_clone(skb, GFP_ATOMIC);
	if (!skb2)
		return 0;

	skb_dst_drop(skb2);

	skb_pull(skb2, offset);
	skb_reset_network_header(skb2);
	eiph = ip_hdr(skb2);

	rt = ip_route_output_ports(dev_net(skb->dev), &fl4, NULL,
				   eiph->saddr, 0,
				   0, 0,
				   IPPROTO_IPIP, RT_TOS(eiph->tos), 0);
	if (IS_ERR(rt))
		goto out;

	skb2->dev = rt->dst.dev;

	if (rt->rt_flags & RTCF_LOCAL) {
		ip_rt_put(rt);
		rt = NULL;
		rt = ip_route_output_ports(dev_net(skb->dev), &fl4, NULL,
					   eiph->daddr, eiph->saddr,
					   0, 0,
					   IPPROTO_IPIP,
					   RT_TOS(eiph->tos), 0);
		if (IS_ERR(rt) ||
		    rt->dst.dev->type != ARPHRD_TUNNEL) {
			if (!IS_ERR(rt))
				ip_rt_put(rt);
			goto out;
		}
		skb_dst_set(skb2, &rt->dst);
	} else {
		ip_rt_put(rt);
		if (ip_route_input(skb2, eiph->daddr, eiph->saddr, eiph->tos,
				   skb2->dev) ||
		    skb_dst(skb2)->dev->type != ARPHRD_TUNNEL)
			goto out;
	}

	if (rel_type == ICMP_DEST_UNREACH && rel_code == ICMP_FRAG_NEEDED) {
		if (rel_info > dst_mtu(skb_dst(skb2)))
			goto out;

		skb_dst(skb2)->ops->update_pmtu(skb_dst(skb2), rel_info);
	}

	icmp_send(skb2, rel_type, rel_code, htonl(rel_info));

out:
	kfree_skb(skb2);
	return 0;
}

static int
ip6ip6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
	   u8 type, u8 code, int offset, __be32 info)
{
	int rel_msg = 0;
	u8 rel_type = type;
	u8 rel_code = code;
	__u32 rel_info = ntohl(info);
	int err;

	err = ip6_tnl_err(skb, IPPROTO_IPV6, opt, &rel_type, &rel_code,
			  &rel_msg, &rel_info, offset);
	if (err < 0)
		return err;

	if (rel_msg && pskb_may_pull(skb, offset + sizeof(struct ipv6hdr))) {
		struct rt6_info *rt;
		struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);

		if (!skb2)
			return 0;

		skb_dst_drop(skb2);
		skb_pull(skb2, offset);
		skb_reset_network_header(skb2);

		rt = rt6_lookup(dev_net(skb->dev), &ipv6_hdr(skb2)->saddr,
				NULL, 0, 0);

		if (rt && rt->rt6i_dev)
			skb2->dev = rt->rt6i_dev;

		icmpv6_send(skb2, rel_type, rel_code, rel_info);

		if (rt)
			dst_release(&rt->dst);

		kfree_skb(skb2);
	}

	return 0;
}

static void ip4ip6_dscp_ecn_decapsulate(const struct ip6_tnl *t,
					const struct ipv6hdr *ipv6h,
					struct sk_buff *skb)
{
	__u8 dsfield = ipv6_get_dsfield(ipv6h) & ~INET_ECN_MASK;

	if (t->parms.flags & IP6_TNL_F_RCV_DSCP_COPY)
		ipv4_change_dsfield(ip_hdr(skb), INET_ECN_MASK, dsfield);

	if (INET_ECN_is_ce(dsfield))
		IP_ECN_set_ce(ip_hdr(skb));
}

static void ip6ip6_dscp_ecn_decapsulate(const struct ip6_tnl *t,
					const struct ipv6hdr *ipv6h,
					struct sk_buff *skb)
{
	if (t->parms.flags & IP6_TNL_F_RCV_DSCP_COPY)
		ipv6_copy_dscp(ipv6_get_dsfield(ipv6h), ipv6_hdr(skb));

	if (INET_ECN_is_ce(ipv6_get_dsfield(ipv6h)))
		IP6_ECN_set_ce(ipv6_hdr(skb));
}

static inline int ip6_tnl_rcv_ctl(struct ip6_tnl *t)
{
	struct ip6_tnl_parm *p = &t->parms;
	int ret = 0;
	struct net *net = dev_net(t->dev);

	if (p->flags & IP6_TNL_F_CAP_RCV) {
		struct net_device *ldev = NULL;

		if (p->link)
			ldev = dev_get_by_index_rcu(net, p->link);

		if ((ipv6_addr_is_multicast(&p->laddr) ||
		     likely(ipv6_chk_addr(net, &p->laddr, ldev, 0))) &&
		    likely(!ipv6_chk_addr(net, &p->raddr, NULL, 0)))
			ret = 1;

	}
	return ret;
}

static int ip6_tnl_rcv(struct sk_buff *skb, __u16 protocol,
		       __u8 ipproto,
		       void (*dscp_ecn_decapsulate)(const struct ip6_tnl *t,
						    const struct ipv6hdr *ipv6h,
						    struct sk_buff *skb))
{
	struct ip6_tnl *t;
	const struct ipv6hdr *ipv6h = ipv6_hdr(skb);

	rcu_read_lock();

	if ((t = ip6_tnl_lookup(dev_net(skb->dev), &ipv6h->saddr,
					&ipv6h->daddr)) != NULL) {
		struct pcpu_tstats *tstats;

		if (t->parms.proto != ipproto && t->parms.proto != 0) {
			rcu_read_unlock();
			goto discard;
		}

		if (!xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb)) {
			rcu_read_unlock();
			goto discard;
		}

		if (!ip6_tnl_rcv_ctl(t)) {
			t->dev->stats.rx_dropped++;
			rcu_read_unlock();
			goto discard;
		}
		secpath_reset(skb);
		skb->mac_header = skb->network_header;
		skb_reset_network_header(skb);
		skb->protocol = htons(protocol);
		skb->pkt_type = PACKET_HOST;
		memset(skb->cb, 0, sizeof(struct inet6_skb_parm));

		tstats = this_cpu_ptr(t->dev->tstats);
		tstats->rx_packets++;
		tstats->rx_bytes += skb->len;

		__skb_tunnel_rx(skb, t->dev);

		dscp_ecn_decapsulate(t, ipv6h, skb);
#if defined(MY_ABC_HERE)
                if (ip6_tnl_4rd_rcv_helper(skb, t)) {
                        rcu_read_unlock();
                        goto discard;
                }
#endif

		netif_rx(skb);

		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	return 1;

discard:
	kfree_skb(skb);
	return 0;
}

static int ip4ip6_rcv(struct sk_buff *skb)
{
	return ip6_tnl_rcv(skb, ETH_P_IP, IPPROTO_IPIP,
			   ip4ip6_dscp_ecn_decapsulate);
}

static int ip6ip6_rcv(struct sk_buff *skb)
{
	return ip6_tnl_rcv(skb, ETH_P_IPV6, IPPROTO_IPV6,
			   ip6ip6_dscp_ecn_decapsulate);
}

struct ipv6_tel_txoption {
	struct ipv6_txoptions ops;
	__u8 dst_opt[8];
};

static void init_tel_txopt(struct ipv6_tel_txoption *opt, __u8 encap_limit)
{
	memset(opt, 0, sizeof(struct ipv6_tel_txoption));

	opt->dst_opt[2] = IPV6_TLV_TNL_ENCAP_LIMIT;
	opt->dst_opt[3] = 1;
	opt->dst_opt[4] = encap_limit;
	opt->dst_opt[5] = IPV6_TLV_PADN;
	opt->dst_opt[6] = 1;

	opt->ops.dst0opt = (struct ipv6_opt_hdr *) opt->dst_opt;
	opt->ops.opt_nflen = 8;
}

static inline int
ip6_tnl_addr_conflict(const struct ip6_tnl *t, const struct ipv6hdr *hdr)
{
	return ipv6_addr_equal(&t->parms.raddr, &hdr->saddr);
}

static inline int ip6_tnl_xmit_ctl(struct ip6_tnl *t)
{
	struct ip6_tnl_parm *p = &t->parms;
	int ret = 0;
	struct net *net = dev_net(t->dev);

	if (p->flags & IP6_TNL_F_CAP_XMIT) {
		struct net_device *ldev = NULL;

		rcu_read_lock();
		if (p->link)
			ldev = dev_get_by_index_rcu(net, p->link);

		if (unlikely(!ipv6_chk_addr(net, &p->laddr, ldev, 0)))
			printk(KERN_WARNING
			       "%s xmit: Local address not yet configured!\n",
			       p->name);
		else if (!ipv6_addr_is_multicast(&p->raddr) &&
			 unlikely(ipv6_chk_addr(net, &p->raddr, NULL, 0)))
			printk(KERN_WARNING
			       "%s xmit: Routing loop! "
			       "Remote address found on this node!\n",
			       p->name);
		else
			ret = 1;
		rcu_read_unlock();
	}
	return ret;
}
 
static int ip6_tnl_xmit2(struct sk_buff *skb,
			 struct net_device *dev,
			 __u8 dsfield,
			 struct flowi6 *fl6,
			 int encap_limit,
			 __u32 *pmtu)
{
	struct net *net = dev_net(dev);
	struct ip6_tnl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct ipv6_tel_txoption opt;
	struct dst_entry *dst = NULL, *ndst = NULL;
	struct net_device *tdev;
	int mtu;
	unsigned int max_headroom = sizeof(struct ipv6hdr);
	u8 proto;
	int err = -1;
	int pkt_len;
#if defined(MY_ABC_HERE)
	__u8 hop_limit;    
#endif

	if (!fl6->flowi6_mark)
		dst = ip6_tnl_dst_check(t);
	if (!dst) {
		ndst = ip6_route_output(net, NULL, fl6);

		if (ndst->error)
			goto tx_err_link_failure;
		ndst = xfrm_lookup(net, ndst, flowi6_to_flowi(fl6), NULL, 0);
		if (IS_ERR(ndst)) {
			err = PTR_ERR(ndst);
			ndst = NULL;
			goto tx_err_link_failure;
		}
		dst = ndst;
	}

	tdev = dst->dev;

	if (tdev == dev) {
		stats->collisions++;
		if (net_ratelimit())
			printk(KERN_WARNING
			       "%s: Local routing loop detected!\n",
			       t->parms.name);
		goto tx_err_dst_release;
	}
	mtu = dst_mtu(dst) - sizeof (*ipv6h);
	if (encap_limit >= 0) {
		max_headroom += 8;
		mtu -= 8;
	}
	if (mtu < IPV6_MIN_MTU)
		mtu = IPV6_MIN_MTU;
	if (skb_dst(skb))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), mtu);
#if defined(MY_ABC_HERE)
        if (!t->ip4rd.prefix) {     
#endif
	if (skb->len > mtu) {
		*pmtu = mtu;
		err = -EMSGSIZE;
		goto tx_err_dst_release;
	}
#if defined(MY_ABC_HERE)
        }                        

	if (t->ip4rd.prefix) {
		struct iphdr *iph;
		iph = ip_hdr(skb);
		hop_limit = iph->ttl;
	}
	else {
		hop_limit = t->parms.hop_limit;
	}
#endif

	max_headroom += LL_RESERVED_SPACE(tdev);

	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *new_skb;

		if (!(new_skb = skb_realloc_headroom(skb, max_headroom)))
			goto tx_err_dst_release;

		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		kfree_skb(skb);
		skb = new_skb;
	}
	skb_dst_drop(skb);
	if (fl6->flowi6_mark) {
		skb_dst_set(skb, dst);
		ndst = NULL;
	} else {
		skb_dst_set_noref(skb, dst);
	}
	skb->transport_header = skb->network_header;

	proto = fl6->flowi6_proto;
	if (encap_limit >= 0) {
		init_tel_txopt(&opt, encap_limit);
		ipv6_push_nfrag_opts(skb, &opt.ops, &proto, NULL);
	}
	skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	ipv6h = ipv6_hdr(skb);
	*(__be32*)ipv6h = fl6->flowlabel | htonl(0x60000000);
	dsfield = INET_ECN_encapsulate(0, dsfield);
	ipv6_change_dsfield(ipv6h, ~INET_ECN_MASK, dsfield);
#if defined(MY_ABC_HERE)
	ipv6h->hop_limit = hop_limit;
#else
	ipv6h->hop_limit = t->parms.hop_limit;
#endif
	ipv6h->nexthdr = proto;
	ipv6_addr_copy(&ipv6h->saddr, &fl6->saddr);
	ipv6_addr_copy(&ipv6h->daddr, &fl6->daddr);
	nf_reset(skb);
	pkt_len = skb->len;
	err = ip6_local_out(skb);

	if (net_xmit_eval(err) == 0) {
		struct pcpu_tstats *tstats = this_cpu_ptr(t->dev->tstats);

		tstats->tx_bytes += pkt_len;
		tstats->tx_packets++;
	} else {
		stats->tx_errors++;
		stats->tx_aborted_errors++;
	}
	if (ndst)
		ip6_tnl_dst_store(t, ndst);
	return 0;
tx_err_link_failure:
	stats->tx_carrier_errors++;
	dst_link_failure(skb);
tx_err_dst_release:
	dst_release(ndst);
	return err;
}

static inline int
ip4ip6_tnl_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	const struct iphdr  *iph = ip_hdr(skb);
	int encap_limit = -1;
	struct flowi6 fl6;
	__u8 dsfield;
	__u32 mtu;
	int err;

	if ((t->parms.proto != IPPROTO_IPIP && t->parms.proto != 0) ||
	    !ip6_tnl_xmit_ctl(t))
		return -1;

	if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
		encap_limit = t->parms.encap_limit;

	memcpy(&fl6, &t->fl.u.ip6, sizeof (fl6));
	fl6.flowi6_proto = IPPROTO_IPIP;

	dsfield = ipv4_get_dsfield(iph);

	if (t->parms.flags & IP6_TNL_F_USE_ORIG_TCLASS)
		fl6.flowlabel |= htonl((__u32)iph->tos << IPV6_TCLASS_SHIFT)
					  & IPV6_TCLASS_MASK;
	if (t->parms.flags & IP6_TNL_F_USE_ORIG_FWMARK)
		fl6.flowi6_mark = skb->mark;

#if defined(MY_ABC_HERE)
        if (t->ip4rd.prefix && ip6_tnl_4rd_xmit_helper(skb, &fl6, t))
                return -1;
#endif

	err = ip6_tnl_xmit2(skb, dev, dsfield, &fl6, encap_limit, &mtu);
	if (err != 0) {
		 
		if (err == -EMSGSIZE)
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				  htonl(mtu));
		return -1;
	}

	return 0;
}

static inline int
ip6ip6_tnl_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	int encap_limit = -1;
	__u16 offset;
	struct flowi6 fl6;
	__u8 dsfield;
	__u32 mtu;
	int err;

	if ((t->parms.proto != IPPROTO_IPV6 && t->parms.proto != 0) ||
	    !ip6_tnl_xmit_ctl(t) || ip6_tnl_addr_conflict(t, ipv6h))
		return -1;

	offset = parse_tlv_tnl_enc_lim(skb, skb_network_header(skb));
	if (offset > 0) {
		struct ipv6_tlv_tnl_enc_lim *tel;
		tel = (struct ipv6_tlv_tnl_enc_lim *)&skb_network_header(skb)[offset];
		if (tel->encap_limit == 0) {
			icmpv6_send(skb, ICMPV6_PARAMPROB,
				    ICMPV6_HDR_FIELD, offset + 2);
			return -1;
		}
		encap_limit = tel->encap_limit - 1;
	} else if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
		encap_limit = t->parms.encap_limit;

	memcpy(&fl6, &t->fl.u.ip6, sizeof (fl6));
	fl6.flowi6_proto = IPPROTO_IPV6;

	dsfield = ipv6_get_dsfield(ipv6h);
	if (t->parms.flags & IP6_TNL_F_USE_ORIG_TCLASS)
		fl6.flowlabel |= (*(__be32 *) ipv6h & IPV6_TCLASS_MASK);
	if (t->parms.flags & IP6_TNL_F_USE_ORIG_FLOWLABEL)
		fl6.flowlabel |= (*(__be32 *) ipv6h & IPV6_FLOWLABEL_MASK);
	if (t->parms.flags & IP6_TNL_F_USE_ORIG_FWMARK)
		fl6.flowi6_mark = skb->mark;

	err = ip6_tnl_xmit2(skb, dev, dsfield, &fl6, encap_limit, &mtu);
	if (err != 0) {
		if (err == -EMSGSIZE)
			icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
		return -1;
	}

	return 0;
}

static netdev_tx_t
ip6_tnl_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net_device_stats *stats = &t->dev->stats;
	int ret;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
#if defined(MY_ABC_HERE)
                if (t->ip4rd.prefix && ip_defrag(skb, IP_DEFRAG_IP6_TNL_4RD))
                        return NETDEV_TX_OK;
#endif
		ret = ip4ip6_tnl_xmit(skb, dev);
		break;
	case htons(ETH_P_IPV6):
		ret = ip6ip6_tnl_xmit(skb, dev);
		break;
	default:
		goto tx_err;
	}

	if (ret < 0)
		goto tx_err;

	return NETDEV_TX_OK;

tx_err:
	stats->tx_errors++;
	stats->tx_dropped++;
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void ip6_tnl_set_cap(struct ip6_tnl *t)
{
	struct ip6_tnl_parm *p = &t->parms;
	int ltype = ipv6_addr_type(&p->laddr);
	int rtype = ipv6_addr_type(&p->raddr);

	p->flags &= ~(IP6_TNL_F_CAP_XMIT|IP6_TNL_F_CAP_RCV);

	if (ltype & (IPV6_ADDR_UNICAST|IPV6_ADDR_MULTICAST) &&
	    rtype & (IPV6_ADDR_UNICAST|IPV6_ADDR_MULTICAST) &&
	    !((ltype|rtype) & IPV6_ADDR_LOOPBACK) &&
	    (!((ltype|rtype) & IPV6_ADDR_LINKLOCAL) || p->link)) {
		if (ltype&IPV6_ADDR_UNICAST)
			p->flags |= IP6_TNL_F_CAP_XMIT;
		if (rtype&IPV6_ADDR_UNICAST)
			p->flags |= IP6_TNL_F_CAP_RCV;
	}

#if defined(MY_ABC_HERE)
        if (t->ip4rd.prefix) {
                p->flags |= IP6_TNL_F_CAP_XMIT;
                p->flags |= IP6_TNL_F_CAP_RCV;
        }
#endif
}

static void ip6_tnl_link_config(struct ip6_tnl *t)
{
	struct net_device *dev = t->dev;
	struct ip6_tnl_parm *p = &t->parms;
	struct flowi6 *fl6 = &t->fl.u.ip6;

	memcpy(dev->dev_addr, &p->laddr, sizeof(struct in6_addr));
	memcpy(dev->broadcast, &p->raddr, sizeof(struct in6_addr));

	ipv6_addr_copy(&fl6->saddr, &p->laddr);
	ipv6_addr_copy(&fl6->daddr, &p->raddr);
	fl6->flowi6_oif = p->link;
	fl6->flowlabel = 0;

	if (!(p->flags&IP6_TNL_F_USE_ORIG_TCLASS))
		fl6->flowlabel |= IPV6_TCLASS_MASK & p->flowinfo;
	if (!(p->flags&IP6_TNL_F_USE_ORIG_FLOWLABEL))
		fl6->flowlabel |= IPV6_FLOWLABEL_MASK & p->flowinfo;

	ip6_tnl_set_cap(t);

	if (p->flags&IP6_TNL_F_CAP_XMIT && p->flags&IP6_TNL_F_CAP_RCV)
		dev->flags |= IFF_POINTOPOINT;
	else
		dev->flags &= ~IFF_POINTOPOINT;

	dev->iflink = p->link;

	if (p->flags & IP6_TNL_F_CAP_XMIT) {
		int strict = (ipv6_addr_type(&p->raddr) &
			      (IPV6_ADDR_MULTICAST|IPV6_ADDR_LINKLOCAL));

		struct rt6_info *rt = rt6_lookup(dev_net(dev),
						 &p->raddr, &p->laddr,
						 p->link, strict);

		if (rt == NULL)
			return;

		if (rt->rt6i_dev) {
			dev->hard_header_len = rt->rt6i_dev->hard_header_len +
				sizeof (struct ipv6hdr);

			dev->mtu = rt->rt6i_dev->mtu - sizeof (struct ipv6hdr);
			if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
				dev->mtu-=8;

			if (dev->mtu < IPV6_MIN_MTU)
				dev->mtu = IPV6_MIN_MTU;
		}
		dst_release(&rt->dst);
	}
}

static int
ip6_tnl_change(struct ip6_tnl *t, struct ip6_tnl_parm *p)
{
	ipv6_addr_copy(&t->parms.laddr, &p->laddr);
	ipv6_addr_copy(&t->parms.raddr, &p->raddr);
	t->parms.flags = p->flags;
	t->parms.hop_limit = p->hop_limit;
	t->parms.encap_limit = p->encap_limit;
	t->parms.flowinfo = p->flowinfo;
	t->parms.link = p->link;
	t->parms.proto = p->proto;
#if defined(MY_ABC_HERE)
        ip6_tnl_4rd_update_parms(t);        
#endif
	ip6_tnl_dst_reset(t);
	ip6_tnl_link_config(t);
	return 0;
}

static int
ip6_tnl_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int err = 0;
	struct ip6_tnl_parm p;
	struct ip6_tnl *t = NULL;
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
#if defined(MY_ABC_HERE)
        struct ip6_tnl_4rd ip4rd, *ip4rdp;  
        struct ip6_tnl_4rd_map_rule *mr;   
#endif

	switch (cmd) {
	case SIOCGETTUNNEL:
		if (dev == ip6n->fb_tnl_dev) {
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p))) {
				err = -EFAULT;
				break;
			}
			t = ip6_tnl_locate(net, &p, 0);
		}
		if (t == NULL)
			t = netdev_priv(dev);
		memcpy(&p, &t->parms, sizeof (p));
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof (p))) {
			err = -EFAULT;
		}
		break;
	case SIOCADDTUNNEL:
	case SIOCCHGTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			break;
		err = -EFAULT;
		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p)))
			break;
		err = -EINVAL;
		if (p.proto != IPPROTO_IPV6 && p.proto != IPPROTO_IPIP &&
		    p.proto != 0)
			break;
		t = ip6_tnl_locate(net, &p, cmd == SIOCADDTUNNEL);
		if (dev != ip6n->fb_tnl_dev && cmd == SIOCCHGTUNNEL) {
			if (t != NULL) {
				if (t->dev != dev) {
					err = -EEXIST;
					break;
				}
			} else
				t = netdev_priv(dev);

			ip6_tnl_unlink(ip6n, t);
			synchronize_net();
			err = ip6_tnl_change(t, &p);
			ip6_tnl_link(ip6n, t);
			netdev_state_change(dev);
		}
		if (t) {
			err = 0;
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &t->parms, sizeof (p)))
				err = -EFAULT;

		} else
			err = (cmd == SIOCADDTUNNEL ? -ENOBUFS : -ENOENT);
		break;
	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			break;

		if (dev == ip6n->fb_tnl_dev) {
			err = -EFAULT;
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof (p)))
				break;
			err = -ENOENT;
			if ((t = ip6_tnl_locate(net, &p, 0)) == NULL)
				break;
			err = -EPERM;
			if (t->dev == ip6n->fb_tnl_dev)
				break;
			dev = t->dev;
		}
		err = 0;
		unregister_netdevice(dev);
		break;
#if defined(MY_ABC_HERE)
	case SIOCADD4RD:
	case SIOCDEL4RD:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		err = -EFAULT;
		if (copy_from_user(&ip4rd, ifr->ifr_ifru.ifru_data, sizeof(ip4rd)))
			goto done;

		t = netdev_priv(dev);

		if (cmd == SIOCADD4RD) {

			__be32 prefix;
			struct in6_addr relay_prefix, relay_suffix;

			err = -EINVAL;

			if (ip4rd.relay_suffixlen > 64)
				goto done;

			if (ip4rd.relay_suffixlen <= ip4rd.relay_prefixlen)
				goto done;

			prefix = ip4rd.prefix & htonl(0xffffffffUL << (32 - ip4rd.prefixlen));
			if (prefix != ip4rd.prefix)
				goto done;

			ipv6_addr_prefix(&relay_prefix, &ip4rd.relay_prefix, ip4rd.relay_prefixlen);
			if (!ipv6_addr_equal(&relay_prefix, &ip4rd.relay_prefix))
				goto done;

			ipv6_addr_prefix(&relay_suffix, &ip4rd.relay_suffix, ip4rd.relay_suffixlen);
			if (!ipv6_addr_equal(&relay_suffix, &ip4rd.relay_suffix))
				goto done;

			err = ip6_tnl_4rd_mr_create(&ip4rd, &t->ip4rd, t->dev);  

			if ( ip4rd.entry_num == 0 ){

				t->ip4rd.prefix = prefix;
				ipv6_addr_copy(&t->ip4rd.relay_prefix, &relay_prefix);
				ipv6_addr_copy(&t->ip4rd.relay_suffix, &relay_suffix);
				t->ip4rd.prefixlen = ip4rd.prefixlen;
				t->ip4rd.relay_prefixlen = ip4rd.relay_prefixlen;
				t->ip4rd.relay_suffixlen = ip4rd.relay_suffixlen;
				t->ip4rd.psid_offsetlen = ip4rd.psid_offsetlen;

				ip6_tnl_4rd_update_parms(t);
				ip6_tnl_dst_reset(t);
				ip6_tnl_link_config(t);
			}
			 
			ip6_tnl_4rd_mr_show(&t->ip4rd);
		}else if(cmd == SIOCDEL4RD){
			if ( ip4rd.entry_num == 0 ){
				ip6_tnl_4rd_mr_delete_all(&t->ip4rd, t->dev);
				t->ip4rd.prefix = 0;
				memset(&t->ip4rd.relay_prefix, 0, sizeof(t->ip4rd.relay_prefix));
				memset(&t->ip4rd.relay_suffix, 0, sizeof(t->ip4rd.relay_suffix));
				t->ip4rd.prefixlen = 0;
				t->ip4rd.relay_prefixlen = 0;
				t->ip4rd.relay_suffixlen = 0;
				t->ip4rd.psid_offsetlen = 0;
				t->ip4rd.laddr4 = 0;
				t->ip4rd.port_set_id = t->ip4rd.port_set_id_len = 0;

				ip6_tnl_dst_reset(t);
				ip6_tnl_link_config(t);
			}else{
				err = ip6_tnl_4rd_mr_delete( ip4rd.entry_num , &t->ip4rd, t->dev);   
			}
			 
			ip6_tnl_4rd_mr_show(&t->ip4rd);
		}else{
			printk(KERN_ERR "=== ioctl_cmd 0x%x \n",cmd );
		}
		err = 0;
		break;
        case SIOCGET4RD:
                t = netdev_priv(dev);
                ip4rdp = (struct ip6_tnl_4r *)ifr->ifr_ifru.ifru_data;
 
                read_lock(&t->ip4rd.map_lock);
                list_for_each_entry (mr, &t->ip4rd.map_list, mr_list){
                        ipv6_addr_copy(&ip4rd.relay_prefix, &mr->relay_prefix);
                        ipv6_addr_copy(&ip4rd.relay_suffix, &mr->relay_suffix);
                        ip4rd.prefix = mr->prefix;
                        ip4rd.relay_prefixlen = mr->relay_prefixlen;
                        ip4rd.relay_suffixlen = mr->relay_suffixlen;
                        ip4rd.prefixlen = mr->prefixlen;
                        ip4rd.eabit_len = mr->eabit_len;
                        ip4rd.psid_offsetlen = mr->psid_offsetlen;
                        ip4rd.entry_num = mr->entry_num;
 
                        if (copy_to_user(ip4rdp, &ip4rd, sizeof(ip4rd))) {
                                read_unlock(&t->ip4rd.map_lock);
                                err = -EFAULT;
                        }
                        ip4rdp++;
                }
                read_unlock(&t->ip4rd.map_lock);
                break;
#endif
	default:
		err = -EINVAL;
	}
#if defined(MY_ABC_HERE)
done:
#endif
	return err;
}

static int
ip6_tnl_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < IPV6_MIN_MTU) {
		return -EINVAL;
	}
	dev->mtu = new_mtu;
	return 0;
}

static const struct net_device_ops ip6_tnl_netdev_ops = {
	.ndo_uninit	= ip6_tnl_dev_uninit,
	.ndo_start_xmit = ip6_tnl_xmit,
	.ndo_do_ioctl	= ip6_tnl_ioctl,
	.ndo_change_mtu = ip6_tnl_change_mtu,
	.ndo_get_stats	= ip6_get_stats,
};

static void ip6_tnl_dev_setup(struct net_device *dev)
{
	struct ip6_tnl *t;

	dev->netdev_ops = &ip6_tnl_netdev_ops;
	dev->destructor = ip6_dev_free;

	dev->type = ARPHRD_TUNNEL6;
	dev->hard_header_len = LL_MAX_HEADER + sizeof (struct ipv6hdr);
	dev->mtu = ETH_DATA_LEN - sizeof (struct ipv6hdr);
	t = netdev_priv(dev);
	if (!(t->parms.flags & IP6_TNL_F_IGN_ENCAP_LIMIT))
		dev->mtu-=8;
	dev->flags |= IFF_NOARP;
	dev->addr_len = sizeof(struct in6_addr);
	dev->features |= NETIF_F_NETNS_LOCAL;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}

static inline int
ip6_tnl_dev_init_gen(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);

	t->dev = dev;
	dev->tstats = alloc_percpu(struct pcpu_tstats);
	if (!dev->tstats)
		return -ENOMEM;
	return 0;
}

static int ip6_tnl_dev_init(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	int err = ip6_tnl_dev_init_gen(dev);

	if (err)
		return err;
	ip6_tnl_link_config(t);
	return 0;
}

static int __net_init ip6_fb_tnl_dev_init(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	int err = ip6_tnl_dev_init_gen(dev);

	if (err)
		return err;

	t->parms.proto = IPPROTO_IPV6;
	dev_hold(dev);
	rcu_assign_pointer(ip6n->tnls_wc[0], t);
	return 0;
}

static struct xfrm6_tunnel ip4ip6_handler __read_mostly = {
	.handler	= ip4ip6_rcv,
	.err_handler	= ip4ip6_err,
	.priority	=	1,
};

static struct xfrm6_tunnel ip6ip6_handler __read_mostly = {
	.handler	= ip6ip6_rcv,
	.err_handler	= ip6ip6_err,
	.priority	=	1,
};

static void __net_exit ip6_tnl_destroy_tunnels(struct ip6_tnl_net *ip6n)
{
	int h;
	struct ip6_tnl *t;
	LIST_HEAD(list);

	for (h = 0; h < HASH_SIZE; h++) {
		t = rtnl_dereference(ip6n->tnls_r_l[h]);
		while (t != NULL) {
			unregister_netdevice_queue(t->dev, &list);
			t = rtnl_dereference(t->next);
		}
	}

	t = rtnl_dereference(ip6n->tnls_wc[0]);
	unregister_netdevice_queue(t->dev, &list);
	unregister_netdevice_many(&list);
}

static int __net_init ip6_tnl_init_net(struct net *net)
{
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);
	struct ip6_tnl *t = NULL;
	int err;

	ip6n->tnls[0] = ip6n->tnls_wc;
	ip6n->tnls[1] = ip6n->tnls_r_l;

	err = -ENOMEM;
	ip6n->fb_tnl_dev = alloc_netdev(sizeof(struct ip6_tnl), "ip6tnl0",
				      ip6_tnl_dev_setup);

	if (!ip6n->fb_tnl_dev)
		goto err_alloc_dev;
	dev_net_set(ip6n->fb_tnl_dev, net);

	err = ip6_fb_tnl_dev_init(ip6n->fb_tnl_dev);
	if (err < 0)
		goto err_register;

	err = register_netdev(ip6n->fb_tnl_dev);
	if (err < 0)
		goto err_register;

	t = netdev_priv(ip6n->fb_tnl_dev);

	strcpy(t->parms.name, ip6n->fb_tnl_dev->name);
	return 0;

err_register:
	ip6_dev_free(ip6n->fb_tnl_dev);
err_alloc_dev:
	return err;
}

static void __net_exit ip6_tnl_exit_net(struct net *net)
{
	struct ip6_tnl_net *ip6n = net_generic(net, ip6_tnl_net_id);

	rtnl_lock();
	ip6_tnl_destroy_tunnels(ip6n);
	rtnl_unlock();
}

static struct pernet_operations ip6_tnl_net_ops = {
	.init = ip6_tnl_init_net,
	.exit = ip6_tnl_exit_net,
	.id   = &ip6_tnl_net_id,
	.size = sizeof(struct ip6_tnl_net),
};

static int __init ip6_tunnel_init(void)
{
#if defined(MY_ABC_HERE)
        int err = 0;                
 
        mr_kmem = kmem_cache_create("ip6_tnl_4rd_map_rule",
                sizeof(struct ip6_tnl_4rd_map_rule), 0, SLAB_HWCACHE_ALIGN,
                NULL);
        if (!mr_kmem)
	{
		err= -ENOMEM; 
                goto out_pernet;
	}
#else
	int  err;
#endif

	err = register_pernet_device(&ip6_tnl_net_ops);
	if (err < 0)
#if defined(MY_ABC_HERE)
		goto out_kmem;
#else
		goto out_pernet;
#endif

	err = xfrm6_tunnel_register(&ip4ip6_handler, AF_INET);
	if (err < 0) {
		printk(KERN_ERR "ip6_tunnel init: can't register ip4ip6\n");
		goto out_ip4ip6;
	}

	err = xfrm6_tunnel_register(&ip6ip6_handler, AF_INET6);
	if (err < 0) {
		printk(KERN_ERR "ip6_tunnel init: can't register ip6ip6\n");
		goto out_ip6ip6;
	}

#if defined(MY_ABC_HERE)
        err =__rtnl_register(PF_UNSPEC, RTM_GET4RD, NULL , inet6_dump4rd_mrule, NULL);
        if(err < 0)
                goto out_ip6ip6;
#endif

	return 0;

out_ip6ip6:
	xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET);
out_ip4ip6:
	unregister_pernet_device(&ip6_tnl_net_ops);
#if defined(MY_ABC_HERE)
out_kmem:
	kmem_cache_destroy(mr_kmem);
#endif
out_pernet:
	return err;
}

static void __exit ip6_tunnel_cleanup(void)
{
	if (xfrm6_tunnel_deregister(&ip4ip6_handler, AF_INET))
		printk(KERN_INFO "ip6_tunnel close: can't deregister ip4ip6\n");

	if (xfrm6_tunnel_deregister(&ip6ip6_handler, AF_INET6))
		printk(KERN_INFO "ip6_tunnel close: can't deregister ip6ip6\n");

#if defined(MY_ABC_HERE)
        kmem_cache_destroy(mr_kmem);     
#endif
 
	unregister_pernet_device(&ip6_tnl_net_ops);

#if defined(MY_ABC_HERE)
        rtnl_unregister(PF_UNSPEC, RTM_GET4RD);
#endif
 
}

module_init(ip6_tunnel_init);
module_exit(ip6_tunnel_cleanup);
