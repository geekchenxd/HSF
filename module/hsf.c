#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/ip.h>
#include <net/ip.h>
//#include "hsf_debug.h"


#define HSF_TABLE_MAXNAMELEN 32
#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
		(1 << NF_INET_FORWARD) | \
		(1 << NF_INET_LOCAL_OUT))


struct hsf_table {
	struct list_head hooks[NF_INET_NUMHOOKS];
	/* What hooks you will enter on */
	unsigned int valid_hooks;
	
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;
	u_int8_t af;	/*address/protocol family */
	int priority;	/* hook order */
	
	/* A unique name... */
	const char name[HSF_TABLE_MAXNAMELEN];
};

struct hsf_filter_rules {
	struct list_head list;
	struct ipt_ip ipinfo;
	unsigned int verdict;
};

struct nf_hook_ops *
hsf_hook_ops_alloc(struct hsf_table *table, nf_hookfn *fn)
{
	unsigned int hook_mask = table->valid_hooks;
	uint8_t i, num_hooks = hweight32(hook_mask);
	uint8_t hooknum;
	struct nf_hook_ops *ops;

	if (!num_hooks)
		return ERR_PTR(-EINVAL);

	ops = kcalloc(num_hooks, sizeof(*ops), GFP_KERNEL);
	if (ops == NULL)
		return ERR_PTR(-ENOMEM);

	for (i = 0, hooknum = 0; i < num_hooks && hook_mask != 0;
			hook_mask >>= 1, ++hooknum) {
		if (!(hook_mask & 1))
			continue;
		ops[i].hook = fn;
		ops[i].pf = table->af;
		ops[i].hooknum = hooknum;
		ops[i].priority = table->priority;
		ops[i].priv = table->hooks;
		++i;
	}

	return ops;
}

static inline bool
ip_packet_match(const struct iphdr *ip,
		const char *indev,
		const char *outdev,
		const struct ipt_ip *ipinfo)
{
	unsigned long ret;

	if (NF_INVF(ipinfo, IPT_INV_SRCIP,
				(ip->saddr & ipinfo->smsk.s_addr) != ipinfo->src.s_addr) ||
			NF_INVF(ipinfo, IPT_INV_DSTIP,
				(ip_>daddr & ipinfo->dmsk.s_addr) != ipinfo->dst.s_addr))
		return false;

	ret = ifname_compare_aligned(indev, ipinfo->iniface, ipinfo->iniface_mask);

	if (NF_INVF(ipinfo, IPT_INV_VIA_IN, ret != 0))
		return false;

	ret = ifname_compare_aligned(outdev, ipinfo->outiface, ipinfo->outiface_mask);

	if (NF_INVF(ipinfo, IPT_INV_VIA_OUT, ret != 0))
		return false;

	/*Check specific protocol */
	if (ipinfo->proto &&
			NF_INVF(ipinfo, IPT_INV_PROTO, ip->protocol != ipinfo->proto))
		return false;

	/*If we have a fragment rule but the packet isnot a fragment
	 * then we return zero */
	if (NF_INVF(ipinfo, IPT_INV_FRAG,
				(ipinfo->flags & IPT_F_FRAG)))
		return false;

	return true;
}

static const struct hsf_table packet_filter = {
	.name		= "filter",
	.valid_hooks= FILTER_VALID_HOOKS,
	.me			= THIS_MODULE,
	.af			= NFPROTO_IPV4,
	.priority	= NF_IP_PRI_FILTER,
};

static struct nf_hook_ops *filter_ops __read_mostly;

static unsigned int hsf_do_table(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hook = state->hook;
	const struct iphdr *ip;
	static const char nulldevname[IFNAMSIZ] __attribute__((aligned(sizeof(long))));
	/*Initializing verdict to NF_DROP keeps gcc happy. */
	//unsigned int verdict = NF_DROP;
	const char *indev, *outdev;
	struct hsf_filter_rules *rule;
	struct list_head *hook_head = (struct list_head *)priv + hook;
	struct list_head *pos;

	ip = ip_hdr(skb);
	indev = state->in ? state->in->name : nulldevname;
	outdev = state->out ? state->out->name : nulldevname;

	list_for_each(pos, hook_head) {
		rule = list_entry(pos, struct hsf_filter_rules, list);
		if (!ip_packet_match(ip, indev, outdev, &rule->ipinfo))
			continue;
		else
			return rule->verdict;

	}

	return NF_ACCEPT;
}

static unsigned int
hsf_filter_hook(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (state->hook == NF_INET_LOCAL_OUT &&
			(skb->len < sizeof(struct iphdr) ||
			 ip_hdrlen(skb) < sizeof(struct iphdr)))
		/* root is playing with raw sockets. */
		return NF_ACCEPT;

	return hsf_do_table(priv, skb, state);
}

int __init hsf_init(void)
{
	int i,ret;
	struct hsf_table *tb;

	tb = (struct hsf_table *)&packet_filter;
	for (i = 0; i < NF_INET_NUMHOOKS; i++)
		INIT_LIST_HEAD(&tb->hooks[i]);

	filter_ops =
		hsf_hook_ops_alloc((struct hsf_table *)&packet_filter, hsf_filter_hook);
	if (IS_ERR(filter_ops))
		return PTR_ERR(filter_ops);

	ret = nf_register_hooks(filter_ops, hweight32(packet_filter.valid_hooks));
	if (ret) {
		//FIRMWALL_DEBUG("Register hook fialed!\n");
		goto init_fail;
	}

	printk("HSF FirmWall Init!\n");

	return 0;

init_fail:
	return ret;
}

void __exit hsf_exit(void)
{
	nf_unregister_hooks(filter_ops, hweight32(packet_filter.valid_hooks));
	kfree(filter_ops);

	printk("HSF FireWall exit!\n");
}

module_init(hsf_init);
module_exit(hsf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("haiyam320@gmail.com");
MODULE_DESCRIPTION("Hylian Shield Firewall");
MODULE_VERSION("0.0.1");
#if 0
static unsigned int 
firewall_local_in(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct iphdr *iph = ip_hdr(skb);
	__be32 saddr = ntohl(iph->saddr);
	__be32 daddr = ntohl(iph->daddr);
	__be16 sport = 0, dport = 0;
	int port_check = 1;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct firewall_rules *r;

	switch (r->default_rules) {
	case RULES_ALL:
		return NF_ACCEPT;
	case RULES_NULL:
		goto nf_drop;
	default:
		break;
	}

	if (r->ip_in_rules == RULES_NULL ||
			r->port_in_rules == RULES_NULL)
		goto nf_drop;

	if (r->ip_in_rules != RULES_ALL)
		if (ip_filter(&r->ip_in_head, saddr))
			goto nf_drop;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		sport = tcph->source;
		dport = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		sport = udph->source;
		dport = udph->dest;
	} else {
		port_check = 0;
	}

	if (!port_check)
		return ACCEPT;

	if (r->.port_in_rules != RULES_ALL)
		if (port_filter(&r->.port_in_head, dport))
			goto nf_drop;

	return NF_ACCEPT;

nf_drop:
	return NF_DROP;
}
#endif
