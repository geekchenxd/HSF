#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include "rules.h"
#include "firewall_debug.h"


#define HSF_TABLE_MAXNAMELEN 32
#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
		(1 << NF_INET_FORWARD) | \
		(1 << NF_INET_LOCAL_OUT))



struct hsf_table {
	/* What hooks you will enter on */
	unsigned int valid_hooks;
	
	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;
	u_int8_t af;	/*address/protocol family */
	int priority;	/* hook order */
	
	/* called when talbe is needed in the fiven netns */
	int (*table_init)(struct net *net);

	/* A unique name... */
	const char name[HSF_TABLE_MAXNAMELEN];
};



static const struct hsf_table packet_filter = {
	.name		= "filter",
	.valid_hooks= FILTER_VALID_HOOKS,
	.me			= THIS_MODULE,
	.af			= NFPROTO_IPV4,
	.priority	= NF_IP_PRI_FILTER,
	.table_init = iptable_filter_table_init,
};

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

static unsigned int 
firewall_local_out(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct iphdr *iph = ip_hdr(skb);
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

	if (r->ip_out_rules == RULES_NULL ||
			r->port_out_rules == RULES_NULL)
		goto nf_drop;

	if (r->ip_out_rules != RULES_ALL)
		if (ip_filter(&r->ip_out_head, daddr))
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

	if (r->.port_out_rules != RULES_ALL)
		if (port_filter(&r->.port_out_head, dport))
			goto nf_drop;

	return NF_ACCEPT;

nf_drop:
	return NF_DROP;
}

static struct nf_hook_ops *filter_ops __read_mostly;
static struct nf_hook_ops hsf_netfilter[] = {
	{
		.hook	 = firewall_local_in,
		.owner	 = THIS_MODULE,
		.pf		 = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority= 100,
		.priv	 = &rules
	},
	{
		.hook	 = firewall_forward,
		.owner   = THIS_MODULE,
		.pf		 = PF_INET,
		.hooknum = NF_IP_FORWARD,
		.priority= NF_IP_PRI_FILTER,
		.priv	 = &rules
	},
	{
		.hook	 = firewall_local_out,
		.owner	 = THIS_MODULE,
		.pf		 = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority= 100,
		.priv	 = &rules
	}
};

static unsigned int
hsf_filter_hook(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	if (state->hook == NF_INET_LOCAL_OUT &&
			(skb->len < sizeof(struct iphdr) ||
			 ip_hdrlen(skb) < sizeof(struct iphdr)))
		/* root is playing with raw sockets. */
		return NF_ACCEPT;

	return NF_ACCEPT;
}

int __init hsf_init(void)
{
	int i,ret;

	filter_ops = xt_hook_ops_alloc(&packet_filter, hfs_filter_hook);
	if (IS_ERR(filter_ops))
		return PTR_ERR(filter_ops);

	ret = nf_register_hooks(&hsf_netfilter[0], ARRAY_SIZE(hsf_netfilter));
	if (ret) {
		FIRMWALL_DEBUG("Register hook fialed!\n");
		goto init_fail;
	}

	printk("FirmWall Init!\n");
	return 0;

init_fail:
	return ret;
}

void __exit hsf_exit(void)
{
	nf_unregister_hooks(&hsf_netfilter[0], ARRAY_SIZE(hsf_netfilter));
	printk("FireWall exit!\n");
}

module_init(hsf_init);
module_exit(hsf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chenxd@hzhytech.com");
MODULE_DESCRIPTION("Hylian Shield Firewall");
MODULE_VERSION("0.0.1");
