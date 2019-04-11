#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/net_namespace.h>
//#include "hsf_debug.h"


#define HSF_OPT_BASE 1020
#define HSF_TABLE_MAXNAMELEN 32
#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
		(1 << NF_INET_FORWARD) | \
		(1 << NF_INET_LOCAL_OUT))

struct hsf_entry {
	struct ipt_ip ipinfo;
	unsigned int verdict;
};

struct hsf_replace {
    /* Which table. */
    char name[HSF_TABLE_MAXNAMELEN];

    /* Which hook entry points are valid:bitmask. 
     * can't change this in user space. */
    unsigned int valid_hooks;

    /* Number of entries */
    unsigned int num_entries;

    /* Total size of new entries */
    unsigned int size;

    /* Hook entry points. */
    unsigned int hook_entry[NF_INET_NUMHOOKS];

    /* The entries (hang off end: not really an array). */
    struct hsf_entry entries[0];
};

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
	struct hsf_entry *e;
};

struct hsf_replace *
hsf_replace_alloc(struct hsf_table *table)
{
	return NULL;
}

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
				(ip->daddr & ipinfo->dmsk.s_addr) != ipinfo->dst.s_addr))
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
		if (!ip_packet_match(ip, indev, outdev, &rule->e->ipinfo))
			continue;
		else
			return rule->e->verdict;

	}

	return NF_DROP;
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

static int
do_hsf_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	return 0;
}

static int
do_hsf_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	return 0;
}

static struct nf_sockopt_ops hsf_sockopts = {
    .pf     = PF_INET,
    .set_optmin = HSF_OPT_BASE,
    .set_optmax = HSF_OPT_BASE + 3,
    .set    = do_hsf_set_ctl,
    .get_optmin = HSF_OPT_BASE,
    .get_optmax = HSF_OPT_BASE + 3,
    .get    = do_hsf_get_ctl,
    .owner  = THIS_MODULE,
};

static int __net_init hsf_tables_net_init(struct net *net)
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

	ret = nf_register_net_hooks(net, filter_ops, hweight32(packet_filter.valid_hooks));
	if (ret) {
		printk("HSF register net hooks fialed!\n");
        kfree(filter_ops);
	}

	return ret;
}

static void __net_exit hsf_tables_net_exit(struct net *net)
{
	nf_unregister_net_hooks(net, filter_ops, hweight32(packet_filter.valid_hooks));
	kfree(filter_ops);
}

static struct pernet_operations hsf_tables_net_ops = {
	.init = hsf_tables_net_init,
	.exit = hsf_tables_net_exit,
};

int __init hsf_init(void)
{
	int ret;

	ret = register_pernet_subsys(&hsf_tables_net_ops);
	if (ret < 0)
		goto err1;

    ret = nf_register_sockopt(&hsf_sockopts);
    if (ret < 0) 
		goto err2;

	printk("HSF Init!\n");

	return 0;

err2:
	unregister_pernet_subsys(&hsf_tables_net_ops);
err1:
	return ret;
}

void __exit hsf_exit(void)
{
	nf_unregister_sockopt(&hsf_sockopts);
	unregister_pernet_subsys(&hsf_tables_net_ops);

	printk("HSF Exit!\n");
}

module_init(hsf_init);
module_exit(hsf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("haiyam320@gmail.com");
MODULE_DESCRIPTION("Hylian Shield Firewall");
MODULE_VERSION("0.0.1");
