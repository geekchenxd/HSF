#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include "hsf_debug.h"


#define SMP_ALIGN(x) (((x) + SMP_CACHE_BYTES-1) & ~(SMP_CACHE_BYTES-1))

#define HSF_MAX_TABLE_SIZE (512 * 1024 * 1024)

#define HSF_OPT_BASE 1020
#define HSF_GET_INFO HSF_OPT_BASE + 1
#define HSF_GET_ENTRIES HSF_OPT_BASE + 2
#define HSF_SET_REPLACE HSF_OPT_BASE + 1

#define HSF_TABLE_MAXNAMELEN 32

#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
		(1 << NF_INET_FORWARD) | \
		(1 << NF_INET_LOCAL_OUT))

struct hsf_entry {
	struct ipt_ip ipinfo;
	unsigned int verdict;
};

struct hsf_getinfo {
    /* Which table. */
    char name[HSF_TABLE_MAXNAMELEN];

	/* Kernel fills these in. */
	/* Which hook entry points are valid: bit mask */
	unsigned int valid_hooks;

	/* Hook entry points: one per netfilter hook. */
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* Number of entries */
	unsigned int num_entries;

	/* Size of entries. */
	unsigned int size;
};

struct hsf_getentry {
    /* Which table. */
    char name[HSF_TABLE_MAXNAMELEN];

	/* Size of entries. */
	unsigned int size;

	/* The entries. */
	struct hsf_entry entry[0];
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
	void *private;
	
	/* A unique name... */
	const char name[HSF_TABLE_MAXNAMELEN];
};

struct hsf_filter_rules {
	struct list_head list;
	struct hsf_entry *e;
};

struct hsf_replace *
hsf_replace_alloc(unsigned int size)
{
	struct hsf_replace *hrp = NULL;
	size_t sz = sizeof(*hrp) + size;

	if (sz < sizeof(*hrp) || sz >= HSF_MAX_TABLE_SIZE)
		return NULL;

#if 0
	hrp = kvmalloc(sz, GFP_KERNEL_ACCOUNT);
	if (!hrp)
		return NULL;
#else
	/*old kernel version*/
	if ((SMP_ALIGN(size) >> PAGE_SHIFT) + 2 > totalram_pages)
		return NULL;

	if (sz <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER))
		hrp = kmalloc(sz, GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY);
	if (!hrp) {
		hrp = vmalloc(sz);
		if (!hrp)
			return NULL;
	}
#endif

	memset(hrp, 0, sizeof(*hrp));
	hrp->size = size;

	return hrp;
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

static struct hsf_table packet_filter = {
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

static bool
ip_checkentry(const struct ipt_ip *ip)
{
	if (ip->flags & ~IPT_F_MASK)
		return false;
	if (ip->invflags & ~IPT_INV_MASK)
		return false;
	return true;
}

static int 
hsf_update_rules(struct hsf_table *tb)
{
	int i, h;
	struct hsf_replace *rpl;
	struct list_head *rule_head;
	struct hsf_filter_rules *rule;
	struct list_head *pos;
	char *base;
	int off_start, off_end;
	
	rpl = (struct hsf_replace *)tb->private;
	base = (char *)rpl->entries;

	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		if (!(rpl->valid_hooks & (1 << i)))
			continue;
		rule_head = &tb->hooks[i];
		/* Clear old rules firstly 
		 */
		list_for_each(pos, rule_head) {
			rule = list_entry(pos, struct hsf_filter_rules, list);
			list_del(&rule->list);
			kfree(rule);
		}

		off_start = rpl->hook_entry[i];
		off_end = rpl->num_entries;
		for (h = i + 1; h < NF_INET_NUMHOOKS; h++) {
			if (!(rpl->valid_hooks & (1 << h)))
				continue;
			off_end = rpl->hook_entry[h];
			break;
		}

		for (h = 0; h < off_start - off_end; h++) {
			rule = kmalloc(sizeof(struct hsf_filter_rules), GFP_KERNEL);
			if (!rule)
				return -ENOMEM;
			rule->e = &rpl->entries[i];
			list_add_tail(&rule->list, rule_head);
		}
	}

	return 0;
}

static int
hsf_set_replace(struct net *net, const void __user *user, unsigned int len)
{
	int ret, i;
	struct hsf_replace tmp;
	struct hsf_replace *new, *old;
	struct hsf_entry *iter, *tmp_entry;
	struct hsf_table *tb = &packet_filter;

	if (copy_from_user(&tmp, user, sizeof(tmp)) != 0)
		return -EFAULT;

	/* Check name and invalid hooks. */
	tmp.name[sizeof(tmp.name)-1] = '\0';
	if (strcmp(tb->name, tmp.name)
			|| tb->valid_hooks != tmp.valid_hooks
			|| !try_module_get(tb->me))
		return -EFAULT;

	if (tmp.size != tmp.num_entries * sizeof(struct hsf_entry))
		return -EFAULT;

	new = hsf_replace_alloc(tmp.size);
	if (!new)
		return -ENOMEM;

	memcpy(new, &tmp, sizeof(tmp));

	iter = new->entries;
	if (copy_from_user(iter, user + sizeof(tmp),
				tmp.size) != 0) {
		ret = -EFAULT;
		goto free_new;
	}

	/* Here should Check weather user data is valid. */
	for (i = 0; i < new->num_entries; i++) {
		tmp_entry = &new->entries[i];
		if (!ip_checkentry(&tmp_entry->ipinfo)) {
			ret = -EFAULT;
			goto free_new;
		}
	}

	/* Replace the table */
	old = (struct hsf_replace *)tb->private;
	tb->private = new;

	module_put(tb->me);

	/* Free old table */
	for (i = 0; i < old->num_entries; i++) {
		tmp_entry = &old->entries[i];
		kvfree(tmp_entry);
	}
	kfree(old);

	return hsf_update_rules(tb);

free_new:
	kvfree(new);
	return ret;
}

static int
do_hsf_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	int ret;

	if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case HSF_SET_REPLACE:
		ret = hsf_set_replace(sock_net(sk), user, len);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int
hsf_get_info(struct net *net, void __user *user, const int *len)
{
	int ret;
	struct hsf_getinfo info;
	char name[HSF_TABLE_MAXNAMELEN];
	const struct hsf_table *tb = &packet_filter;
	struct hsf_replace *rpl;

	if (*len < sizeof(struct hsf_getinfo))
		return -EINVAL;

	if (copy_from_user(name, user, sizeof(name)) != 0)
		return -EFAULT;

	name[HSF_TABLE_MAXNAMELEN-1] = '\0';

	/* We have only one table currently */
	if (strcmp(tb->name, name) || !try_module_get(tb->me))
		return -EFAULT;

	rpl = (struct hsf_replace *)tb->private;
	if (!rpl) {
		module_put(tb->me);
		return -EFAULT;
	}

	memset(&info, 0, sizeof(info));
	info.valid_hooks = tb->valid_hooks;
	memcpy(info.hook_entry, rpl->hook_entry,
			sizeof(info.hook_entry));
	info.num_entries = rpl->num_entries;
	info.size = rpl->size;
	strcpy(info.name, name);

	if (copy_to_user(user, &info, *len) != 0)
		ret =  -EFAULT;
	else
		ret = 0;

	module_put(tb->me);

	return ret;
}

static int
hsf_get_entries(struct net *net, void __user *user, const int *len)
{
	int ret;
	struct hsf_getentry get;
	const struct hsf_table *tb = &packet_filter;
	struct hsf_replace *rpl;

	if (*len < sizeof(get))
		return -EINVAL;

	if (copy_from_user(&get, user, sizeof(get)) != 0)
		return -EFAULT;

	if (*len != sizeof(struct hsf_getentry) + get.size)
		return -EINVAL;

	get.name[sizeof(get.name) - 1] = '\0';

	/* We have only one table currently */
	if (strcmp(tb->name, get.name) || !try_module_get(tb->me))
		return -EFAULT;

	rpl = (struct hsf_replace *)tb->private;
	if (rpl->size == get.size) {
		memcpy(get.entry, rpl->entries, get.size);
		if (copy_to_user(user, &get, *len) != 0) {
			module_put(tb->me);
			ret =  -EFAULT;
		}
	}

	module_put(tb->me);

	return 0;
}

static int
do_hsf_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	int ret;

	if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case HSF_GET_INFO:
		ret = hsf_get_info(sock_net(sk), user, len);
		break;
	case HSF_GET_ENTRIES:
		ret = hsf_get_entries(sock_net(sk), user, len);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
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
	struct hsf_replace *rpl;

	tb = &packet_filter;
	for (i = 0; i < NF_INET_NUMHOOKS; i++)
		INIT_LIST_HEAD(&tb->hooks[i]);

	rpl = hsf_replace_alloc(0);
	if (!rpl) {
		ret = -ENOMEM;
		return ret;
	}
	rpl->valid_hooks = tb->valid_hooks;
	tb->private = (void *)rpl;

	filter_ops =
		hsf_hook_ops_alloc(&packet_filter, hsf_filter_hook);
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
	struct hsf_table *tb;

	tb = &packet_filter;

	nf_unregister_net_hooks(net, filter_ops, hweight32(packet_filter.valid_hooks));
	kfree(filter_ops);
	kfree(tb->private);
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

	FIREWALL_DEBUG("[HSF:]FireWall Init!\n");

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

	FIREWALL_DEBUG("[HSF:]FireWall Exit!\n");
}

module_init(hsf_init);
module_exit(hsf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("haiyam320@gmail.com");
MODULE_DESCRIPTION("Hylian Shield Firewall");
MODULE_VERSION("0.0.1");
