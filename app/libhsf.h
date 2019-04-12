#ifndef __LIB_HSF_H__
#define __LIB_HSF_H__

#include <stdint.h>
#include <net/if.h>
#include "list.h"

#define HSF_MAX_TABLE_SIZE (512 * 1024 * 1024)

#define HSF_OPT_BASE 1020
#define HSF_GET_INFO HSF_OPT_BASE + 1
#define HSF_GET_ENTRIES HSF_OPT_BASE + 2
#define HSF_SET_REPLACE HSF_OPT_BASE + 1

#define HSF_TABLE_MAXNAMELEN 32

#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
		(1 << NF_INET_FORWARD) | \
		(1 << NF_INET_LOCAL_OUT))

#define NF_INET_NUMHOOKS 5

struct ipt_ip {
	/* Source and destination IP addr */
	struct in_addr src, dst;
	/* Mask for src and dest IP addr */
	struct in_addr smsk, dmsk;
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

	/* protocol, 0 = ANY */
	uint16_t proto;

	/* Flags word */
	uint8_t flags;

	/* Inverse flags */
	uint8_t invflags;
};

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

struct sock_ops {
    int socket;
}

struct hsf {
	struct hsf_table *tb;
	struct sock_ops *sk;
};


#endif
