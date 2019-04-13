#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "libhsf.h"

const struct hsf_pprot hsf_chain_protos[] = {
	{"tcp",		IPPROTO_TCP},
	//{"stcp",	IPPROTO_STCP},
	{"udp",		IPPROTO_UDP},
	{"udplite",	IPPROTO_UDPLITE},
	{"icmp",	IPPROTO_ICMP},
	{"esp",		IPPROTO_ESP},
	{"ah",		IPPROTO_AH},
	{"mh",		IPPROTO_MH},
	{"all",		0},
	{NULL},
};

uint16_t hsf_parse_protocol(const char *s)
{
	const struct protoent *pent;
	unsigned int proto, i;
}


int hsf_get_table_info(struct hsf_getinfo *info, socklen_t *len,  int socket)
{
    int ret = 0;

    if (!info || socket <= 0) {
        debug(ERROR, "Invalid argument\n");
		ret = -EINVAL;
        return ret;
    }

    ret = getsockopt(socket, IPPROTO_IP, HSF_GET_INFO, info, len);
    if (ret) {
        perror("getsockopt:");
        goto out;
    }

    /* Here print the debug info. */
    debug(INFO, "Table Info:\n");
    debug(INFO, "name:%s\n", info->name);
    debug(INFO, "valid_hooks:%d\n", info->valid_hooks);
    debug(INFO, "num_entries:%d\n", info->num_entries);
    debug(INFO, "size:%d\n", info->size);

out:
    return ret;
}

struct hsf_getentry *hsf_getentry_alloc(int size)
{
    int sz = sizeof(struct hsf_getentry) + size;

    return (struct hsf_getentry *)malloc(sz);
}

struct hsf_getentry *hsf_get_table_entry(int *size, int socket, char *name)
{
    struct hsf_getentry *get;
    int ret;
    socklen_t *sz = 0;

    get = hsf_getentry_alloc(*size);
    if (!get) {
        perror("hsf_getentry_alloc:");
        goto out;
    }

    *sz = sizeof(*get) + *size;
    get->size = *size;
    memcpy(get, name, sizeof(get->name));

    ret = getsockopt(socket, IPPROTO_IP, HSF_GET_INFO, get, sz);
    if (ret) {
        perror("getsockopt:");
		goto free_entry;
	}

    *size = *sz;

    if (get && !ret) {
        debug(INFO, "GetEntry:\n");
        debug(INFO, "name:%s\n", get->name);
        debug(INFO, "size:%d\n", get->size);
    }

free_entry:
	free(get);
	get = NULL;
out:
    return get;
}

int socket_init(struct sock_ops *sk)
{
    if (sk) {
        sk->socket = socket(AF_INET, SOCK_STREAM, 0);
        if (sk->socket > 0)
            return 0;
        else
            return sk->socket;
    }

    return -1;
}

#if 0
static char *ipv4_addr_to_string(const struct in_addr *addr,
		const struct in_addr *mask)
{
	static char buf[BUFSIZ];

	return buf;
}
#endif

void hsf_table_show(struct hsf_table *tb)
{
	if (!tb)
		return;

	struct hsf_replace *rpl;

	printf("Table Name:%s\n", tb->name);
	printf("\n");
}

int hsf_table_replace(struct hsf_replace *rpl, int size, int socket)
{
	int ret;
	if (!rpl || size <= 0 || socket <= 0) {
		debug(ERROR, "Invalid argument!\n");
		ret = -EINVAL;
		goto out;
	}

	if (size != sizeof(*rpl) + rpl->size) {
		debug(ERROR, "Invalid data!\n");
		ret = -1;
		goto out;
	}

    ret = setsockopt(socket, IPPROTO_IP, HSF_SET_REPLACE, rpl, size);
    if (ret) {
        perror("setsockopt:");
		ret = errno;
		goto out;
	}

out:
	return ret;
}

struct hsf_replace *hsf_table_replace_alloc(int size)
{
	struct hsf_replace *rpl = NULL;
	int sz = 0;

	if (size < 0)
		return NULL;

	sz = sizeof(*rpl) + size;

	rpl = (struct hsf_replace *)malloc(sz);
	if (!rpl) {
		perror("malloc:");
		return NULL;
	}

	memset(rpl, 0, sz);
	rpl->size = size;

	return rpl;
}

