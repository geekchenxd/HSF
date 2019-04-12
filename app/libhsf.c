#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "debug.h"
#include "libhsf.h"

int hsf_get_table_info(struct hsf_getinfo *info, socklen_t *len,  int socket)
{
    int ret = 0;

    if (!info || socket <= 0) {
        debug(ERROR, "Invalid argument\n");
        errno = -22;
        return errno;
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
    struct hsf_getentry *get = NULL;
    int sz = sizeof(struct hsf_getentry) + size;

    return (struct hsf_getentry *)malloc(sz);
}

int hsf_get_table_entry(struct hsf_getentry *get, int *size, int socket, char *name)
{
    struct hsf_getentry *get;
    int ret;
    socklen_t *sz = 0;

    get = hsf_getentry_alloc(*size);
    if (!get) {
        perror("hsf_getentry_alloc:");
        ret = errno;
    }

    *sz = sizeof(*get) + *size;
    get->size = *size;
    memcpy(get, name, sizeof(get->name));

    ret = getsockopt(socket, IPPROTO_IP, HSF_GET_INFO, get, sz);
    if (ret)
        perror("getsockopt:");

    *size = *sz;

    if (get && !ret) {
        debug(INFO, "GetEntry:\n");
        debug(INFO, "name:%s\n", get->name);
        debug(INFO, "size:%d\n", get->size);
    }

    return ret;
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


