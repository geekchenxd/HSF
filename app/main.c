#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include "libhsf.h"


int do_cmd(int argc, char *argv[])
{
    unsigned int nsaddrs = 0, ndaddrs = 0;
    struct in_addr *saddrs = NULL, *smasks = NULL;
    struct in_addr *daddrs = NULL, *dmasks = NULL;

    return 0;
}

struct hsf_replace rpl = {
};

struct hsf_getinfo info = {
	.name = "filter",
};

int main(int argc, char *argv[])
{
    int ret;
	int sockfd;
	socklen_t len = sizeof(struct hsf_getinfo);

    ret = do_cmd(argc, argv);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd <= 0) {
		printf("socket\n");
		return sockfd;
	}

	ret = getsockopt(sockfd, IPPROTO_IP, HSF_GET_INFO, &info, &len);
	if (ret) {
		printf("getsockopt:\n");
		return ret;
	}

	printf("info:\n");
	printf("name:%s\n", info.name);
	printf("valid_hooks:%d\n", info.valid_hooks);
	printf("num_entries:%d\n", info.num_entries);
	printf("size:%d\n", info.size);

    return 0;
}
