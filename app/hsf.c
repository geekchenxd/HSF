#include <stdio.h>
#include <errno.h>


int do_cmd(int argc, char *argv[])
{
    unsigned int nsaddrs = 0, ndaddrs = 0;
    struct in_addr *saddrs = NULL, *smasks = NULL;
    struct in_addr *daddrs = NULL, *dmasks = NULL;

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;

    ret = do_cmd(argc, argv);

    return 0;
}
