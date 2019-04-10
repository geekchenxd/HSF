obj-m += hsf.o

CURRENT = $(shell uname -r)
#KDIR = /lib/modules/$(CURRENT)/
KDIR = /root/work/workspace/git/u4n2/linux-4.9.28/
PWD = $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD)  modules;

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean;
	rm -rf *.o *.mod.c *.symvers .*.ko.cmd .*.o.cmd
