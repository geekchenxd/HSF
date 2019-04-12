SUBDIRS :=
.PHONY: $(SUBDIRS)


CROSS_COMPILE ?= arm-linux-gnueabihf-
CC := $(CROSS_COMPILE)gcc
LDFLAGS := -lm
TARGET := hsf

INCLUDE := .
SUBOBJS := $(patsubst %.c, %.o, $(wildcard *.c))
SUBOBJS += $(foreach dir, $(SUBDIRS), $(patsubst %.c, %.o, $(wildcard $(dir)/*.c)))
OBJS	:= $(COBJS) $(SUBOBJS)
CFLAGS	?= -Wall -O2 -g -I$(INCLUDE)

target:$(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(CFLAGS)

clean:
	$(RM) $(OBJS) $(LIBS) $(TARGET)
