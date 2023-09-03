obj-m := e1000_lego.o

LEGOOS_REL ?= ../..
LEGOOS_ABS ?= $(abspath $(M)/$(LEGOOS_REL))

# Relative path is required here to make it work
e1000_obj := $(addprefix $(LEGOOS_REL)/drivers/eth/, e1000.o)
e1000_lego-y := $(e1000_obj)

cflags += -g
EXTRA_CFLAGS += -g -D_LEGO_LINUX_MODULE_ -I$(LEGOOS_ABS)/include

ifeq ($(KERNEL_PATH),)
KERNEL_PATH := /lib/modules/$(shell uname -r)/build
$(warn `KERNEL_PATH` is not specified, using default: $(KERNEL_PATH))
endif

KERNEL_PATH := $(abspath $(KERNEL_PATH))

all:
	make -C $(KERNEL_PATH) M=$(shell pwd) modules

clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) clean

.PHONY: all clean
