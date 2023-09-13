CONFIG_MODULE_SIG=n

obj-m := storage.o
storage-y := core.o handlers.o file_ops.o replica.o stat.o

LEGO_INCLUDE := -I$(M)/../../include

EXTRA_CFLAGS += -g $(LEGO_INCLUDE) -D_LEGO_STORAGE_SOURCE_ -D_LEGO_LINUX_MODULE_ -I$(M)
KBUILD_EXTRA_SYMBOLS += $(shell pwd)/../fit/eth/Module.symvers
export KBUILD_EXTRA_SYMBOLS

ifeq ($(KERNEL_PATH),)
KERNEL_PATH := /lib/modules/$(shell uname -r)/build
$(warn `KERNEL_PATH` is not specified, using default: $(KERNEL_PATH))
endif

KERNEL_PATH ?= $(abspath $(KERNEL_PATH))
export KERNEL_PATH

all:
	make -C $(KERNEL_PATH) M=$(shell pwd) modules
clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) clean
