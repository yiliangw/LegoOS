CONFIG_MODULE_SIG=n

obj-m := ethfit.o

LEGOOS_REL ?= ../../..
LEGOOS_ABS ?= $(abspath $(LEGOOS_REL))
export LEGOOS_REL
export LEGOOS_ABS

ifeq ($(ethfit-y),)
lego_ethfit-obj := $(addprefix $(LEGOOS_REL)/net/lego/fit_ethapi/, fit_api.o fit_conn.o fit_context.o fit_internal.o fit_utils.o)

lego_lwip-obj := $(addprefix core/, init.o tcp_in.o dhcp.o mem.o memp.o netif.o pbuf.o raw.o stats.o sys.o tcp.o tcp_out.o udp.o dns.o)
lego_lwip-obj += $(addprefix core/ipv4/, ip_addr.o icmp.o ip.o ip_frag.o inet_chksum.o inet.o)
lego_lwip-obj += $(addprefix netif/, etharp.o loopif.o)
lego_lwip-obj := $(addprefix $(LEGOOS_REL)/net/lwip/, $(lego_lwip-obj))

lego_e1000-obj := $(addprefix $(LEGOOS_REL)/drivers/eth/, e1000.o)

ethfit-y := $(lego_ethfit-obj) $(lego_lwip-obj) $(lego_e1000-obj) ethfit_main.o
export ethfit-y
endif

LEGO_KCONFIG := CONFIG_E1000 CONFIG_FIT CONFIG_ETHERNET_FIT CONFIG_FIT_MAX_RPC_TIMEOUT_SEC=60 \
	CONFIG_FIT_NR_NODES=3 CONFIG_FIT_LOCAL_ID=2 \
	CONFIG_E1000_NETIF_IP='"10.0.2.17"' CONFIG_E1000_NETIF_MASK='"255.255.255.0"' CONFIG_E1000_NETIF_GATEWAY='"10.0.2.2"'

cflags += -g
EXTRA_CFLAGS += -g -D_LEGO_LINUX_MODULE_ $(addprefix -D, $(LEGO_KCONFIG)) -I$(LEGOOS_ABS)/include

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
