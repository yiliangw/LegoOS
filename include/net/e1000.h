
#ifndef LEGO_E1000_H
#define LEGO_E1000_H
#ifdef CONFIG_E1000

#include <lego/types.h>
#include <net/netif/etharp.h>

extern void (*e1000_input_callback)(void);
extern u8 e1000_mac[ETHARP_HWADDR_LEN];

int __init e1000_init(void);

int e1000_transmit(const void * src, u16 len);
int e1000_receive(void *dst, u16 *len);

#endif  // CONFIG_E1000
#endif	// LEGO_E1000_H
