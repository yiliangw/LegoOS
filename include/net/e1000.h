#ifndef LEGO_E1000_H
#define LEGO_E1000_H

#ifdef CONFIG_E1000

#include <lego/compiler.h>
#include <lego/types.h>

int __init e1000_init(void);
int e1000_transmit(const void *src, size_t len);
int e1000_receive(void *buf, size_t *len);

#endif	// CONFIG_E1000

#endif	// LEGO_E1000_H
