#ifndef _INCLUDE_FIT_UTILS_H_
#define _INCLUDE_FIT_UTILS_H_

#include "fit_sys.h"
#include <net/lwip/pbuf.h>

int utils_pbuf_cut(struct pbuf *p, off_t off, struct pbuf **p1, 
    struct pbuf **p2);

#endif /* _INCLUDE_FIT_UTILS_H_ */