#ifndef _INCLUDE_FIT_INTERNAL_H
#define _INCLUDE_FIT_INTERNAL_H

int fit_init_e1000_netif(void);
void fit_dispatch(void);

int fit_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
    int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec);

#endif /* _INCLUDE_FIT_INTERNAL_H */