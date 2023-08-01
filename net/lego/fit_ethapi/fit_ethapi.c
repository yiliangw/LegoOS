#include <lego/fit_ibapi.h>
#include <lego/completion.h>

#include "fit.h"
#include "fit_internal.h"

__initdata DEFINE_COMPLETION(eth_fit_init_done);

// TODO: for mComponent
int ethapi_establish_conn(int ib_port, int mynodeid)
{
    return 0;
}

int ethapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr,
        int max_ret_size, int if_use_ret_phys_addr)
{
    return fit_send_reply_timeout(target_node, addr, size, ret_addr,
        max_ret_size, if_use_ret_phys_addr, FIT_MAX_TIMEOUT_SEC);
}

int ethapi_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
        int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec)
{
    return fit_send_reply_timeout(target_node, addr, size, ret_addr,
        max_ret_size, if_use_ret_phys_addr, timeout_sec);
}

int ethapi_receive_message(unsigned int designed_port, void *ret_addr,
        int receive_size, uintptr_t *descriptor)
{
    return fit_receive_message(designed_port, ret_addr, receive_size, descriptor);
}

int ethapi_reply_message(void *addr, int size, uintptr_t descriptor)
{
    return fit_reply_message(addr, size, descriptor);
}

int ethapi_get_node_id(void)
{
    return MY_NODE_ID;
}

int lego_eth_init(void *unused)
{
    int err;
    
    err = fit_init_e1000_netif();
    if (err) {
        pr_err("Ehernet FIT: Failed to init netif\n");
        return err;
    }

    err = ethapi_establish_conn(1, CONFIG_FIT_LOCAL_ID);
    if (err) {
        pr_err("Ehernet FIT: Failed to establish connection\n");
        return err;
    }

	complete(&eth_fit_init_done);

    fit_dispatch();

	return 0;
}