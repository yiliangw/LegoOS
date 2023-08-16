#include "lego/errno.h"
#include "uapi/fit.h"
#include <lego/fit_ibapi.h>
#include <lego/completion.h>

#include "fit.h"
#include "fit_internal.h"

__initdata DEFINE_COMPLETION(eth_fit_init_done);

static struct fit_context *CTX; 


int ethapi_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
        int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec)
{
    size_t ret_size;
    int ret;
    if (if_use_ret_phys_addr) {
        pr_warn("Do not support physical address\n");
        return -EINVAL;
    }
    ret = fit_call(CTX, FIT_NONE_PORT, target_node, FIT_NONE_PORT,
        addr, size, ret_addr, &ret_size, max_ret_size);
    if (ret)
        return ret;
    else
        return ret_size;
}

int ethapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr,
        int max_ret_size, int if_use_ret_phys_addr)
{
    return ethapi_send_reply_timeout(target_node, addr, size, ret_addr, max_ret_size,
            if_use_ret_phys_addr, FIT_MAX_TIMEOUT_SEC);
}

int ethapi_send(int target_node, void *addr, int size)
{
    panic("ethapi_send not implemented\n");
    return -1;
}

int ethapi_receive_message(unsigned int designed_port, void *ret_addr,
        int receive_size, uintptr_t *descriptor)
{
    fit_node_t node;
    fit_port_t port;
    size_t sz;
    int ret;
    ret = fit_recv(CTX, designed_port, &node, &port, descriptor, ret_addr, &sz, receive_size);
    if (ret)
        return ret;
    else
        return sz;
}

int ethapi_reply_message(void *addr, int size, uintptr_t descriptor)
{
    return fit_reply(CTX, descriptor, addr, size);
}

int ethapi_get_node_id(void)
{
    return MY_NODE_ID;
}

int lego_eth_init(void *unused)
{
    int ret;

    ret = fit_init();
    if (ret)
        goto err;

    CTX = fit_new_context(MY_NODE_ID, FIT_UDP_PORT); 

    ret = fit_dispatch();
    if (ret)
        goto err;
    
    complete(&eth_fit_init_done);
	return 0;
err:
    pr_err("Ethernet FIT exit: %d\n", ret);
    return ret;
}