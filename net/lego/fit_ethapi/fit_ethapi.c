#include <lego/fit_ibapi.h>
#include <lego/completion.h>

#include "fit_internal.h"

__initdata DEFINE_COMPLETION(eth_init_done);

int lego_eth_init(void *unused)
{
    int err;
    
    err = fit_init_e1000_netif();
    if (err) {
        pr_err("Ehernet FIT: Failed to init netif\n");
        return err;
    }

	complete(&eth_init_done);
	return 0;
}

int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr,
    int max_ret_size, int if_use_ret_phys_addr)
{
    return 0;
}

int ibapi_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
    int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec)
{
    return 0;
}
