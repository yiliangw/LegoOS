#include <linux/module.h>
#include <linux/printk.h>
#include <linux/completion.h>
#include <linux/kthread.h>

#include <net/e1000.h>
#include <lego/fit_ibapi.h>

int __init lego_eth_init(void *unused);
extern struct completion eth_fit_init_done;

int fit_state = 0;

static int __init ethfit_init(void)
{
    e1000_init();

    kthread_run(lego_eth_init, NULL, "ethfit-initd");
    wait_for_completion(&eth_fit_init_done);

    fit_state = 1;
    
    printk("ethfit: init\n");
    return 0;
}

static void __exit ethfit_exit(void)
{
    printk(KERN_INFO "ethfit: exit\n");
}

EXPORT_SYMBOL(ibapi_send_reply_imm);
EXPORT_SYMBOL(ibapi_receive_message);
EXPORT_SYMBOL(ibapi_reply_message);
EXPORT_SYMBOL(fit_state);

module_init(ethfit_init);
module_exit(ethfit_exit);

MODULE_LICENSE("GPL");
