#include "lego/kthread.h"
#include "lego/timer.h"
#include "lego/types.h"
#include <lego/fit_ibapi.h>

#define BUF_SZ          256

#define SERVER_NODE_ID  0
#define CLIENT_NODE_ID  1

#define PORT_ID         0

static int
fit_test_server_thread(void *_)
{
    static u8 buf[BUF_SZ];
    uintptr_t descriptor;
    int ret;

    pr_info("fit_test_server_thread started\n");
    
    while (1) {
        ret = ibapi_receive_message(PORT_ID, buf, BUF_SZ, &descriptor);
        if (ret < 0) {
            pr_err("ibapi_receive_message failed: %d\n", ret);
            continue;
        }
        pr_info("ibapi_receive_message succeeded: %d\n", ret);
        ret = ibapi_reply_message(buf, ret, descriptor);
        if (ret)
            pr_err("ibapi_reply_message failed: %d\n", ret);
        else
            pr_info("ibapi_reply_message succeeded: %d\n", ret);
    }
    return 0;
}

static int
fit_test_client_thread(void *_)
{
    static char msg[] = "Hello FIT!";
    static u8 buf[BUF_SZ];
    int ret;

    pr_info("fit_test_client_thread started\n");

    while (1) {
        ret = ibapi_send_reply_imm(SERVER_NODE_ID, msg, sizeof msg, buf, BUF_SZ, 0);
        if (ret < 0) {
            pr_err("ibapi_send_reply_imm failed: %d\n", ret);
        } else {
            pr_info("ibapi_send_reply_imm succeeded: %d\n", ret);
        }
        msleep(3000);
    }
    return 0;
}

int
test_fit(void)
{
    if (ibapi_get_node_id() == SERVER_NODE_ID) {
        kthread_run(fit_test_server_thread, NULL, "FIT-test-server");
    } else {
        kthread_run(fit_test_client_thread, NULL, "FIT-test-client");
    }
    return 0;
}

