#include "lego/bitops.h"
#include "lego/bug.h"
#include "lego/errno.h"
#include "lego/fit_ibapi.h"
#include "lego/spinlock.h"
#include "net/lwip/arch.h"
#include <lego/semaphore.h>
#include <lego/time.h>
#include <lego/jiffies.h>
#include <lego/printk.h>
#include <lego/completion.h>
#include <lego/delay.h>
#include <lego/sched.h>
#include <lego/kthread.h>
#include <lego/types.h>
#include <lego/bitmap.h>

#include <net/netif/etharp.h>
#include <net/e1000.h>

#include <net/lwip/netif.h>
#include <net/lwip/udp.h>
#include <net/lwip/ip_addr.h>
#include <net/lwip/ip_frag.h>
#include <net/lwip/pbuf.h>

#include "fit_internal.h"

static const char e1000_netif_name[] = "en";
static struct netif e1000_netif;
static struct semaphore e1000_sem;    /* pending e1000 interrupt number */

typedef struct fit_context ctx_t;

static ctx_t fit_ctx;

static fit_seqnum_t alloc_sequence_num(ctx_t *ctx)
{
    fit_seqnum_t num;
    spin_lock(&ctx->sequence_num_lock);
    num = ctx->sequence_num++;
    spin_unlock(&ctx->sequence_num_lock);
    return num;
}

static struct fit_s_handle *alloc_send_handle(ctx_t *ctx)
{
    unsigned int i;
    struct fit_s_handle *handle;
    spin_lock(&ctx->s_handles_lock);
    i = find_first_zero_bit(ctx->s_handles_bitmap, FIT_NUM_SEND_HANDLE);
    if (i == FIT_NUM_SEND_HANDLE)
        handle = NULL;
    else
        handle = &ctx->s_handles[i];
    spin_unlock(&ctx->s_handles_lock);
    return handle;
}

static int free_send_handle(ctx_t *ctx, struct fit_s_handle *handle)
{
    int i = handle - ctx->s_handles;
    if (i < 0 || i >= FIT_NUM_SEND_HANDLE) {
        FIT_ERR("Invalid send handle\n");
        return -EINVAL;
    }
    /* We do not need to lock here */
    if (test_and_clear_bit(i, ctx->s_handles_bitmap) == 0) {
        FIT_ERR("Freeing a free send handle\n");
        return -EPERM;
    }
    return 0;
}

static struct fit_r_handle *alloc_recv_handle(ctx_t *ctx)
{
    unsigned int i;
    struct fit_r_handle *handle;
    spin_lock(&ctx->r_handles_lock);
    i = find_first_zero_bit(ctx->r_handles_bitmap, FIT_NUM_RECV_HANDLE);
    if (i == FIT_NUM_RECV_HANDLE)
        handle = NULL;
    else
        handle = &ctx->r_handles[i];
    spin_unlock(&ctx->r_handles_lock);
    return handle;
}

static int free_recv_handle(ctx_t *ctx, struct fit_r_handle *handle)
{
    int i = handle - ctx->r_handles;
    if (i < 0 || i >= FIT_NUM_RECV_HANDLE) {
        FIT_ERR("Invalid recv handle\n");
        return -EINVAL;
    }
    /* We do not need to lock here */
    if (test_and_clear_bit(i, ctx->r_handles_bitmap) == 0) {
        FIT_ERR("Freeing a free recv handle\n");
        return -EPERM;
    }
    return 0;
}

static inline long __timespec_diff_ms(struct timespec *t1, struct timespec *t2)
{
    return (t1->tv_sec - t2->tv_sec) * 1000 + (t1->tv_nsec - t2->tv_nsec) / 1000000;
}

/* The function which performs transmission using lwIP */
static int __udp_output(ctx_t *ctx, int fit_node, int fit_port, 
        fit_rpc_id_t rpc_id, void *msg, size_t len)
{
    struct pbuf *p;
    int ret;
    struct ip_addr *dst_ip;
    struct fit_hdr *hdr;

    if (fit_node >= FIT_NUM_NODE) {
        FIT_ERR("Invalid node number\n");
        return -EINVAL;
    }
    dst_ip = &ctx->node_ip_addr[fit_node];

    p = pbuf_alloc(PBUF_TRANSPORT, len + sizeof(struct fit_hdr), PBUF_RAM);
    if (p == NULL) {
        FIT_ERR("Failed to allocate pbuf\n");
        return -ENOMEM;
    }

    /* set FIT header */
    hdr = (struct fit_hdr *)p->payload;
    hdr->rpc_id = rpc_id;
    hdr->src_node = ctx->node_id;
    hdr->dst_node = fit_node;
    hdr->dst_port = fit_port;

    memcpy(p->payload, msg, len);
    FIT_DEBUG("Sending packet\n");
    ret = udp_sendto(ctx->pcb, p, dst_ip, FIT_UDP_PORT);
    if (ret) {
        FIT_ERR("Failed to send packet\n");
        return ret;
    }
    pbuf_free(p);
    return 0;
}


/**
 * Network interface test
 */

#define TEST_PORT 6000

#define NODE_0_IP "10.0.2.15"
#define NODE_1_IP "10.0.2.16"

static const char msg[] = "Hello, world!";

static void __e1000_input_callback(void);

static void client_receive_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
    pr_info("FIT client: Received packet from port %d, len=%u\n", port, p->len);
    pbuf_free(p);
}

static int test_client_thread(void *unused)
{
    struct udp_pcb *pcb;
    struct pbuf *p;
    struct ip_addr server_ip;

    pr_info("Testing client\n");

    IP4_ADDR(&server_ip, 10, 0, 2, 15);

    pcb = udp_new();
    if (pcb == NULL) {
        pr_err("FIT client: Failed to create udp pcb\n");
    }

    udp_bind(pcb, IP_ADDR_ANY, TEST_PORT);
    udp_recv(pcb, client_receive_cb, NULL);

    while(1) {
        // __udp_output(pcb, &server_ip, FIT_UDP_PORT, (void *)msg, sizeof(msg));
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(500));
    }
    BUG();
    return 0;
}

static void try_e1000_input(void);


static int test_server_thread(void *unused)
{
    pr_info("Testing server\n");
    while(1) {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    BUG();
    return 0;
}

void e1000_netif_test(void)
{
    if (CONFIG_FIT_LOCAL_ID == 0) {
        /* udp server */
        kthread_run(test_server_thread, NULL, "fit_server");
    } else {
        /* udp client */
        kthread_run(test_client_thread, NULL, "fit_client");
    }
}

/**
 * E1000 lwIP network interface low-level I/O functions
 */
static err_t e1000_netif_low_level_output(struct netif *netif, struct pbuf *p)
{
    int err;
    pr_debug("Ethernet FIT: Transmitting packet, len: %d\n", p->len);
    err = e1000_transmit(p->payload, p->len);
    if (err) {
        pr_err("Ethernet FIT: Failed to transmit packet\n");
        return ERR_IF;
    }
    return ERR_OK;
}

static struct pbuf *e1000_netif_low_level_input(void)
{
    u8 buf[0x5EE];
    
    struct pbuf *p, *q;
    u16 len, copied_len;
    int err;

    err = e1000_receive(buf, &len);
    if (err) {
        pr_err("Ethernet FIT: Failed to receive packet: %d\n", err);
        return NULL;
    }

    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p == NULL) {
        pr_warn("Ethernet FIT: Failed to allocate pbuf\n");
        return NULL;
    }

    copied_len = 0;
    for (q = p; q != NULL; q = q->next) {
        int bytes = q->len;
        if (bytes > (len - copied_len))
            bytes = len - copied_len;
        memcpy(q->payload, buf + copied_len, bytes);
        copied_len += bytes;
    }

    return p;
}

/**
 * This function is called in the interrupt context
 */
static void __e1000_input_callback(void)
{
    pr_info("Ethernet FIT: e1000 interrupt detected\n");
    up(&e1000_sem);
}

/**
 * E1000 lwIP network interface initialization 
 * See net/lwip/netif/ehernetif.c for reference
 */
/*-----------------------------------------*/
static err_t e1000_netif_output(struct netif *netif, struct pbuf *p,
    struct ip_addr *ipaddr)
{
    /* May perform some checks here */
    return etharp_output(netif, p, ipaddr);
}

static err_t e1000_netif_init_cb(struct netif *netif)
{
    int i;

    netif->state = NULL;
    netif->output = e1000_netif_output;
    netif->linkoutput = e1000_netif_low_level_output;
    memcpy(&netif->name[0], e1000_netif_name, strlen(e1000_netif_name));

    /* Low-level initialization */
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    for (i = 0; i < ETHARP_HWADDR_LEN; i++)
        netif->hwaddr[i] = e1000_mac[i];

    /* We should have called e1000_init() by now, but the input callback has 
        not been set yet */
    sema_init(&e1000_sem, 0);
    e1000_input_callback = __e1000_input_callback;

    etharp_init();

    return ERR_OK;
}

int fit_init_e1000_netif(void)
{
    struct ip_addr ipaddr, netmask, gateway;
    
    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&netmask, 0, sizeof(netmask));
    memset(&gateway, 0, sizeof(gateway));

    if ((ipaddr.addr = inet_addr(CONFIG_E1000_NETIF_IP)) == INADDR_NONE) {
        pr_err("Ethernet FIT: Invalid IP address: %s\n", CONFIG_E1000_NETIF_IP);
        goto ip_err;
    }
    if ((netmask.addr = inet_addr(CONFIG_E1000_NETIF_MASK)) == INADDR_NONE) {
        pr_err("Ethernet FIT: Invalid netmask: %s\n", CONFIG_E1000_NETIF_MASK);
        goto ip_err;
    }
    if ((gateway.addr = inet_addr(CONFIG_E1000_NETIF_GATEWAY)) == INADDR_NONE) {
        pr_err("Ethernet FIT: Invalid gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
        goto ip_err;
    }

    /* se should use ethernet_input here to handle Ethernet headers */
    if (netif_add(&e1000_netif, &ipaddr, &netmask, &gateway, NULL, e1000_netif_init_cb, ethernet_input) == NULL) {
        pr_err("Ehernet FIT: Failed to add netif\n");
        goto ip_err;
    }

    pr_info("Ethernet FIT: netif name: %s\n", e1000_netif_name);
    pr_info("Ethernet FIT: netif ip: %s\n", CONFIG_E1000_NETIF_IP);
    pr_info("Ethernet FIT: netif netmask: %s\n", CONFIG_E1000_NETIF_MASK);
    pr_info("Ethernet FIT: netif gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
    pr_info("Ethernet FIT: netif mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		e1000_netif.hwaddr[0], e1000_netif.hwaddr[1], e1000_netif.hwaddr[2],
        e1000_netif.hwaddr[3], e1000_netif.hwaddr[4], e1000_netif.hwaddr[5]);

    netif_set_default(&e1000_netif);
    netif_set_up(&e1000_netif);

    pr_info("Ethernet FIT: netif initialized\n");

    return 0;

ip_err:
    pr_err("Ehernet FIT: netif initialization failed\n");
    return -EINVAL;
}

static void try_e1000_input(void)
{
    struct pbuf *p;

    while(e1000_pending_reception() > 0) {
        p = e1000_netif_low_level_input();
        /* no packet could be read, silently ignore this */
        if (p == NULL)
            break;
        pr_debug("Ethernet FIT: Received packet (len=%d)\n", p->len);
        
        /* here input() has been initialized to ethernet_input, which
        will take care of the Ethernet header */
        e1000_netif.input(p, &e1000_netif);
    }
}

static void __udp_receive_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
    ctx_t *ctx = (ctx_t *)arg;

    FIT_DEBUG("ctx[%d]eceived packet from port %d, length=%u\n", ctx->node_id, port, p->len);
    pbuf_free(p);

    /* Find the corresponding RPC handle in the request pool */

    /* Set the reply content in the registerd address */

    /* Up the RPC handle's semaphore */
}

static int fit_init_context(ctx_t *ctx, int node_id, u16 udp_port)
{
    memset(ctx, 0, sizeof(ctx_t));
    ctx->node_id = node_id;

    /* Set up UDP */
    ctx->udp_port = udp_port;
    ctx->pcb = udp_new();
    if (ctx->pcb == NULL) {
        FIT_ERR("Fail to create udp pcb\n");
        return -ENOMEM;
    }
    udp_bind(ctx->pcb, IP_ADDR_ANY, ctx->udp_port);
    udp_recv(ctx->pcb, __udp_receive_cb, ctx);
    
    /* Hardcode the IP table*/
    IP4_ADDR(&ctx->node_ip_addr[0], 10, 0, 2, 15);
    IP4_ADDR(&ctx->node_ip_addr[1], 10, 0, 2, 16);

    ctx->sequence_num = 0;
    spin_lock_init(&ctx->sequence_num_lock);
    spin_lock_init(&ctx->s_handles_lock);
    spin_lock_init(&ctx->r_handles_lock);

    return 0;
}

void fit_dispatch(void)
{
    /* LwIP timers */
    struct timespec ts_etharp, ts_ipreass, ts;
    int ret;

    ret = fit_init_context(&fit_ctx, MY_NODE_ID, FIT_UDP_PORT);
    if (ret)
        FIT_PANIC("Failed to init the context: %d\n", ret);

    FIT_INFO("dispatched\n");

    /* Only try to get the packet from the driver */
    while(1) {
        down(&e1000_sem);
        /* Clear the semaphore before doing actual input because 
        we will get all the pending input in try_e1000_input() */
        while(down_trylock(&e1000_sem) == 0); 

        FIT_DEBUG("e1000_sem down succeeds\n");
        try_e1000_input();
    }

    ts_etharp = ts_ipreass = current_kernel_time();

    while(1) {
        /* Clear the input buffer */
        while(down_trylock(&e1000_sem) == 0) {
            try_e1000_input();
        }

        /* polling for lwIP */
        ts = current_kernel_time();
        if (__timespec_diff_ms(&ts, &ts_etharp) >= ARP_TMR_INTERVAL_MS) {
            ts_etharp = ts;
            etharp_tmr();
        }
        if (__timespec_diff_ms(&ts, &ts_ipreass) >= IP_TMR_INTERVAL_MS) {
            ts_ipreass = ts;
            ip_reass_tmr();
        }

        ret = down_timeout(&e1000_sem, msecs_to_jiffies(SEM_DOWN_TIMEOUT_MS));
        if (ret == 0) {
            /* The semaphore is acquired */
            try_e1000_input();
        }
    }
}

int fit_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
        int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec)
{
    struct fit_s_handle *handle;
    int ret;

    /* Register the RPC handle in the request pool */
    handle = alloc_send_handle(&fit_ctx);
    if (handle == NULL) {
        FIT_ERR("No memory for send handle\n");
        return -ENOMEM;
    }

    /* Initialize the handle */
    handle->id.node_id = fit_ctx.node_id;
    handle->id.sequence_num = alloc_sequence_num(&fit_ctx);
    sema_init(&handle->sema, 0);
    handle->ret_addr = addr,
    handle->max_ret_size = max_ret_size;
    
    /* Invoke udp_send to do transmission */
    __udp_output(&fit_ctx, target_node, 0, handle->id, addr, size);
    
    /* Wait on the the RPC handle's semaphore with timeout */
    if (timeout_sec == 0 || timeout_sec > FIT_MAX_TIMEOUT_SEC)
        timeout_sec = FIT_MAX_TIMEOUT_SEC;

    ret = down_timeout(&handle->sema, msecs_to_jiffies(timeout_sec * 1000));

    return ret;
}

int fit_reply_message(void *addr, int size, uintptr_t descriptor)
{
    return 0;
}

int fit_receive_message(unsigned int designed_port, void *ret_addr,
        int receive_size, uintptr_t *descriptor)
{
    return 0;
}
