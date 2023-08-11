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


typedef struct fit_context ctx_t;
static struct timespec ts_etharp, ts_ipreass;

/**
 * @brief The semaphore used to wake up the FIT polling thread
 *
 * Both the input context (i.e. the E1000 interrupt handler) and
 * the output context (i.e. the FIT API) notify the FIT polling thread
 * through this semaphore.
 */
static struct semaphore fit_polling_sem;


static inline long __timespec_diff_ms(struct timespec *t1, struct timespec *t2)
{
    return (t1->tv_sec - t2->tv_sec) * 1000 + (t1->tv_nsec - t2->tv_nsec) / 1000000;
}


/************************************************************************
 * @defgroup interface_lwip_e1000 LwIP's interface with E1000 driver
 * @{
 ***********************************************************************/
/**
 * This function is registerd to be called as the top half in the 
 * context of E1000 interrupt.
 */
static void 
e1000if_input_callback(void)
{
    FIT_DEBUG("E1000 interrupt detected\n");
    up(&fit_polling_sem);
}

static int
e1000if_low_level_input(struct pbuf **head)
{
    // TODO: remove the redundant copy
    u8 buf[0x5EE];
    
    struct pbuf *p, *q;
    u16 len, copied_len;
    int ret;

    ret = e1000_receive(buf, &len);
    if (ret) {
        FIT_ERR("Failed to receive packet: %d\n", ret);
        goto err;
    }

    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p == NULL) {
        FIT_ERR("Failed to allocate pbuf\n");
        ret = -ENOMEM;
        goto err;
    }

    copied_len = 0;
    for (q = p; q != NULL; q = q->next) {
        int bytes = q->len;
        if (bytes > (len - copied_len))
            bytes = len - copied_len;
        memcpy(q->payload, buf + copied_len, bytes);
        copied_len += bytes;
    }
    *head = p;
    return 0;

err:
    /* 
     * No matter what the error is, we discard this packet 
     * to keep consistency in a simple way.
     */
    e1000_clear_pending_reception(1);
    *head = NULL;
    return ret;
}

static err_t
e1000if_low_level_output(struct netif *netif, struct pbuf *p)
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

static err_t 
e1000if_init_cb(struct netif *netif)
{
    int i;

    netif->state = NULL;
    netif->output = etharp_output;
    netif->linkoutput = e1000if_low_level_output;
    memcpy(&netif->name[0], e1000_netif_name, strlen(e1000_netif_name));

    /* Low-level initialization */
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    for (i = 0; i < ETHARP_HWADDR_LEN; i++)
        netif->hwaddr[i] = e1000_mac[i];

    /* We should have called e1000_init() by now, but the input callback has 
        not been set yet */

    etharp_init();
    return ERR_OK;
}

static int 
e1000if_init(void)
{
    struct ip_addr ipaddr, netmask, gateway;
    
    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&netmask, 0, sizeof(netmask));
    memset(&gateway, 0, sizeof(gateway));

    if ((ipaddr.addr = inet_addr(CONFIG_E1000_NETIF_IP)) == INADDR_NONE) {
        FIT_ERR("Invalid IP address: %s\n", CONFIG_E1000_NETIF_IP);
        goto ip_err;
    }
    if ((netmask.addr = inet_addr(CONFIG_E1000_NETIF_MASK)) == INADDR_NONE) {
        FIT_ERR("Invalid netmask: %s\n", CONFIG_E1000_NETIF_MASK);
        goto ip_err;
    }
    if ((gateway.addr = inet_addr(CONFIG_E1000_NETIF_GATEWAY)) == INADDR_NONE) {
        FIT_ERR("Invalid gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
        goto ip_err;
    }

    /* se should use ethernet_input here to handle Ethernet headers */
    if (netif_add(&e1000_netif, &ipaddr, &netmask, &gateway, NULL, e1000if_init_cb, ethernet_input) == NULL) {
        FIT_ERR("Failed to add netif\n");
        goto ip_err;
    }

    FIT_INFO("netif name: %s\n", e1000_netif_name);
    FIT_INFO("netif ip: %s\n", CONFIG_E1000_NETIF_IP);
    FIT_INFO("netif netmask: %s\n", CONFIG_E1000_NETIF_MASK);
    FIT_INFO("netif gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
    FIT_INFO("netif mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		e1000_netif.hwaddr[0], e1000_netif.hwaddr[1], e1000_netif.hwaddr[2],
        e1000_netif.hwaddr[3], e1000_netif.hwaddr[4], e1000_netif.hwaddr[5]);

    netif_set_default(&e1000_netif);
    netif_set_up(&e1000_netif);

    /* Let the E1000 driver notify the polling thread with fit_polling_sema */
    e1000_input_callback = e1000if_input_callback;

    FIT_INFO("netif initialized\n");
    return 0;

ip_err:
    FIT_ERR("netif initialization failed\n");
    return -EINVAL;
}
/************************************************************************
 @} */ // end of group interface_lwip_e1000

/************************************************************************
 * @defgroup interface_fit_lwip LwIP's interface with the FIT polling 
            threead
 * @{
 ***********************************************************************/
static int
lwipif_output(ctx_t *ctx, int dst_node, int dst_port, 
    enum fit_msg_type type, struct fit_rpc_id *rpc_id, void *msg, size_t len)
{
    struct pbuf *p;
    int ret;
    struct ip_addr *dst_ip;
    struct fit_msg_hdr *hdr;

    if (dst_node >= FIT_NUM_NODE) {
        FIT_ERR("Invalid node number\n");
        return -EINVAL;
    }
    dst_ip = &ctx->node_ip_addr[dst_node];

    p = pbuf_alloc(PBUF_TRANSPORT, len + sizeof(struct fit_msg_hdr), 
        PBUF_RAM);
    if (p == NULL) {
        FIT_ERR("Failed to allocate pbuf\n");
        return -ENOMEM;
    }

    /* set FIT header */
    hdr = (struct fit_msg_hdr *)p->payload;
    hdr->rpc_id = *rpc_id;
    hdr->type = type;
    hdr->src_node = ctx->id;
    hdr->dst_node = dst_node;
    hdr->dst_port = dst_port;

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

static void
lwipif_input_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, 
    struct ip_addr *addr, u16_t port)
{
    ctx_t *ctx = (ctx_t *)arg;
    struct fit_msg_hdr *hdr;

    FIT_DEBUG("ctx[%d]eceived packet from port %d, length=%u\n", 
        ctx->id, port, p->len);

    hdr = (struct fit_msg_hdr *) p->payload;
    if (hdr->dst_node != ctx->id) {
        FIT_ERR("Received packet with wrong destination node\n");
        pbuf_free(p);
        return;
    }

    ctx->input(ctx, hdr->src_node, hdr->dst_port, hdr->type, 
        &hdr->rpc_id, p->payload+sizeof(struct fit_msg_hdr), hdr->length);    

    pbuf_free(p);
}

/************************************************************************
 @} */ // end of group interface_fit_lwip


/************************************************************************
 * @defgroup fit_ctx_utils FIT Context Utilities
 * @{
 ************************************************************************/
static int
ctx_init(ctx_t *ctx, fit_node_id_t node_id, u16 udp_port, fit_input_cb_t input)
{
    memset(ctx, 0, sizeof(ctx_t));
    ctx->id = node_id;

    /* Set up UDP */
    ctx->udp_port = udp_port;
    ctx->pcb = udp_new();
    if (ctx->pcb == NULL) {
        FIT_ERR("Fail to create udp pcb\n");
        return -ENOMEM;
    }
    udp_bind(ctx->pcb, IP_ADDR_ANY, ctx->udp_port);
    udp_recv(ctx->pcb, lwipif_input_cb, ctx);
    
    /* Hardcode the IP table*/
    IP4_ADDR(&ctx->node_ip_addr[0], 10, 0, 2, 15);
    IP4_ADDR(&ctx->node_ip_addr[1], 10, 0, 2, 16);

    ctx->sequence_num = 0;
    spin_lock_init(&ctx->sequence_num_lock);
    spin_lock_init(&ctx->handles_lock);

    ctx->input = input;
    return 0;
}

static fit_seqnum_t
ctx_alloc_sequence_num(ctx_t *ctx)
{
    fit_seqnum_t num;
    spin_lock(&ctx->sequence_num_lock);
    num = ctx->sequence_num++;
    spin_unlock(&ctx->sequence_num_lock);
    return num;
}

static struct fit_handle *
ctx_alloc_handle(ctx_t *ctx)
{
    unsigned int i;
    struct fit_handle *handle;
    spin_lock(&ctx->handles_lock);
    i = find_first_zero_bit(ctx->handles_bitmap, FIT_NUM_HANDLE);
    if (i == FIT_NUM_HANDLE)
        handle = NULL;
    else
        handle = &ctx->handles[i];
    spin_unlock(&ctx->handles_lock);
    return handle;
}

static int
ctx_free_rhandle(ctx_t *ctx, struct fit_handle *handle)
{
    int i = handle - ctx->handles;
    if (i < 0 || i >= FIT_NUM_HANDLE) {
        FIT_ERR("Invalid recv handle\n");
        return -EINVAL;
    }
    /* We do not need to lock here */
    if (test_and_clear_bit(i, ctx->handles_bitmap) == 0) {
        FIT_ERR("Freeing a free recv handle\n");
        return -EPERM;
    }
    return 0;
}
/************************************************************************
 @} */ // end of fit_ctx_utils


/************************************************************************
 * @defgroup fit_polling Main Polling Logic of FIT
 * @{
 ************************************************************************/
/**
 * @brief Poll the pending input messages from E1000
 *
 * Deliver all avaialbe input messages in E1000 through lwIP with 
 * best effort.
 */
static void
poll_pending_input(void)
{
    int ret;
    struct pbuf *p;

    while(e1000_pending_reception()) {
        ret = e1000if_low_level_input(&p);
        /* e1000if_low_level_input should take care of the error */
        if (ret)
            continue;
        BUG_ON(p == NULL);

        FIT_DEBUG("Received packet (len=%d)\n", p->len);
        /* input has been initialized to ethernet_input */
        e1000_netif.input(p, &e1000_netif);
    }
}

/**
 * @brief Poll the pending output messages from the FIT API layer
 * 
 * Flush all pending output messages through lwIP to E1000 with
 * best effort.
 */
static void
poll_pending_output(void)
{
    // TODO:
}

/**
 * @brief Poll the lwIP stack
 * 
 * Poll the reassembly timer and ARP timer of lwIP stack.
 */
static void
poll_lwip(void)
{
    struct timespec ts;

    ts = current_kernel_time();
    if (__timespec_diff_ms(&ts, &ts_etharp) >= ARP_TMR_INTERVAL_MS) {
        ts_etharp = ts;
        etharp_tmr();
    }
    if (__timespec_diff_ms(&ts, &ts_ipreass) >= IP_TMR_INTERVAL_MS) {
        ts_ipreass = ts;
        ip_reass_tmr();
    }
}

static void
handle_input(ctx_t *ctx, fit_node_id_t node, fit_port_id_t port,
    fit_msg_type_t type, struct fit_rpc_id *rpc_id, 
    void *msg, fit_msg_len_t len)
{
    // TODO:
}

int
fit_init(void)
{
    int ret;
    
    /* Initialize the interface with E1000 driver */
    ret = e1000if_init();
    if (ret)
        return ret;

    /* Initialize the polling semaphore */
    sema_init(&fit_polling_sem, 0);
    
    FIT_INFO("Initalized\n");
    return 0;

}

int
fit_add_context(ctx_t *ctx, fit_node_id_t node_id, u16 udp_port)
{
    int ret;
    ret = ctx_init(ctx, node_id, udp_port, handle_input);
    if (ret)
        return ret;
    return 0;
}

int
fit_dispatch(void)
{
    FIT_INFO("Dispatched\n");

    ts_etharp = ts_ipreass = current_kernel_time();

    while (1) {
        down(&fit_polling_sem);
        /* 
         * Down the semahphore to 0 before polling the messages to prevent
         * missing any new one
         */
        while(down_trylock(&fit_polling_sem) == 0);
        
        poll_pending_input();
        poll_pending_output();
        poll_lwip();
    }

    BUG();
    return -1;
}

/************************************************************************
 @} */ // end of group fit_polling