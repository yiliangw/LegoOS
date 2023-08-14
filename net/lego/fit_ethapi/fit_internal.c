#include <lego/bitops.h>
#include <lego/bug.h>
#include <lego/errno.h>
#include <lego/spinlock.h>
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
#include <lego/list.h>
#include <lego/fit_ibapi.h>

#include <net/netif/etharp.h>
#include <net/e1000.h>

#include <net/lwip/netif.h>
#include <net/lwip/udp.h>
#include <net/lwip/ip_addr.h>
#include <net/lwip/ip_frag.h>
#include <net/lwip/pbuf.h>

#include "fit_internal.h"

typedef struct fit_context ctx_t;

const char e1000_netif_name[] = "en";
/**
 * @brief Context of the FIT polling thread
 *
 * There is just one FIT polling thread in the system. However, this
 * polling thread can serve multiple FIT contexts. Each FIT context
 * represents a virtual FIT node with a unique node ID.
 */
static struct {
    ctx_t ctxs[FIT_NUM_CONTEXT];
    size_t num_ctx;
    struct timespec ts_etharp, ts_ipreass;
    struct netif e1000_netif;
    /* The free pbufs are produced by FIT client threads and consumed
       by the FIT polling thread. */
    struct pbuf *free_pbuf[FIT_NUM_FREE_PBUF];
    atomic_t free_pbuf_head; /* Updated by the FIT polling thread */
    atomic_t free_pbuf_tail; /* Updated by FIT client threads */
    /**
     * @brief The semaphore used to wake up the FIT polling thread
     *
     * Both the input context (i.e. the E1000 interrupt handler) and
     * the output context (i.e. the FIT API) notify the FIT polling thread
     * through this semaphore.
     */
    struct semaphore polling_sem;
} fit_polling_ctx;
#define FPC (&fit_polling_ctx)

static int produce_free_pbuf(struct pbuf *pbuf)
{
    int tail;

    while (1) {
        tail = atomic_read(&FPC->free_pbuf_tail);
        if (tail == atomic_read(&FPC->free_pbuf_head) - 1) {
            FIT_WARN("Run out of free pbuf slots\n");
            return -ENOMEM;
        }
        if (atomic_cmpxchg(&FPC->free_pbuf_tail, tail, (tail + 1) % FIT_NUM_FREE_PBUF) == tail)
            break;
    }
    FPC->free_pbuf[tail] = pbuf;
    return 0;
}

/** 
 * @note This function can only be called by the FIT polling thread.
 */
static void consume_free_pbuf(void)
{
    int tail, head;

    head = atomic_read(&FPC->free_pbuf_head);
    while ((tail = atomic_read(&FPC->free_pbuf_tail)) != head) {
        while (head != tail) {
            pbuf_free(FPC->free_pbuf[head]);
            head = (head + 1) % FIT_NUM_FREE_PBUF;
        }
        atomic_set(&FPC->free_pbuf_head, head);
    }
}

static inline long __timespec_diff_ms(struct timespec *t1, struct timespec *t2)
{
    return (t1->tv_sec - t2->tv_sec) * 1000 + (t1->tv_nsec - t2->tv_nsec) / 1000000;
}

/**
 * @brief Poke the FIT polling thread to work on input/output
 *
 * @note This function is called both in the context of E1000 interrupt 
 *       and in the context of FIT clinet threads.
 * @note This function should be called after the corresponding data
 *       is prepared. For example, it should not be called before the
 *       output is queued in the output queue of a FIT context.
 */
static void __poke_polling_thread(void)
{
    if (&FPC->polling_sem.count > 0)
        return;
    up(&FPC->polling_sem);
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
    __poke_polling_thread();
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
    if (netif_add(&FPC->e1000_netif, &ipaddr, &netmask, &gateway, NULL, e1000if_init_cb, ethernet_input) == NULL) {
        FIT_ERR("Failed to add netif\n");
        goto ip_err;
    }

    FIT_INFO("netif name: %s\n", e1000_netif_name);
    FIT_INFO("netif ip: %s\n", CONFIG_E1000_NETIF_IP);
    FIT_INFO("netif netmask: %s\n", CONFIG_E1000_NETIF_MASK);
    FIT_INFO("netif gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
    FIT_INFO("netif mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		FPC->e1000_netif.hwaddr[0], FPC->e1000_netif.hwaddr[1], FPC->e1000_netif.hwaddr[2],
        FPC->e1000_netif.hwaddr[3], FPC->e1000_netif.hwaddr[4], FPC->e1000_netif.hwaddr[5]);

    netif_set_default(&FPC->e1000_netif);
    netif_set_up(&FPC->e1000_netif);

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
lwipif_output(ctx_t *ctx, fit_port_t port, fit_node_t dst_node, fit_port_t dst_port, 
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
    hdr->src_port = port;
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
        FIT_WARN("Received packet with wrong destination node\n");
        pbuf_free(p);
        return;
    }

    ctx->input(ctx, hdr->src_node, hdr->src_port, hdr->dst_port, hdr->type, 
        &hdr->rpc_id, p, sizeof(struct fit_msg_hdr));   
}

/************************************************************************
 @} */ // end of group interface_fit_lwip


/************************************************************************
 * @defgroup fit_ctx_utils FIT Context Utilities
 * @{
 ************************************************************************/
static int
ctx_init(ctx_t *ctx, fit_node_t node_id, u16 udp_port, fit_input_cb_t input)
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

    INIT_LIST_HEAD(&ctx->input_q);
    INIT_LIST_HEAD(&ctx->output_q);
    spin_lock_init(&ctx->input_q_lock);
    spin_lock_init(&ctx->output_q_lock);

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

/**
 * Alloc a handle for the specified RPC ID. If rpcid is NULL, 
 * create a new RPC ID.
 */
static struct fit_handle *
ctx_alloc_handle(ctx_t *ctx, struct fit_rpc_id *rpcid, int alloc_seqnum)
{
    unsigned int i;
    fit_seqnum_t seqnum;
    struct fit_handle *hdl;
    
    spin_lock(&ctx->handles_lock);
    i = find_first_zero_bit(ctx->handles_bitmap, FIT_NUM_HANDLE);
    if (i == FIT_NUM_HANDLE) {
        FIT_WARN("Run out of FIT handles.\n");
        hdl = NULL;
    } else {
        set_bit(i, ctx->handles_bitmap);
        hdl = &ctx->handles[i];
    }
    spin_unlock(&ctx->handles_lock);

    if (hdl) {
        memset(hdl, 0, sizeof(struct fit_handle));
        hdl->ctx = ctx;
        if (rpcid) {
            hdl->id = *rpcid;
        } else {
            seqnum = alloc_seqnum ? ctx_alloc_sequence_num(ctx) : 0;
            hdl->id.fit_node = ctx->id;
            hdl->id.sequence_num = seqnum;
            hdl->id.__local_id = i;
        }
    }
    return hdl;
}

/**
 * @warning This function does not lock handles_lock. 
 */
static struct fit_handle *
ctx_find_handle(ctx_t *ctx, struct fit_rpc_id *rpcid)
{
    struct fit_handle *hdl;
    size_t idx = rpcid->__local_id;
    
    if (idx >= FIT_NUM_HANDLE || !test_bit(idx, ctx->handles_bitmap))
        return NULL;
    hdl = &ctx->handles[idx];

    /* Further check sequence number */
    if (hdl->id.fit_node != rpcid->fit_node || 
        hdl->id.sequence_num != rpcid->sequence_num)
        return NULL;

    return hdl;
}

static int
ctx_free_handle(ctx_t *ctx, struct fit_handle *handle)
{
    size_t idx = handle->id.__local_id;
    
    if (handle->ctx != ctx || idx >= FIT_NUM_HANDLE) {
        FIT_ERR("Invalid handle\n");
        return -EINVAL;
    }
    /* We do not need to lock here */
    handle->id.sequence_num = 0;
    if (test_and_clear_bit(idx, ctx->handles_bitmap) == 0) {
        FIT_ERR("Freeing a free recv handle\n");
        return -EPERM;
    }

    return 0;
}

static int
ctx_enque_input(ctx_t *ctx, struct fit_handle *handle)
{
    spin_lock(&ctx->input_q_lock);
    list_add_tail(&ctx->input_q, &handle->qnode);
    spin_unlock(&ctx->input_q_lock);
    return 0;
}

static int
ctx_enque_output(ctx_t *ctx, struct fit_handle *handle)
{
    spin_lock(&ctx->output_q_lock);
    list_add_tail(&ctx->output_q, &handle->qnode);
    spin_unlock(&ctx->output_q_lock);
    return 0;
}

/**
 * Concatenate all the handles in the input queue to the specified head.
 */
static void
ctx_deque_all_input(ctx_t *ctx, struct list_head *head)
{
    spin_lock(&ctx->input_q_lock);
    list_splice_init(&ctx->input_q, head);
    spin_unlock(&ctx->input_q_lock);
}

static void
ctx_deque_all_output(ctx_t *ctx, struct list_head *head)
{
    spin_lock(&ctx->output_q_lock);
    list_splice_init(&ctx->output_q, head);
    spin_unlock(&ctx->output_q_lock);
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
        FPC->e1000_netif.input(p, &FPC->e1000_netif);
    }
}

static int
do_output_call(struct fit_handle *hdl)
{
    int ret;
    ret = lwipif_output(hdl->ctx, hdl->local_port, hdl->remote_node, hdl->remote_port,
        FIT_MSG_CALL, &hdl->id, hdl->call.out_addr, hdl->call.out_len);
    return ret;
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
    int i, ret;

    for (i = 0; i < FPC->num_ctx; i++) {
        /* For each context */
        ctx_t *ctx;
        struct list_head outq;
        struct fit_handle *hdl;

        ctx = &FPC->ctxs[i];
        INIT_LIST_HEAD(&outq);
        ctx_deque_all_output(ctx, &outq);
        list_for_each_entry(hdl, &outq, qnode) {
            /* For each message */
            switch(hdl->type) {
                case FIT_HANDLE_CALL:
                    ret = do_output_call(hdl);
                    break;
                case FIT_HANDLE_RECV_CALL: // TODO:
                case FIT_HANDLE_SEND: // TODO:
                default:
                    ret = -EINVAL;
                    FIT_PANIC("Output for handle type %d not implemented.\n", hdl->type);
            }
            if (ret)
                FIT_WARN("Output failed: %d\n", ret);
        }                
    }
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
    if (__timespec_diff_ms(&ts, &FPC->ts_etharp) >= ARP_TMR_INTERVAL_MS) {
        FPC->ts_etharp = ts;
        etharp_tmr();
    }
    if (__timespec_diff_ms(&ts, &FPC->ts_ipreass) >= IP_TMR_INTERVAL_MS) {
        FPC->ts_ipreass = ts;
        ip_reass_tmr();
    }
}

static void
handle_input(ctx_t *ctx, fit_node_t node, fit_port_t port,
    fit_port_t dst_port, fit_msg_type_t type, struct fit_rpc_id *rpc_id,
    struct pbuf *pbuf, size_t pbuf_off)
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
    sema_init(&FPC->polling_sem, 0);

    /* Initialize the free pbuf list */
    atomic_set(&FPC->free_pbuf_head, 0);
    atomic_set(&FPC->free_pbuf_tail, 0);
    
    FIT_INFO("Initalized\n");
    return 0;

}

ctx_t *
fit_new_context(fit_node_t node_id, u16 udp_port)
{
    int ret;
    ctx_t *ctx;

    if (FPC->num_ctx >= FIT_NUM_CONTEXT) {
        FIT_WARN("Only support %u contexts\n", FIT_NUM_CONTEXT);
        return NULL;
    }
    ctx = &FPC->ctxs[FPC->num_ctx];

    ret = ctx_init(ctx, node_id, udp_port, handle_input);
    if (ret)
        return NULL;

    FPC->num_ctx++;
    return ctx;
}

int
fit_dispatch(void)
{
    FIT_INFO("Dispatched\n");

    FPC->ts_etharp = FPC->ts_ipreass = current_kernel_time();

    while (1) {
        down(&FPC->polling_sem);
        /* Consume the semahphore to 0 before polling the messages so that
          we will not miss any new notification. */
        while(down_trylock(&FPC->polling_sem) == 0);
        
        consume_free_pbuf();
        poll_pending_input();
        poll_pending_output();
        poll_lwip();
    }

    BUG();
    return -1;
}

/************************************************************************
 @} */ // end of group fit_polling


/************************************************************************
 * @defgroup fit_api FIT API Layer
 * 
 * These API functions run in the context of FIT client threads. The
 * client threads interact with the FIT polling thread through the
 * (sending) message queue and message handlers.
 ************************************************************************/

int fit_call(ctx_t *ctx, fit_node_t local_port, fit_node_t node, 
    fit_port_t port, void *msg, size_t size, void *ret_addr, 
    size_t *ret_size, size_t max_ret_size)
{
    int ret;
    struct fit_handle *h;
    size_t sz;

    h = ctx_alloc_handle(ctx, NULL, 1);
    if (h == NULL) {
        FIT_WARN("No available handle\n");
        return -ENOMEM;
    }
    
    /* Initialize the handle */
    h->local_port = local_port;
    h->remote_node = node;
    h->remote_port = port;
    h->errno = 0;
    h->type = FIT_HANDLE_CALL;
    h->call.out_addr = msg;
    h->call.out_len = size;

    sz = 0;
    /* Queue the message in in the output queue, poke the polling thread,
       and wait on the semaphore. */
    sema_init(&h->sem, 0);
    ctx_enque_output(ctx, h);
    __poke_polling_thread();
    ret = down_interruptible(&h->sem);
    if (ret) {
        /* TODO: Manage resources when there is a interrupt, especially
           for the in_pbuf */
        FIT_PANIC("Interrupted while waiting for reply\n");
        goto out;
    }

    /* We have been notified by the FIT thread */
    if (h->errno) {
        ret = h->errno;
        goto out;
    }

    sz = min((size_t)h->call.in_pbuf->len, max_ret_size);
    memcpy(ret_addr, h->call.in_pbuf->payload, sz);
    produce_free_pbuf(h->call.in_pbuf);
    ret = 0;
out:
    /* If there is an error, the FIT polling thread should
       free the pbuf if it exists. */
    ctx_free_handle(ctx, h);
    *ret_size = sz;
    return ret;
}
/************************************************************************
 @} */ // end of group fit_api