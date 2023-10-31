#include "fit.h"
#include "fit_conn.h"
#include "fit_sys.h"
#include "fit_context.h"

#include "fit_types.h"
#include <net/netif/etharp.h>
#include <net/e1000.h>

#include <net/lwip/netif.h>
#include <net/lwip/tcp.h>
#include <net/lwip/ip_addr.h>
#include <net/lwip/ip_frag.h>
#include <net/lwip/pbuf.h>

#ifndef _LEGO_LINUX_MODULE_
#include <lego/comp_common.h>
#endif

#include "fit_internal.h"

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
    struct {
        unsigned long etharp, ipreass, tcp;
    } next_jif;
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

/**
 * @brief Poke the FIT polling thread to work on input/output
 *
 * @note This function is called both in the context of E1000 interrupt 
 *       and in the context of FIT clinet threads.
 * @note This function should be called after the corresponding data
 *       is prepared. For example, it should not be called before the
 *       output is queued in the output queue of a FIT context.
 */
void fit_poke_polling_thread(void)
{
    if (FPC->polling_sem.count > 0)
        return;
    up(&FPC->polling_sem);
}

static void produce_free_pbuf(struct pbuf *pbuf)
{
    int tail;
    while (1) {
        tail = atomic_read(&FPC->free_pbuf_tail);
        if (tail == atomic_read(&FPC->free_pbuf_head) - 1) { /* Full */
            fit_warn("Ran out of free pbuf slots\n");
            /* Notify the polling thread to clean up */
            fit_poke_polling_thread();
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
        } else {
            if (atomic_cmpxchg(&FPC->free_pbuf_tail, tail, 
                (tail + 1) % FIT_NUM_FREE_PBUF) == tail)
                break;
        }
    }
    FPC->free_pbuf[tail] = pbuf;
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
    fit_poke_polling_thread();
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
        fit_err("Failed to receive packet: %d\n", ret);
        goto err;
    }

    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p == NULL) {
        fit_err("Failed to allocate pbuf\n");
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
    
    struct pbuf *q;
    off_t off = 0;

    for (q = p; q != NULL; q = q->next) {
        if (e1000_prepare(q->payload, q->len, off)) {
            fit_err("Failed to prepare packet\n");
            return ERR_IF;
        }
        off += q->len;
    }

    fit_debug("Transmitting packet, len: %d\n", p->tot_len);
    err = e1000_transmit(p->tot_len);
    if (err) {
        pr_err("Failed to transmit packet\n");
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
        fit_err("Invalid IP address: %s\n", CONFIG_E1000_NETIF_IP);
        goto ip_err;
    }
    if ((netmask.addr = inet_addr(CONFIG_E1000_NETIF_MASK)) == INADDR_NONE) {
        fit_err("Invalid netmask: %s\n", CONFIG_E1000_NETIF_MASK);
        goto ip_err;
    }
    if ((gateway.addr = inet_addr(CONFIG_E1000_NETIF_GATEWAY)) == INADDR_NONE) {
        fit_err("Invalid gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
        goto ip_err;
    }

    /* se should use ethernet_input here to handle Ethernet headers */
    if (netif_add(&FPC->e1000_netif, &ipaddr, &netmask, &gateway, NULL, e1000if_init_cb, ethernet_input) == NULL) {
        fit_err("Failed to add netif\n");
        goto ip_err;
    }

    fit_info("netif name: %s\n", e1000_netif_name);
    fit_info("netif ip: %s\n", CONFIG_E1000_NETIF_IP);
    fit_info("netif netmask: %s\n", CONFIG_E1000_NETIF_MASK);
    fit_info("netif gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
    fit_info("netif mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		FPC->e1000_netif.hwaddr[0], FPC->e1000_netif.hwaddr[1], FPC->e1000_netif.hwaddr[2],
        FPC->e1000_netif.hwaddr[3], FPC->e1000_netif.hwaddr[4], FPC->e1000_netif.hwaddr[5]);

    netif_set_default(&FPC->e1000_netif);
    netif_set_up(&FPC->e1000_netif);

    /* Let the E1000 driver notify the polling thread with fit_polling_sema */
    e1000_input_callback = e1000if_input_callback;

    fit_info("netif initialized\n");
    return 0;

ip_err:
    fit_err("netif initialization failed\n");
    return -EINVAL;
}
/************************************************************************
 @} */ // end of group interface_lwip_e1000


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

        fit_debug("Received packet (len=%d)\n", p->len);
        /* input has been initialized to ethernet_input */
        FPC->e1000_netif.input(p, &FPC->e1000_netif);
    }
}

static int
do_output_call(struct fit_handle *hdl)
{
    int ret;
    ctx_t *ctx = hdl->ctx;

    fit_node_t peer = hdl->remote_node;
    struct fit_conn *conn = &ctx->conns[peer];

    ret = conn_send(conn, &hdl->id, FIT_MSG_CALL, hdl->local_port,
        hdl->remote_node, hdl->remote_port, hdl->call.out_addr,
        hdl->call.out_len, NULL, NULL);

    fit_info("Out Call [%d:%d](%d) errno=%d\n", hdl->ctx->id, peer, hdl->id.sequence_num, ret);

    return ret;
}

static int
do_output_reply(struct fit_handle *hdl)
{
    int ret;
    ctx_t *ctx = hdl->ctx;

    fit_node_t peer = hdl->remote_node;
    struct fit_conn *conn = &ctx->conns[peer];

    ret = conn_send(conn, &hdl->id, FIT_MSG_REPLY, hdl->local_port,
        hdl->remote_node, hdl->remote_port, hdl->recvcall.out_addr,
        hdl->recvcall.out_len, &hdl->sem, &hdl->errno);

    fit_info("Out Reply [%d:%d](%d) errno=%d\n", hdl->remote_node, hdl->ctx->id, hdl->id.sequence_num, ret);
    return 0;
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
        struct list_head outq, busyq;
        struct fit_handle *hdl, *prev_busy_hdl;

        INIT_LIST_HEAD(&busyq);
        prev_busy_hdl = NULL;

        ctx = &FPC->ctxs[i];
        INIT_LIST_HEAD(&outq);
        ctx_deque_all_output(ctx, &outq);
        list_for_each_entry(hdl, &outq, qnode) {
            if (prev_busy_hdl) { /* We delay this becuase of list_for_each_entry() */
                /* outq is never used after this function, so we don't need to delete
                the entry from it. */
                list_add_tail(&prev_busy_hdl->qnode, &busyq);
                prev_busy_hdl = NULL;
            }

            hdl->errno = 0;
            /* For each message */
            switch(hdl->type) {
                case FIT_HANDLE_CALL:
                    ret = do_output_call(hdl);
                    /* TODO: Add timeout mechanism for call. For simplicity, we can 
                        start the counting after the polling thread doing the call */
                    break;
                case FIT_HANDLE_RECV_CALL:
                    ret = do_output_reply(hdl);
                    break;
                case FIT_HANDLE_SEND: // TODO:
                default:
                    ret = -EINVAL;
                    fit_panic("Output for handle type %d not implemented.\n", hdl->type);
            }

            if (ret) { /* It is better to manage the failures here because of the list iteration. */
                switch(-ret) {
                    case EBUSY:
                        prev_busy_hdl = hdl;
                        fit_warn("conn busy\n");
                        break;
                    default:
                        fit_warn("Output failed: %d\n", ret);
                        hdl->errno = ret;
                        up(&hdl->sem); /* Notify the client of the failure */
                }
            }
            /* Else, We shoud not notify the client at least until the sent calback is called */
        }
        if (prev_busy_hdl) /* The last one may also return EBUSY */
            list_add_tail(&prev_busy_hdl->qnode, &busyq);

        if (!list_empty(&busyq)) {
            ctx_enque_output_list(ctx, &busyq);
            fit_poke_polling_thread();
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
    unsigned long jif = jiffies;
    if (time_after(jif, FPC->next_jif.etharp)) {
        FPC->next_jif.etharp = jif + ARP_TMR_INTERVAL_JIF;
        etharp_tmr();
    }
    if (time_after(jif, FPC->next_jif.ipreass)) {
        FPC->next_jif.ipreass = jif + IP_TMR_INTERVAL_JIF;
        ip_reass_tmr();
    }
    if (time_after(jif, FPC->next_jif.tcp)) {
        FPC->next_jif.tcp = jif + TCP_TMR_INTERVAL_JIF;
        tcp_tmr();
    }
}

static void
handle_input_call(ctx_t *ctx, fit_node_t node, fit_port_t port,
    fit_port_t dst_port, struct fit_rpc_id *rpc_id, 
    struct pbuf *pbuf, off_t data_off)
{
    struct fit_handle *hdl;
    
    fit_info("In Call [%d:%d](%d)\n", node, ctx->id, rpc_id->sequence_num);
    
    hdl = ctx_alloc_handle(ctx, rpc_id, 0);
    if (hdl == NULL) {
        fit_warn("Ran out of FIT handles.\n");
        pbuf_free(pbuf);
        return;
    }
    hdl->local_port = dst_port;
    hdl->remote_node = node;
    hdl->remote_port = port;
    hdl->errno = 0;

    hdl->type = FIT_HANDLE_RECV_CALL;
    hdl->recvcall.in_pbuf = pbuf;
    hdl->recvcall.in_off = data_off;
    hdl->recvcall.out_addr = NULL;
    hdl->recvcall.out_len = 0;

#ifdef FIT_CALL_TO_THPOOL
    /* Enqueue the request (FIT call) to thpool. Here, fit_offset
       is not used in the ethernet implementation. Also, we use
       fit_imm to hold our handler. */

    {
        void *buf;
        int chain = pbuf->tot_len > pbuf->len;
        size_t tot_len = pbuf->tot_len - data_off;
        
        if (chain) {
            /* For compatability with thpool, we should malloc a continuous 
            buffer which is large enough. */
            buf = kmalloc(tot_len, GFP_KERNEL);
            pbuf_copy_partial(pbuf, buf, tot_len, data_off);
        } else {
            buf = pbuf->payload + data_off;
        }
        
        thpool_callback(ctx, hdl, 
            buf, tot_len, node, 0);

        if (chain)
            kfree(buf);
        (void) ctx_enque_input;
    }
#else
    ctx_enque_input(ctx, hdl);
#endif /* FIT_CALL_TO_THPOOL */
}

static void
handle_input_reply(ctx_t *ctx, fit_node_t node, fit_port_t port,
    fit_port_t dst_port, struct fit_rpc_id *rpc_id, 
    struct pbuf *pbuf, off_t data_off)
{
    struct fit_handle *hdl;
    unsigned seqnum = rpc_id->sequence_num;

    fit_info("In Reply [%d:%d](%d)\n", ctx->id, node, seqnum);

    hdl = ctx_find_handle(ctx, rpc_id);
    if (hdl == NULL) {
        /* Regard as a delayed reply */
        fit_warn("Cannot find the handle for the reply. Discarded.\n");
        goto err;
    }
    if (hdl->type != FIT_HANDLE_CALL) {
        fit_warn("Received a reply for a non-call handle. Discarded.\n");
        goto err;
    }
    if (hdl->local_port != dst_port || hdl->remote_node != node || 
        hdl->remote_port != port) {
        fit_warn("Received a reply for a call with conflicting \
            communication info. Discarded.\n");
        goto err;
    }
    // TODO: Deal with scenarioes when we received duplicate replies
    hdl->errno = 0;
    
    hdl->call.in_pbuf = pbuf;
    hdl->call.in_off = data_off;
    /* We do not queue it in the input queue. Just notify the caller,
       which will free the pbuf */
    up(&hdl->sem);
    return;

err:
    pbuf_free(pbuf);
    return;
}

static void
handle_input(ctx_t *ctx, fit_node_t node, fit_port_t port,
    fit_port_t dst_port, fit_msg_type_t type, struct fit_rpc_id *rpc_id,
    struct pbuf *pbuf, off_t data_off)
{
    switch(type) {
    case FIT_MSG_CALL:
        handle_input_call(ctx, node, port, dst_port, rpc_id, 
            pbuf, data_off);
        break;
    case FIT_MSG_REPLY:
        handle_input_reply(ctx, node, port, dst_port, rpc_id, 
            pbuf, data_off);
        break;
    case FIT_MSG_SEND: // TODO:
        fit_panic("input handler not implemented for message type %d\n",
            type);
    default:
        fit_err("Invalid message type %d\n", type);
        pbuf_free(pbuf);
        break;
    }
}

static unsigned long 
__polling_sem_timeout_jif(void)
{
    unsigned long jif, etharp_diff, ipreass_diff, tcp_diff;
    const unsigned long min_diff = MIN_IINTERVAL_JIF;
    jif = jiffies;
    etharp_diff = FPC->next_jif.etharp - jif;
    ipreass_diff = FPC->next_jif.ipreass - jif;
    tcp_diff = FPC->next_jif.tcp - jif;

    jif = etharp_diff < ipreass_diff ? etharp_diff : ipreass_diff;
    jif = jif < tcp_diff ? jif : tcp_diff;
    if (jif > min_diff) {
        /* Could be caused by wraparound or already timedout */ 
        return 0;
    }
    return jif;
}

static int
fit_polling_thread_fn(void *_arg)
{
#ifndef _LEGO_LINUX_MODULE_
    if (pin_current_thread())
        fit_panic("Fail to pin FIT polling thread");
#endif

    FPC->next_jif.etharp = jiffies + ARP_TMR_INTERVAL_JIF;
    FPC->next_jif.ipreass = jiffies + IP_TMR_INTERVAL_JIF;
    FPC->next_jif.tcp = jiffies + TCP_TMR_INTERVAL_JIF;

    while (1) {
        // unsigned jif = __polling_sem_timeout_jif();
        // if (jif)
            // down_timeout(&FPC->polling_sem, jif);
        /* Consume the semahphore to 0 before polling the messages so that
          we will not miss any new notification. */
        // while(down_trylock(&FPC->polling_sem) == 0);
        
        consume_free_pbuf();
        poll_lwip();
        poll_pending_input();
        poll_pending_output();
    }

    BUG();
    return -1;
}

/************************************************************************
 @} */ // end of group fit_polling


/************************************************************************
 * @defgroup fit_init FIT Initialization
 * 
 * Called in the context to initialize FIT.
 * @{
 ************************************************************************/

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
    
    fit_info("Initalized\n");
    return 0;

}

ctx_t *
fit_new_context(fit_node_t node_id)
{
    int ret;
    ctx_t *ctx;

    if (FPC->num_ctx >= FIT_NUM_CONTEXT) {
        fit_warn("Only support %u contexts\n", FIT_NUM_CONTEXT);
        return NULL;
    }
    ctx = &FPC->ctxs[FPC->num_ctx];

    ret = ctx_init(ctx, node_id, handle_input);
    if (ret)
        return NULL;

    FPC->num_ctx++;
    return ctx;
}

int
fit_dispatch(void)
{
    kthread_run(fit_polling_thread_fn, NULL, "FIT-polling");
    fit_info("Dispatched FIT polling thread.\n");
    return 0;
}

/************************************************************************
 @} */ // end of group fit_initialization


/************************************************************************
 * @defgroup fit_api FIT API Layer
 * 
 * These API functions run in the context of FIT client threads. The
 * client threads interact with the FIT polling thread through the
 * (sending) message queue and message handlers.
 ************************************************************************/

int 
fit_call(ctx_t *ctx, fit_node_t local_port, fit_node_t node, 
    fit_port_t port, void *msg, size_t size, void *ret_addr, 
    size_t *ret_size, size_t max_ret_size)
{
    int ret;
    struct fit_handle *h;
    size_t sz = 0;  /* Default value for failure */

    h = ctx_alloc_handle(ctx, NULL, 1);
    if (h == NULL) {
        fit_warn("No available handle\n");
        ret = -ENOMEM;
        goto before_alloc_handle;
    }

    /* Initialize the handle */
    h->local_port = local_port;
    h->remote_node = node;
    h->remote_port = port;
    h->errno = 0;
    h->type = FIT_HANDLE_CALL;
    h->call.out_addr = msg;
    h->call.out_len = size;

    /* Enque the message to the output queue, poke the polling thread,
       and wait on the semaphore. */
    sema_init(&h->sem, 0);
    ctx_enque_output(ctx, h);
    fit_poke_polling_thread();
    ret = down_interruptible(&h->sem);
    if (ret) {
        /* TODO: Manage resources when there is a interrupt, especially
           for the in_pbuf */
        fit_panic("Interrupted while waiting for reply\n");
        goto after_alloc_handle;
    }

    /* We have been notified by the FIT thread */
    if (h->errno) {
        /* When there is an error, the possible pbuf should be freed by
           the polling thread */
        ret = h->errno;
        goto after_alloc_handle;
    }

    sz = h->call.in_pbuf->tot_len - h->call.in_off;

    if (sz > max_ret_size) {
        fit_warn("Buffer size is not enough\n");
        produce_free_pbuf(h->call.in_pbuf);
        sz = 0;
        ret = -ENOMEM;
        goto after_alloc_handle;
    }

    pbuf_copy_partial(h->call.in_pbuf, ret_addr, sz, h->call.in_off);
    produce_free_pbuf(h->call.in_pbuf);
    ret = 0;
after_alloc_handle:
    /* If there is an error, the FIT polling thread should
       free the pbuf if it exists. */
    ctx_free_handle(ctx, h);
before_alloc_handle:
    *ret_size = sz;
    return ret;
}

int
fit_recv(ctx_t *ctx, fit_port_t recv_port, fit_node_t *node, 
    fit_port_t *port, uintptr_t *handle, void *buf, size_t *sz, 
    size_t buf_sz)
{
    // TODO: Receive from different ports
    int ret;
    struct fit_handle *hdl;
    size_t _sz;

    ret = ctx_deque_input(ctx, &hdl);
    if (ret) { /* Woke up by signal */
        fit_warn("Interrupted while waiting for message\n");
        goto err;
    }

    switch (hdl->type) {
    case FIT_HANDLE_RECV_CALL:
        _sz = hdl->recvcall.in_pbuf->tot_len - hdl->recvcall.in_off;
        if (_sz > buf_sz) {
            fit_warn("Buffer size is not enough\n");
            produce_free_pbuf(hdl->recvcall.in_pbuf);
            ret = -ENOMEM;
            goto err;
        }
        *node = hdl->remote_node;
        *port = hdl->remote_port;
        *handle = (uintptr_t)hdl;
        *sz = _sz;
        pbuf_copy_partial(hdl->recvcall.in_pbuf, buf, _sz, 
            hdl->recvcall.in_off);
        produce_free_pbuf(hdl->recvcall.in_pbuf);
        /* Cannot free the handle here because the corresponding reply 
           will depend on it. Do it in fit_reply(). */
        break;
    case FIT_HANDLE_RECV_SEND:
        // TODO:
        fit_panic("Not implemented\n");
        /* Can free the handle immediately since there is no reply */
        break;
    default:
        fit_panic("Invalid handle type(%d) in the input queue\n", 
            hdl->type);
    }

    return 0;
err:
    *node = 0;
    *port = 0;
    *handle = 0;
    *sz = 0;
    return ret;
}

int 
fit_reply(ctx_t *ctx, uintptr_t handle, void *msg, size_t len)
{
    int ret;
    struct fit_handle *hdl;

    hdl = (struct fit_handle *)handle;
    // TODO: Do some other check on the handle
    if (hdl->ctx != ctx || hdl->type != FIT_HANDLE_RECV_CALL) {
        fit_err("Invalid handle\n");
        return -EINVAL;
    }

    hdl->recvcall.out_addr = msg;
    hdl->recvcall.out_len = len;

    hdl->errno = 0;
    sema_init(&hdl->sem, 0);
    ctx_enque_output(ctx, hdl);
    fit_poke_polling_thread();
    ret = down_interruptible(&hdl->sem);
    if (ret) {
        // TODO: Manage resources when there is a interrupt.
        fit_panic("Interrupted while doing reply\n");
        goto out;
    }

    /* Norified by the FIT polling thread */
    ret = hdl->errno;
out:
    ctx_free_handle(ctx, hdl);
    return ret;
}

#ifdef FIT_CALL_TO_THPOOL
void 
fit_ack_reply_callback(struct thpool_buffer *b)
{
    ctx_t *ctx;
    struct fit_handle *hdl;
    void *reply_data;
    size_t reply_len;

    ctx = (ctx_t *)b->fit_ctx;
    hdl = (struct fit_handle *)b->fit_imm;

    /* Confirm the type */
    BUG_ON(hdl->type != FIT_HANDLE_RECV_CALL &&
        hdl->type != FIT_HANDLE_RECV_SEND);
    
    /* We could have done this earlier but for compatability
       with the thpool implementation */
    produce_free_pbuf(hdl->recvcall.in_pbuf);
    
    if (ThpoolBufferNoreply(b)) {
        /* No need to reply */
        if (hdl->type == FIT_HANDLE_RECV_CALL)
            fit_warn("Not replying to a call.");
        ctx_free_handle(ctx, hdl);
        return;
    }

    if (ThpoolBufferPrivateTX(b))
        reply_data = b->private_tx;
    else
        reply_data = b->tx;
    reply_len = b->tx_size;

    /* Do the reply. Notice that ctx_free_handle has been already 
       called inside */
    fit_reply(ctx, (uintptr_t) hdl, reply_data, reply_len);
}
#endif /* FIT_CALL_TO_THPOOL */
/************************************************************************
 @} */ // end of group fit_api
