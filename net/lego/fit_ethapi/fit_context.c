
#include "fit.h"
#include "fit_sys.h"
#include "fit_log.h"
#include "fit_types.h"

#include <net/lwip/ip_addr.h>

#include "fit_context.h"

#define FIT_TCP_PORT_BASE 6000U
#define FIT_PEER_PORT(node) (node + FIT_TCP_PORT_BASE)

static int
__setup_connection(ctx_t *ctx)
{
    /*
     * Rules:
     * 1. Node with bigger ID set up the connection actively.
     * 2. Node with smaller ID set up the connection passively. 
     * 3. Set up connections in the ascending order of peer node ID.
     *
     * Reference: https://lwip.fandom.com/wiki/Raw/TCP
     */
    const fit_node_t me = ctx->id;
    fit_node_t node;
    int ret;

    memset(ctx->conns, 0, sizeof(ctx->conns));

    for (node = 0; node < FIT_NUM_NODE; node++) {
        struct fit_conn *conn;
        struct ip_addr *ipaddr;
        u16_t bind_port, peer_port;
        if (node == me)
            continue;         

        conn = &ctx->conns[node];
        ipaddr = &ctx->node_ip_addrs[node];
        bind_port = FIT_PEER_PORT(node);
        peer_port = FIT_PEER_PORT(me);

        ret = conn_init(conn, ctx, bind_port, node, ipaddr, peer_port, 
            me > node);
        if (ret)
            return ret;
    }
    return ret;
}

static fit_seqnum_t
__alloc_sequence_num(ctx_t *ctx)
{
    fit_seqnum_t num;
    spin_lock(&ctx->sequence_num_lock);
    num = ctx->sequence_num++;
    spin_unlock(&ctx->sequence_num_lock);
    return num;
}

int
ctx_init(ctx_t *ctx, fit_node_t node_id, fit_input_cb_t input)
{
    memset(ctx, 0, sizeof(ctx_t));
    ctx->id = node_id;

    /* Hardcode the IP table*/
    IP4_ADDR(&ctx->node_ip_addrs[0], 10, 0, 2, 15);
    IP4_ADDR(&ctx->node_ip_addrs[1], 10, 0, 2, 16);
    IP4_ADDR(&ctx->node_ip_addrs[2], 10, 0, 2, 17);

    ctx->sequence_num = 0;
    spin_lock_init(&ctx->sequence_num_lock);

    spin_lock_init(&ctx->handles_lock);

    INIT_LIST_HEAD(&ctx->input_q);
    INIT_LIST_HEAD(&ctx->output_q);
    spin_lock_init(&ctx->input_q_lock);
    spin_lock_init(&ctx->output_q_lock);

    sema_init(&ctx->input_sem, 0);

    __setup_connection(ctx);

    ctx->input = input;
    return 0;
}


/**
 * Alloc a handle for the specified RPC ID. If rpcid is NULL, 
 * create a new RPC ID.
 */
struct fit_handle *
ctx_alloc_handle(ctx_t *ctx, struct fit_rpc_id *rpcid, int alloc_seqnum)
{
    unsigned int i;
    fit_seqnum_t seqnum;
    struct fit_handle *hdl;
    
    spin_lock(&ctx->handles_lock);
    i = find_first_zero_bit(ctx->handles_bitmap, FIT_NUM_HANDLE);
    if (i == FIT_NUM_HANDLE) {
        fit_warn("Run out of FIT handles.\n");
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
            seqnum = alloc_seqnum ? __alloc_sequence_num(ctx) : 0;
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
struct fit_handle *
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

int
ctx_free_handle(ctx_t *ctx, struct fit_handle *handle)
{
    size_t idx = handle - ctx->handles;
    /* We should not use handle->id.__local_id here because
       this is the local identity of the sender / caller. */
    
    if (handle->ctx != ctx || idx >= FIT_NUM_HANDLE) {
        fit_err("Invalid handle\n");
        return -EINVAL;
    }
    /* We do not need to lock here */
    handle->id.sequence_num = 0;
    if (test_and_clear_bit(idx, ctx->handles_bitmap) == 0) {
        fit_err("Freeing a free recv handle\n");
        return -EPERM;
    }

    return 0;
}

int
ctx_enque_input(ctx_t *ctx, struct fit_handle *handle)
{
    spin_lock(&ctx->input_q_lock);
    list_add_tail(&handle->qnode, &ctx->input_q);
    spin_unlock(&ctx->input_q_lock);
    up(&ctx->input_sem);
    return 0;
}

int
ctx_enque_output(ctx_t *ctx, struct fit_handle *handle)
{
    spin_lock(&ctx->output_q_lock);
    list_add_tail(&handle->qnode, &ctx->output_q);
    spin_unlock(&ctx->output_q_lock);
    return 0;
}

int
ctx_deque_input(ctx_t *ctx, struct fit_handle **phandle)
{
    struct fit_handle *hdl;
    if (down_interruptible(&ctx->input_sem))
        return -EINTR;
    spin_lock(&ctx->input_q_lock);
    hdl = list_first_entry(&ctx->input_q, struct fit_handle, qnode);
    list_del_init(&hdl->qnode);
    spin_unlock(&ctx->input_q_lock);
    *phandle = hdl;
    return 0;
}

void
ctx_deque_all_output(ctx_t *ctx, struct list_head *head)
{
    spin_lock(&ctx->output_q_lock);
    list_splice_init(&ctx->output_q, head);
    spin_unlock(&ctx->output_q_lock);
}
