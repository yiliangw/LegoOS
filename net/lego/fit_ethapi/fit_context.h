#ifndef _INCLUDE_FIT_CONTEXT_H_
#define _INCLUDE_FIT_CONTEXT_H_

#include "fit.h"
#include "fit_types.h"
#include "fit_conn.h"

#include <net/lwip/ip_addr.h>

#define FIT_NUM_HANDLE      32U

struct fit_context;
struct fit_handle;

/**
 * @brief FIT handle types
 * 
 * @note There is no REPLY handle type. RECV_CALL is used for fit_call.
 */
enum fit_handle_type {
    FIT_HANDLE_CALL = 1,
    FIT_HANDLE_SEND,        
    FIT_HANDLE_RECV_CALL,   /* When the received message is a call */
    FIT_HANDLE_RECV_SEND,   /* When the received message is a send */
};

struct fit_handle {
    struct fit_rpc_id id;
    struct fit_context *ctx;
    fit_port_t local_port;
    fit_node_t remote_node;
    fit_port_t remote_port;
    struct semaphore sem; /* Should always be initialized by the waiter */
    struct list_head qnode; /* Anchor for input/output queue */
    int errno;
    enum fit_handle_type type;
    union {
        struct {
            void *out_addr;
            size_t out_len;
            struct pbuf *in_pbuf;
            off_t in_off;
        } call;
        struct {
            void *out_addr;
            size_t out_len;
        } send;
        struct {
            struct pbuf *in_pbuf;
            off_t in_off;
            void *out_addr;
            size_t out_len;
        } recvcall;
        struct {
            struct pbuf *in_pbuf;
            off_t in_off;
        } recvsend;
    };
};

typedef void (*fit_input_cb_t)(
    struct fit_context *ctx, 
    fit_node_t src_node,
    fit_port_t src_port,
    fit_port_t dst_port, 
    fit_msg_type_t msg_type, 
    struct fit_rpc_id *rpc_id, 
    struct pbuf *pbuf,
    off_t pbuf_off
);

struct fit_context {
    /* Identity */
    fit_node_t id;
    /* lwIP TCP context */
    struct ip_addr node_ip_addrs[FIT_NUM_NODE];
    struct fit_conn conns[FIT_NUM_NODE];
    /* RPC sequence number */
    fit_seqnum_t sequence_num;
    spinlock_t sequence_num_lock;
    /* RPC handles */
    struct fit_handle handles[FIT_NUM_HANDLE];
    unsigned long handles_bitmap[(FIT_NUM_HANDLE + BITS_PER_LONG - 1) / BITS_PER_LONG];
    spinlock_t handles_lock;

    struct list_head output_q;
    spinlock_t output_q_lock;
    struct list_head input_q;
    spinlock_t input_q_lock;
    struct semaphore input_sem;

    fit_input_cb_t input;
};
typedef struct fit_context ctx_t;

int ctx_init(ctx_t *ctx, fit_node_t node_id, fit_input_cb_t input);
int ctx_ready(ctx_t *ctx);
struct fit_handle *ctx_alloc_handle(ctx_t *ctx, struct fit_rpc_id *rpcid,
    int alloc_seqnum);
struct fit_handle *ctx_find_handle(ctx_t *ctx, struct fit_rpc_id *rpcid);
int ctx_free_handle(ctx_t *ctx, struct fit_handle *handle);
int ctx_enque_input(ctx_t *ctx, struct fit_handle *handle);
int ctx_enque_output(ctx_t *ctx, struct fit_handle *handle);
int ctx_enque_output_list(ctx_t *ctx, struct list_head *head);
int ctx_deque_input(ctx_t *ctx, struct fit_handle **phandle);
void ctx_deque_all_output(ctx_t *ctx, struct list_head *head);

#endif /* _INCLUDE_FIT_CONTEXT_H_ */
