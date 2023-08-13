#ifndef _INCLUDE_FIT_INTERNAL_H
#define _INCLUDE_FIT_INTERNAL_H

#include <lego/types.h>
#include <lego/semaphore.h>
#include <lego/spinlock.h>
#include <lego/time.h>
#include <net/lwip/ip_addr.h>
#include "fit.h"

#define FIT_ERR(fmt, ...) \
    pr_err("Ethernet FIT: " fmt, ##__VA_ARGS__)
#define FIT_WARN(fmt, ...) \
    pr_warn("Ethernet FIT: " fmt, ##__VA_ARGS__)
#define FIT_DEBUG(fmt, ...) \
    pr_debug("Ethernet FIT: " fmt, ##__VA_ARGS__)
#define FIT_INFO(fmt, ...) \
    pr_info("Ethernet FIT: " fmt, ##__VA_ARGS__)

#define FIT_PANIC(fmt, ...) \
    panic("Ethernet FIT: " fmt, ##__VA_ARGS__)

#define ARP_TMR_INTERVAL_MS     ARP_TMR_INTERVAL
#define IP_TMR_INTERVAL_MS      IP_TMR_INTERVAL
#define SEM_DOWN_TIMEOUT_MS     (MIN(ARP_TMR_INTERVAL_MS, IP_TMR_INTERVAL_MS) + 10)

#define FIT_UDP_PORT    6000U

#define FIT_NUM_HANDLE      32U
#define FIT_NUM_CONTEXT     1U

/** 
 * @defgroup fit_network_types FIT Types over Network
 * Data types which may be transmitted over the network should be defined 
 * with specified length for portability.
 * @{
 */
typedef s32 fit_node_t;
typedef s32 fit_port_t;
typedef u32 fit_seqnum_t;
typedef u32 fit_msg_len_t;
typedef u32 fit_local_id_t;
typedef u8 fit_msg_type_t;
enum fit_msg_type {
    FIT_MSG_CALL = 1,
    FIT_MSG_REPLY,
    FIT_MSG_SEND
};

struct fit_rpc_id {
    fit_node_t   fit_node;
    fit_seqnum_t    sequence_num;
    /* Provide extra information to locate the handle
       at the requesting node side */
    fit_local_id_t  local_id; 
} __attribute__((packed)) fit_rpc_id_t;

struct fit_msg_hdr {
    fit_node_t src_node;
    fit_node_t dst_node;
    fit_port_t dst_port;
    fit_msg_len_t length;
    fit_msg_type_t type;
    struct fit_rpc_id rpc_id;
} __attribute__((packed));
/** @} */ // end of group fit_network_types

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
    struct semaphore sem;
    struct list_head qnode; /* Anchor for input/output queue */
    int errno;
    enum fit_handle_type type;
    union {
        struct {
            void *out_addr;
            size_t out_len;
            void *in_addr;
            size_t in_len;
        } call;
        struct {
            void *out_addr;
            size_t out_len;
        } send;
        struct {
            void *in_addr;
            size_t in_len;
            void *out_addr;
            size_t out_len;
        } recvcall;
        struct {
            void *in_addr;
            size_t in_len;
        } recvsend;
    };
};

struct fit_context;
typedef void (*fit_input_cb_t)(
    struct fit_context *ctx, 
    fit_node_t src_node, 
    fit_port_t dst_port, 
    fit_msg_type_t msg_type, 
    struct fit_rpc_id *rpc_id, 
    void *msg, fit_msg_len_t len
);

struct fit_context {
    /* Identity */
    fit_node_t id;
    /* lwIP UDP context */
    struct udp_pcb *pcb;
    struct ip_addr node_ip_addr[FIT_NUM_NODE];
    u16 udp_port;
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

    fit_input_cb_t input;
};

int fit_init(void);
struct fit_context *fit_new_context(fit_node_t node_id, u16 udp_port);
int fit_dispatch(void);



#endif /* _INCLUDE_FIT_INTERNAL_H */