#ifndef _INCLUDE_FIT_INTERNAL_H
#define _INCLUDE_FIT_INTERNAL_H
#ifdef _LEGO_LINUX_MODULE_
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/printk.h>
#include <linux/jiffies.h>
#else
#include <lego/types.h>
#include <lego/semaphore.h>
#include <lego/spinlock.h>
#include <lego/time.h>
#include <lego/printk.h>
#include <lego/jiffies.h>
#endif /* _LEGO_LINUX_MODULE_ */

#include <net/lwip/ip_addr.h>
#include <net/lwip/pbuf.h>
#include "fit.h"

#define FIT_LOG_LEVEL   LOGLEVEL_INFO

#define _FIT_LOG_PREFIX "FIT: "
#define fit_log(level, fmt, ...) do { \
    if (level <= FIT_LOG_LEVEL) \
        printk(_FIT_LOG_PREFIX fmt, ##__VA_ARGS__); \
    } while (0)

#define fit_err(fmt, ...) \
    fit_log(LOGLEVEL_ERR, fmt, ##__VA_ARGS__)
#define fit_warn(fmt, ...) \
    fit_log(LOGLEVEL_WARNING, fmt, ##__VA_ARGS__)
#define fit_debug(fmt, ...) \
    fit_log(LOGLEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define fit_info(fmt, ...) \
    fit_log(LOGLEVEL_INFO, fmt, ##__VA_ARGS__)

#define fit_panic(fmt, ...) \
    panic(_FIT_LOG_PREFIX fmt, ##__VA_ARGS__)

#define ARP_TMR_INTERVAL_MS   ARP_TMR_INTERVAL
#define IP_TMR_INTERVAL_MS    IP_TMR_INTERVAL
#define MIN_INTERVAL_MS       (ARP_TMR_INTERVAL_MS < IP_TMR_INTERVAL_MS ? \
                                ARP_TMR_INTERVAL_MS : IP_TMR_INTERVAL_MS)
#define ARP_TMR_INTERVAL_JIF  msecs_to_jiffies(ARP_TMR_INTERVAL_MS)
#define IP_TMR_INTERVAL_JIF   msecs_to_jiffies(IP_TMR_INTERVAL_MS)
#define MIN_IINTERVAL_JIF     msecs_to_jiffies(MIN_INTERVAL_MS)

#if defined(CONFIG_FIT_CALL_TO_THPOOL) && CONFIG_FIT_CALL_TO_THPOOL
#define FIT_CALL_TO_THPOOL
#include <memory/thread_pool.h>
#endif

#define FIT_UDP_PORT    6000U

#define FIT_NUM_HANDLE      32U
#define FIT_NUM_CONTEXT     1U
#define FIT_NUM_FREE_PBUF   64U

#define FIT_NONE_PORT       -1

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
       at the requesting node side. Should only accessed
       by the ctx_ functions. */
    fit_local_id_t  __local_id; 
} __attribute__((packed));

struct fit_msg_hdr {
    fit_node_t src_node;
    fit_node_t dst_node;
    fit_port_t src_port;
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

struct fit_context;
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
    struct semaphore input_sem;

    fit_input_cb_t input;
};

int fit_init(void);
struct fit_context *fit_new_context(fit_node_t node_id, u16 udp_port);
int fit_dispatch(void);

int fit_call(struct fit_context *ctx, fit_node_t local_port, 
    fit_node_t node, fit_port_t port, void *msg, size_t size, 
    void *ret_addr, size_t *ret_size, size_t max_ret_size);

int fit_recv(struct fit_context *ctx, fit_port_t recv_port, 
    fit_node_t *node, fit_port_t *port, uintptr_t *handle, 
    void *buf, size_t *sz, size_t buf_sz);

int fit_reply(struct fit_context *ctx, uintptr_t handle, void *msg, 
    size_t len);


#endif /* _INCLUDE_FIT_INTERNAL_H */