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

#define FIT_NUM_SEND_HANDLE      32
#define FIT_NUM_RECV_HANDLE      32

/** 
 * @defgroup fit_network_types FIT Types over Network
 * Data types which may be transmitted over the network should be defined 
 * with specified length for portability.
 * @{
 */
typedef s32 fit_node_id_t;
typedef s32 fit_port_id_t;
typedef u32 fit_seqnum_t;
typedef u32 fit_msg_len_t;

typedef u8 fit_msg_type_t;
enum fit_msg_type {
    FIT_CALL,
    FIT_REPLY,
    FIT_SEND
};

struct fit_rpc_id {
    fit_node_id_t fit_node;
    fit_seqnum_t sequence_num;
} __attribute__((packed)) fit_rpc_id_t;

struct fit_msg_hdr {
    fit_node_id_t src_node;
    fit_node_id_t dst_node;
    fit_port_id_t dst_port;
    fit_msg_len_t length;
    fit_msg_type_t type;
    struct fit_rpc_id rpc_id;
} __attribute__((packed));
/** @} */ // end of group fit_network_types

/* FIT sending handle */
struct fit_s_handle {
    struct fit_rpc_id id;
    struct semaphore sema;
    void *ret_addr;
    int max_ret_size;
};

/* FIT receiving handle */
struct fit_r_handle {
    struct fit_rpc_id rpc_id;
};

struct fit_context;
typedef void (*fit_input_cb_t)(
    struct fit_context *ctx, 
    fit_node_id_t src_node, 
    fit_port_id_t dst_port, 
    fit_msg_type_t msg_type, 
    struct fit_rpc_id *rpc_id, 
    void *msg, fit_msg_len_t len
);

struct fit_context {
    /* Identity */
    fit_node_id_t id;
    /* lwIP UDP context */
    struct udp_pcb *pcb;
    struct ip_addr node_ip_addr[FIT_NUM_NODE];
    u16 udp_port;
    /* RPC sequence number */
    fit_seqnum_t sequence_num;
    spinlock_t sequence_num_lock;
    /* RPC handles */
    struct fit_s_handle s_handles[FIT_NUM_SEND_HANDLE];
    struct fit_r_handle r_handles[FIT_NUM_RECV_HANDLE];
    unsigned long s_handles_bitmap[(FIT_NUM_SEND_HANDLE + BITS_PER_LONG - 1) / BITS_PER_LONG];
    unsigned long r_handles_bitmap[(FIT_NUM_RECV_HANDLE + BITS_PER_LONG - 1) / BITS_PER_LONG];
    spinlock_t s_handles_lock;
    spinlock_t r_handles_lock;

    fit_input_cb_t input;
};

int fit_init(void);
int fit_dispatch(void);

int fit_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
        int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec);
int fit_receive_message(unsigned int designed_port, void *ret_addr,
        int receive_size, uintptr_t *descriptor);
int fit_reply_message(void *addr, int size, uintptr_t descriptor);

#endif /* _INCLUDE_FIT_INTERNAL_H */