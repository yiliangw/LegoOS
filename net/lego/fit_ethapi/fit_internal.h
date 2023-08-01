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

#ifndef MIN()
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#define ARP_TMR_INTERVAL_MS     ARP_TMR_INTERVAL
#define IP_TMR_INTERVAL_MS      IP_TMR_INTERVAL
#define SEM_DOWN_TIMEOUT_MS     (MIN(ARP_TMR_INTERVAL_MS, IP_TMR_INTERVAL_MS) + 10)

#define FIT_UDP_PORT    6000U

#define FIT_NUM_SEND_HANDLE      32
#define FIT_NUM_RECV_HANDLE      32

typedef u32 fit_seqnum_t;

typedef struct {
    int node_id;
    fit_seqnum_t sequence_num;
} __attribute__((packed)) fit_rpc_id_t;

/* FIT sending handle */
struct fit_s_handle {
    fit_rpc_id_t id;
    struct semaphore sema;
    void *ret_addr;
    int max_ret_size;
};

/* FIT receiving handle */
struct fit_r_handle {
    fit_rpc_id_t rpc_id;
};

struct fit_context {
    /* Identity */
    int node_id;
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

    
};

enum fit_msg_type {
    FIT_REQUEST,
    FIT_REPLY
};

struct fit_hdr {
    fit_rpc_id_t rpc_id;
    int src_node;
    int dst_node;
    int dst_port;
} __attribute__((packed));


int fit_init_e1000_netif(void);
void fit_dispatch(void);

int fit_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
        int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec);
int fit_receive_message(unsigned int designed_port, void *ret_addr,
        int receive_size, uintptr_t *descriptor);
int fit_reply_message(void *addr, int size, uintptr_t descriptor);

#endif /* _INCLUDE_FIT_INTERNAL_H */