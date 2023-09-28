#ifndef _INCLUDE_FIT_CONN_H_
#define _INCLUDE_FIT_CONN_H_

#include <net/lwip/tcp.h>
#include "fit_types.h"

struct fit_context;

/**
 * FIT connection state
 */
enum fit_conn_state {
    FIT_CONN_NONE = 0,
    FIT_CONN_INITIALIZED, /* After the metadata has been initialized */
    FIT_CONN_READY, /* After the connection has been setup  */
    FIT_CONN_ERR,
    FIT_CONN_CONNECTING,
};

/**
 * FIT connection
 */
struct fit_conn {
    struct fit_context *ctx;
    /* For reconnecting */
    struct ip_addr peer_addr;
    u16_t peer_port, bind_port;
    struct tcp_pcb *tpcb;
    fit_node_t peer_id;
    int active; /* Whether to set up the connection actively */
    enum fit_conn_state state;
    
    /* The buf for assembling complete FIT messages. It shoud be ensured
       the message starts at offset 0 */
    struct {
        struct fit_msg_hdr hdr;
        struct pbuf *buf;
        int seen_hdr;
    } recv;
    
    struct {
        int ongoing;
        struct fit_msg_hdr hdr;
        void *msg;
        size_t written_len; /* Including the header */
        size_t sent_len;    /* Including the header */
        struct semaphore *sem; /* The semaphore to notify the sender */
        int *err; /* The err to notify the sender */
    } send;
};

int conn_init(struct fit_conn *conn, struct fit_context *ctx, 
    u16_t bind_port, fit_node_t peer_id, struct ip_addr *peer_addr, 
    u16_t peer_port, int active);
int conn_send(struct fit_conn *conn, struct fit_rpc_id *rpcid,
    fit_msg_type_t type, fit_port_t port,
    fit_node_t dst_node, fit_port_t dst_port,
    void *msg, size_t len, struct semaphore *send_sem, int *send_err);

#endif /* _INCLUDE_FIT_CONN_H_ */
