#ifndef _INCLUDE_FIT_INTERNAL_H
#define _INCLUDE_FIT_INTERNAL_H


#include <net/lwip/ip_addr.h>
#include <net/lwip/pbuf.h>
#include <net/lwip/tcp.h>
#include "fit_sys.h"
#include "fit_types.h"
#include "fit_conn.h"
#include "fit_log.h"
#include "fit.h"

#define _MIN(x,y) ((x) < (y) ? (x) : (y))

#define ARP_TMR_INTERVAL_MS   ARP_TMR_INTERVAL
#define IP_TMR_INTERVAL_MS    IP_TMR_INTERVAL
#define TCP_TMR_INTERVAL_MS   TCP_TMR_INTERVAL
#define MIN_INTERVAL_MS       \
    _MIN(TCP_TMR_INTERVAL, _MIN(ARP_TMR_INTERVAL_MS, IP_TMR_INTERVAL_MS))

#define ARP_TMR_INTERVAL_JIF  msecs_to_jiffies(ARP_TMR_INTERVAL_MS)
#define IP_TMR_INTERVAL_JIF   msecs_to_jiffies(IP_TMR_INTERVAL_MS)
#define TCP_TMR_INTERVAL_JIF  msecs_to_jiffies(TCP_TMR_INTERVAL_MS)
#define MIN_IINTERVAL_JIF     msecs_to_jiffies(MIN_INTERVAL_MS)

#if defined(CONFIG_FIT_CALL_TO_THPOOL) && CONFIG_FIT_CALL_TO_THPOOL
#define FIT_CALL_TO_THPOOL
#include <memory/thread_pool.h>
#endif

#define FIT_NUM_CONTEXT     1U
#define FIT_NUM_FREE_PBUF   64U

#define FIT_NONE_PORT       -1


void fit_poke_polling_thread(void);

int fit_init(void);
struct fit_context *fit_new_context(fit_node_t node_id);
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