#ifndef _INCLUDE_FIT_TYPES_H_
#define _INCLUDE_FIT_TYPES_H_

#include "fit_sys.h"

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
    fit_msg_len_t length;   /* Including the header */
    fit_msg_type_t type;
    struct fit_rpc_id rpc_id;
} __attribute__((packed));
/** @} */ // end of group fit_network_types

#endif /* _INCLUDE_FIT_TYPES_H_ */