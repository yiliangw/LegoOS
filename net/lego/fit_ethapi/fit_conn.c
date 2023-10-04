#include "fit_types.h"
#include <net/lwip/tcp.h>
#include <net/lwip/pbuf.h>
#include "fit_log.h"
#include "fit_utils.h"
#include "fit_context.h"
#include "fit_internal.h"

#include "fit_conn.h"


static void __do_input(struct fit_conn *conn, struct pbuf *p);
static int __do_connect(struct fit_conn *conn);


/**
 * Try to write as much as possible the current send message to the 
 * TCP connection.
 */
static int
__do_send(struct fit_conn *conn)
{
    const size_t hdr_len = sizeof(struct fit_msg_hdr);
    size_t write_len, sndbuf_len;
    off_t write_off;
    struct tcp_pcb *tpcb;
    err_t err;

    /* Check the state of the connection */
    if (conn->state != FIT_CONN_READY || !conn->send.ongoing) { 
        /* Allow only one message at a time */
        fit_err("%s: conn.state(%d) send.ongoing(%d)\n", __func__,
            conn->state, conn->send.ongoing);
        return -EPERM;
    }

    if (conn->send.written_len >= conn->send.hdr.length) {
        BUG_ON(conn->send.written_len > conn->send.hdr.length);
        return 0;
    }

    tpcb = conn->tpcb;

    if (conn->send.written_len == 0) { /* Header not written */
        BUG_ON(tcp_sndbuf(conn->tpcb) < hdr_len);
        /* This should not happen because there is no concurrent send */
        err = tcp_write(tpcb, &conn->send.hdr, hdr_len, 
            TCP_WRITE_FLAG_MORE);
        if (err) {
            fit_warn("tcp_write(): %d\n", err);
            return -ENOMEM;
        }
        conn->send.written_len += hdr_len;
    }
    /* Require to write the header as a whole */
    BUG_ON(conn->send.written_len < hdr_len);

    while (conn->send.hdr.length > conn->send.written_len) {
        sndbuf_len = tcp_sndbuf(tpcb);
        write_len = conn->send.hdr.length - conn->send.written_len;
        write_len = sndbuf_len < write_len ? sndbuf_len : write_len;

        if (!write_len)
            return -EAGAIN;

        write_off = conn->send.written_len - hdr_len;
        err = tcp_write(tpcb, conn->send.msg + write_off, write_len, 
            TCP_WRITE_FLAG_MORE);
        if (err != ERR_OK) {
            if (err == ERR_MEM) {
                fit_warn("tcp_write() ERR_MEM\n");
                return -EAGAIN;
            } else {
                fit_warn("tcp_write(): %d\n", err);
                return -ENOMEM;
            }
        }
        conn->send.written_len += write_len;
        err = tcp_output(tpcb);
        if (err != ERR_OK) {
            fit_warn("tcp_output(): %d\n", err);
            return -EAGAIN;
        }
    }

    err = tcp_output(tpcb);
    if (err != ERR_OK) {
        fit_warn("tcp_output() 2: %d\n", err);
        return -EAGAIN;
    }
    
    return 0;
}

static void
__tcp_connecting_err_cb(void *arg, err_t err)
{
    struct fit_conn *conn = (struct fit_conn *)arg;
    int ret;

    fit_warn("TCP error when connecting to %d: %d. Retrying.\n", conn->peer_id, err);
    conn->state = FIT_CONN_INITIALIZED;
    ret = __do_connect(conn);
    if (ret)
        fit_panic("Failed to do connect\n");
}

static void
__tcp_connected_err_cb(void *arg, err_t err)
{
    // TODO: Handle possible errors
    fit_panic("Unhandled TCP connected error: %d\n", err);
}

/* There can be some extra bytes sent e.g., ACK */
static err_t
__tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    struct fit_conn *conn = (struct fit_conn *)arg;
    size_t msg_len;

    // BUG_ON(!conn->send.ongoing);
    if (!conn->send.ongoing) {
        fit_info("sent %d bytes\n", len);
        /* Should be just some protocol bytes */
        return ERR_OK;
    }

    msg_len = conn->send.hdr.length;

    conn->send.sent_len += len;
    // BUG_ON(conn->send.sent_len > msg_len);

    if (conn->send.sent_len >= msg_len) {
        /* We have sent the whole FIT message */
        conn->send.ongoing = 0;
        if (conn->send.sem) {
            *conn->send.err = 0;
            up(conn->send.sem);
        }
        fit_poke_polling_thread();
    } else {
        __do_send(conn);
    }

    return ERR_OK;
}

static err_t
__tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct fit_conn *conn = (struct fit_conn *)arg;
    u16_t pbuf_len;

    if (p == NULL) { /* Remote host closed connection */
        fit_panic("Remote host closed connection\n");
        /* TODO: Close the local tcp connection and try to reconnect. */
    }
    if (err != ERR_OK) { /* Unknown reason */
        fit_warn("%s: err=%d\n", __func__, err);
        if (p != NULL)
            pbuf_free(p);
        return err;
    }

    /* 
     * At this point, the ownership of the pbuf is passed to upper layer.
     * We no longer care about it anymore. We should keep the length in
     * advance.
     */
    pbuf_len = p->tot_len;
    __do_input(conn, p);
    tcp_recved(tpcb, pbuf_len);

    return ERR_OK;
}

static err_t
__tcp_poll_cb(void *arg, struct tcp_pcb *tpcb)
{
    struct fit_conn *conn = (struct fit_conn *)arg;
    int ret;

    if (conn->send.ongoing && 
        conn->send.written_len < conn->send.hdr.length) {
        ret = __do_send(conn);
        if (ret != 0 && ret != -EAGAIN)
            fit_warn("__do_send(): %d\n", ret);
    }

    return ERR_OK;
}

static err_t
__tcp_connected_cb(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    struct fit_conn *conn = (struct fit_conn *)arg;
    fit_debug("Connected to node %d\n", conn->peer_id);

    /* Set err callback to connected callback */
    tcp_err(tpcb, __tcp_connected_err_cb);
    tcp_poll(tpcb, __tcp_poll_cb, 0);

    conn->state = FIT_CONN_READY;
    // TODO: If there are relevant pending messages in the queue, send them out
    fit_poke_polling_thread();

    return ERR_OK;
}

static err_t
__tcp_accepted_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    struct fit_conn *conn = (struct fit_conn *)arg;
    fit_info("Connected to node %d\n", conn->peer_id);

    conn->tpcb = newpcb;
    tcp_arg(newpcb, arg);
    tcp_recv(newpcb, __tcp_recv_cb);
    tcp_err(newpcb, __tcp_connected_err_cb);
    tcp_poll(newpcb, __tcp_poll_cb, 0);
    tcp_sent(newpcb, __tcp_sent_cb);

    conn->state = FIT_CONN_READY;
    // TODO: If there are relevant pending messages in the queue, send them out
    fit_poke_polling_thread();

    return ERR_OK;
}

static int
__do_connect(struct fit_conn *conn)
{
    struct tcp_pcb *tpcb;
    err_t err;

    BUG_ON(conn->state != FIT_CONN_INITIALIZED);

    tpcb = tcp_new();
    if (tpcb == NULL) {
        fit_err("tcp_new()\n");
        return -ENOMEM;
    }
    err = tcp_bind(tpcb, IP_ADDR_ANY, conn->bind_port);
    if (err != ERR_OK) {
        fit_err("tcp_bind(): %d\n", err);
        return -ENOMEM;
    }

    if (conn->active) {
        tcp_arg(tpcb, conn);
        tcp_err(tpcb, __tcp_connecting_err_cb);
        tcp_recv(tpcb, __tcp_recv_cb);
        tcp_sent(tpcb, __tcp_sent_cb);
        err = tcp_connect(tpcb, &conn->peer_addr, conn->peer_port,
            __tcp_connected_cb);
        if (err != ERR_OK) {
            fit_err("tcp_connect(): %d\n", err);
            tcp_close(tpcb); /* Free the PCB */
            return -ENOMEM;
        }
    } else {
        tpcb = tcp_listen(tpcb);
        if (tpcb == NULL) {
            fit_err("tcp_listen: %d\n", err);
            return -ENOMEM;
        }
        tcp_accept(tpcb, __tcp_accepted_cb);
        tcp_arg(tpcb, conn);
    }
    conn->tpcb = tpcb;
    conn->state = FIT_CONN_CONNECTING;

    return 0;
}

int
conn_init(struct fit_conn *conn, ctx_t *ctx, u16_t bind_port, 
    fit_node_t peer_id, struct ip_addr *peer_addr, u16_t peer_port, 
    int active)
{
    int ret;

    memset(conn, 0, sizeof(*conn));
    conn->ctx = ctx;
    conn->peer_addr = *peer_addr;
    conn->peer_port = peer_port;
    conn->bind_port = bind_port;
    conn->tpcb = NULL;
    conn->peer_id = peer_id;
    conn->active = active;
    conn->state = FIT_CONN_INITIALIZED;

    ret = __do_connect(conn);
    if (ret)
        fit_panic("Failed to do connect\n");

    return 0;
}

/**
 * Initialize to send a FIT message.
 *
 * @note We assume msg will be valid before the send finishes because
 * the API is designed to be synchronous.
 *
 * @note sem and err should only be used in sent callback.
 */
int
conn_send(struct fit_conn *conn, struct fit_rpc_id *rpcid,
    fit_msg_type_t type, fit_port_t port,
    fit_node_t dst_node, fit_port_t dst_port,
    void *msg, size_t len, struct semaphore *send_sem, int *send_err)
{
    int ret;
    struct fit_msg_hdr *hdr;

    if (conn->state != FIT_CONN_READY) { 
        /* Allow only one message at a time */
        fit_warn("Connection is not ready (state=%d)\n", conn->state);
        return -EPERM;
    }
    if (conn->send.ongoing) {
        fit_warn("There is an ongoing send\n");
        return -EBUSY;
    }

    conn->send.ongoing = 1;

    /* Initialize the FIT header */
    hdr = &conn->send.hdr;
    hdr->src_node = conn->ctx->id;
    hdr->src_port = port;
    hdr->dst_node = dst_node;
    hdr->dst_port = dst_port;
    hdr->length = sizeof(struct fit_msg_hdr) + len;
    hdr->type = type;
    hdr->rpc_id = *rpcid;

    conn->send.msg = msg;
    conn->send.written_len = 0;
    conn->send.sent_len = 0;
    conn->send.sem = send_sem;
    conn->send.err = send_err;

    ret = __do_send(conn);
    
    if (ret != 0 && ret != -EAGAIN) /* Retry in tcp_poll */
        fit_warn("__do_send(): %d\n", ret);

    if (ret == -EAGAIN)
        return 0;
    
    return ret;
}

/**
 * We received some real data from the stream. Check whether we can
 * assemble packets to the upper layer.
 *
 * This function should be from the TCP recv callback.
 */
static void
__do_input(struct fit_conn *conn, struct pbuf *p)
{
    int ret;
    ctx_t *ctx = conn->ctx;

    if (conn->recv.buf == NULL) {
        conn->recv.buf = p;
    } else {
        pbuf_cat(conn->recv.buf, p);
    }
    
    while (1) { /* Assemble as many FIT messages as possible */
        struct pbuf *msg;
        struct fit_msg_hdr *hdr;
        size_t msg_len;
        size_t buf_len = (conn->recv.buf == NULL) ? 0 : 
            conn->recv.buf->tot_len;

        if (!conn->recv.seen_hdr) {
            /* The complete header hasn't been seen yet */
            if (buf_len < sizeof(struct fit_msg_hdr))
                break; /* Still not forming a complete header */

            /* We see a new FIT message header. */
            /* In case that the header span accross multiple pbufs */
            pbuf_copy_partial(conn->recv.buf, &conn->recv.hdr, 
                sizeof(struct fit_msg_hdr), 0);
            /* Do some check. But we cannot discard the packet right now if 
            there is something wrong because the message may not be 
            complete. */
            if (conn->recv.hdr.dst_node != ctx->id) {
                fit_warn("Received a apcket with unexpected dst_node(%d)\n", 
                    conn->recv.hdr.dst_node);
            }
            if (conn->recv.hdr.src_node != conn->peer_id) {
                fit_warn("Received a packet with unexpected src_node(%d) "
                    "conn->peer_id(%d)\n", conn->recv.hdr.src_node, 
                    conn->peer_id);
            }
        }

        msg_len = conn->recv.hdr.length;
        /* At this point, conn->msg_hdr shoud be valid */
        if (buf_len < msg_len)
            break; /* Still not forming a complete message */
        
        /* We see a new complete FIT message */
        ret = utils_pbuf_cut(conn->recv.buf, msg_len, &msg, &conn->recv.buf);
        conn->recv.seen_hdr = 0; /* Reset */
        if (ret)
            fit_panic("");
        
        hdr = &conn->recv.hdr;
        ctx->input(ctx, hdr->src_node, hdr->src_port, hdr->dst_port, 
            hdr->type, &hdr->rpc_id, msg, sizeof(struct fit_msg_hdr));
    }
}
