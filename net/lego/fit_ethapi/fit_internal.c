#include <lego/printk.h>
#include <lego/completion.h>

#include <net/lwip/netif.h>
#include <net/netif/etharp.h>
#include <net/e1000.h>

#include "fit_internal.h"

static const char e1000_netif_name[] = "en";


static struct netif e1000_netif;


/**
 * E1000 lwIP network interface low-level I/O functions
 */
static err_t e1000_netif_low_level_output(struct netif *netif, struct pbuf *p)
{
    int err;
    err = e1000_transmit(p->payload, p->len);
    if (err) {
        pr_err("Ehernet FIT: Failed to transmit packet\n");
        return ERR_IF;
    }
    return ERR_OK;
}

static struct pbuf *e1000_netif_low_level_input(void)
{
    u8 buf[0x5EE];
    
    struct pbuf *p, *q;
    u16 len, copied_len;
    int err;

    err = e1000_receive(buf, &len);
    if (err) {
        pr_err("Ehernet FIT: Failed to receive packet\n");
        return NULL;
    }

    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p == NULL) {
        pr_warn("Ehernet FIT: Failed to allocate pbuf\n");
        return NULL;
    }

    copied_len = 0;
    for (q = p; q != NULL; q = q->next) {
        int bytes = q->len;
        if (bytes > (len - copied_len))
            bytes = len - copied_len;
        memcpy(q->payload, buf + copied_len, bytes);
        copied_len += bytes;
    }

    return p;
}

/**
 * This function is called in the interrupt context
 */
static void __e1000_input_callback(void)
{
    struct pbuf *p;

    p = e1000_netif_low_level_input();
    /* no packet could be read, silently ignore this */
    if (p == NULL) return;

    /* here input() has been initialized to ethernet_input, which
    will take care of the Ethernet header */
    // TODO: Shall we divide top half and bottom half?
    e1000_netif.input(p, &e1000_netif);
}

/**
 * E1000 lwIP network interface initialization 
 * See net/lwip/netif/ehernetif.c for reference
 */
/*-----------------------------------------*/
static err_t e1000_netif_output(struct netif *netif, struct pbuf *p,
    struct ip_addr *ipaddr)
{
    /* May perform some checks here */
    return etharp_output(netif, p, ipaddr);
}

static err_t e1000_netif_init_cb(struct netif *netif)
{
    int i;

    netif->state = NULL;
    netif->output = e1000_netif_output;
    netif->linkoutput = e1000_netif_low_level_output;
    memcpy(&netif->name[0], e1000_netif_name, strlen(e1000_netif_name));

    /* Low-level initialization */
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    for (i = 0; i < ETHARP_HWADDR_LEN; i++)
        netif->hwaddr[i] = e1000_mac[i];

    /* We should have called e1000_init() by now, but the input callback has 
        not been set yet */
    e1000_input_callback = __e1000_input_callback;

    etharp_init();

    return ERR_OK;
}

int fit_init_e1000_netif(void)
{
    struct ip_addr ipaddr, netmask, gateway;
    
    memset(&ipaddr, 0, sizeof(ipaddr));
    memset(&netmask, 0, sizeof(netmask));
    memset(&gateway, 0, sizeof(gateway));

    if ((ipaddr.addr = inet_addr(CONFIG_E1000_NETIF_IP)) == INADDR_NONE) {
        pr_err("Ehernet FIT: Invalid IP address: %s\n", CONFIG_E1000_NETIF_IP);
        goto ip_err;
    }
    if ((netmask.addr = inet_addr(CONFIG_E1000_NETIF_MASK)) == INADDR_NONE) {
        pr_err("Ehernet FIT: Invalid netmask: %s\n", CONFIG_E1000_NETIF_MASK);
        goto ip_err;
    }
    if ((gateway.addr = inet_addr(CONFIG_E1000_NETIF_GATEWAY)) == INADDR_NONE) {
        pr_err("Ehernet FIT: Invalid gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
        goto ip_err;
    }

    // TODO: check whether ip_input or ethernet_input should be used
    if (netif_add(&e1000_netif, &ipaddr, &netmask, &gateway, NULL, e1000_netif_init_cb, ethernet_input) == NULL) {
        pr_err("Ehernet FIT: Failed to add netif\n");
        goto ip_err;
    }

    netif_set_default(&e1000_netif);
    netif_set_up(&e1000_netif);

    pr_info("Ethernet FIT: netif ip: %s\n", CONFIG_E1000_NETIF_IP);
    pr_info("Ethernet FIT: netif netmask: %s\n", CONFIG_E1000_NETIF_MASK);
    pr_info("Ethernet FIT: netif gateway: %s\n", CONFIG_E1000_NETIF_GATEWAY);
    pr_info("Ethernet FIT: netif mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
		e1000_netif.hwaddr[0], e1000_netif.hwaddr[1], e1000_netif.hwaddr[2],
        e1000_netif.hwaddr[3], e1000_netif.hwaddr[4], e1000_netif.hwaddr[5]);
    pr_info("Ethernet FIT: netif initialized\n");

    return 0;

ip_err:
    pr_err("Ehernet FIT: netif initialization failed\n");
    return -EINVAL;
}
