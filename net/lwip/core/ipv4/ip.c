/**
 * @file
 * This is the IPv4 layer implementation for incoming and outgoing IP traffic.
 * 
 * @see ip_frag.c
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "net/lwip/debug.h"
#include "net/lwip/opt.h"
#include "net/lwip/ip.h"
#include "net/lwip/def.h"
#include "net/lwip/mem.h"
#include "net/lwip/ip_frag.h"
#include "net/lwip/inet.h"
#include "net/lwip/inet_chksum.h"
#include "net/lwip/netif.h"
#include "net/lwip/icmp.h"
#include "net/lwip/igmp.h"
#include "net/lwip/raw.h"
#include "net/lwip/udp.h"
#include "net/lwip/tcp.h"
#include "net/lwip/snmp.h"
#include "net/lwip/dhcp.h"
#include "net/lwip/stats.h"
#include "net/arch/perf.h"

/**
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 *
 * @param dest the destination IP address for which to find the route
 * @return the netif on which to send to reach dest
 */
struct netif *
ip_route(struct ip_addr *dest)
{
  struct netif *netif;

  /* iterate through netifs */
  for(netif = netif_list; netif != NULL; netif = netif->next) {
  	if (dest)
  	LWIP_DEBUGF(IP_DEBUG, ("ip_route netif %p dest %p %lx\n", netif, dest, dest->addr));
	else
  	LWIP_DEBUGF(IP_DEBUG, ("ip_route netif %p dest %p\n", netif, dest));
    /* network mask matches? */
    if (netif_is_up(netif)) {
    	if (dest)
  	LWIP_DEBUGF(IP_DEBUG, ("ip_route netif %p is up dest %lx netifip %p %lx mask %lx\n", 
			netif, dest->addr, netif->ip_addr, (netif->ip_addr).addr, (netif->netmask).addr));
	//ip_addr_debug_print(NETIF_DEBUG, dest);
	//ip_addr_debug_print(NETIF_DEBUG, netif->ip_addr);
	//ip_addr_debug_print(NETIF_DEBUG, netif->netmask);
      if (ip_addr_netcmp(dest, &(netif->ip_addr), &(netif->netmask))) {
        /* return netif on which to forward IP packet */
	LWIP_DEBUGF(IP_DEUBG, ("ip_route found netif %p\n", netif));
        return netif;
      }
    }
  }
  if ((netif_default == NULL) || (!netif_is_up(netif_default))) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_route: No route to 0x%"X32_F"\n", dest->addr));
    IP_STATS_INC(ip.rterr);
    snmp_inc_ipoutnoroutes();
    return NULL;
  }
  /* no matching netif found, use default netif */
  LWIP_DEBUGF(IP_DEBUG, ("ip_route no netif found netif %p\n", netif_default));
  return netif_default;
}

#if IP_FORWARD
/**
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 * @return the netif on which the packet was sent (NULL if it wasn't sent)
 */
static struct netif *
ip_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp)
{
  struct netif *netif;

  PERF_START;
  /* Find network interface where to forward this IP packet to. */
  netif = ip_route((struct ip_addr *)&(iphdr->dest));
  if (netif == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_forward: no forwarding route for 0x%"X32_F" found\n",
                      iphdr->dest.addr));
    snmp_inc_ipoutnoroutes();
    return (struct netif *)NULL;
  }
  /* Do not forward packets onto the same network interface on which
   * they arrived. */
  if (netif == inp) {
    LWIP_DEBUGF(IP_DEBUG, ("ip_forward: not bouncing packets back on incoming interface.\n"));
    snmp_inc_ipoutnoroutes();
    return (struct netif *)NULL;
  }

  /* decrement TTL */
  IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);
  /* send ICMP if TTL == 0 */
  if (IPH_TTL(iphdr) == 0) {
    snmp_inc_ipinhdrerrors();
#if LWIP_ICMP
    /* Don't send ICMP messages in response to ICMP messages */
    if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) {
      icmp_time_exceeded(p, ICMP_TE_TTL);
    }
#endif /* LWIP_ICMP */
    return (struct netif *)NULL;
  }

  /* Incrementally update the IP checksum. */
  if (IPH_CHKSUM(iphdr) >= htons(0xffff - 0x100)) {
    IPH_CHKSUM_SET(iphdr, IPH_CHKSUM(iphdr) + htons(0x100) + 1);
  } else {
    IPH_CHKSUM_SET(iphdr, IPH_CHKSUM(iphdr) + htons(0x100));
  }

  LWIP_DEBUGF(IP_DEBUG, ("ip_forward: forwarding packet to 0x%"X32_F"\n",
                    iphdr->dest.addr));

  IP_STATS_INC(ip.fw);
  IP_STATS_INC(ip.xmit);
  snmp_inc_ipforwdatagrams();

  PERF_STOP("ip_forward");
  /* transmit pbuf on chosen interface */
  netif->output(netif, p, (struct ip_addr *)&(iphdr->dest));
  return netif;
}
#endif /* IP_FORWARD */

/**
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 * 
 * @param p the received IP packet (p->payload points to IP header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
err_t
ip_input(struct pbuf *p, struct netif *inp)
{
	struct ip_hdr *iphdr;
	struct netif *netif;
	u16_t iphdr_hlen;
	u16_t iphdr_len;
#if LWIP_DHCP
	int check_ip_src=1;
#endif /* LWIP_DHCP */

	IP_STATS_INC(ip.recv);
	snmp_inc_ipinreceives();

	/* identify the IP header */
	iphdr = p->payload;
	if (IPH_V(iphdr) != 4) {
		LWIP_DEBUGF(IP_DEBUG | 1, ("IP packet dropped due to bad version number %"U16_F"\n", IPH_V(iphdr)));
		ip_debug_print(p);
		pbuf_free(p);
		IP_STATS_INC(ip.err);
		IP_STATS_INC(ip.drop);
		snmp_inc_ipinhdrerrors();
		return ERR_OK;
	}

	/* obtain IP header length in number of 32-bit words */
	iphdr_hlen = IPH_HL(iphdr);
	/* calculate IP header length in bytes */
	iphdr_hlen *= 4;
	/* obtain ip length in bytes */
	iphdr_len = ntohs(IPH_LEN(iphdr));

	/* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
	if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len)) {
		if (iphdr_hlen > p->len)
			LWIP_DEBUGF(IP_DEBUG | 2, ("IP header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
						iphdr_hlen, p->len));
		if (iphdr_len > p->tot_len)
			LWIP_DEBUGF(IP_DEBUG | 2, ("IP (len %"U16_F") is longer than pbuf (len %"U16_F"), "
						"IP packet dropped.\n",
						iphdr_len, p->tot_len));
		/* free (drop) packet pbufs */
		pbuf_free(p);
		IP_STATS_INC(ip.lenerr);
		IP_STATS_INC(ip.drop);
		snmp_inc_ipindiscards();
		return ERR_OK;
	}

	/* verify checksum */
#if CHECKSUM_CHECK_IP
	if (inet_chksum(iphdr, iphdr_hlen) != 0) {

		LWIP_DEBUGF(IP_DEBUG | 2, ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
		ip_debug_print(p);
		pbuf_free(p);
		IP_STATS_INC(ip.chkerr);
		IP_STATS_INC(ip.drop);
		snmp_inc_ipinhdrerrors();
		return ERR_OK;
	}
#endif

	/* Trim pbuf. This should have been done at the netif layer,
	 * but we'll do it anyway just to be sure that its done. */
	pbuf_realloc(p, iphdr_len);

	/* match packet against an interface, i.e. is this packet for us? */
#if LWIP_IGMP
	if (ip_addr_ismulticast(&(iphdr->dest))) {
		if ((inp->flags & NETIF_FLAG_IGMP) && (igmp_lookfor_group(inp, &(iphdr->dest)))) {
			netif = inp;
		} else {
			netif = NULL;
		}
	} else
#endif /* LWIP_IGMP */
	{
		/* start trying with inp. if that's not acceptable, start walking the
		   list of configured netifs.
		   'first' is used as a boolean to mark whether we started walking the list */
		int first = 1;
		netif = inp;
		do {
			LWIP_DEBUGF(IP_DEBUG, ("ip_input: iphdr->dest 0x%"X32_F" netif->ip_addr 0x%"X32_F" (0x%"X32_F", 0x%"X32_F", 0x%"X32_F")\n",
						iphdr->dest.addr, netif->ip_addr.addr,
						iphdr->dest.addr & netif->netmask.addr,
						netif->ip_addr.addr & netif->netmask.addr,
						iphdr->dest.addr & ~(netif->netmask.addr)));

			/* interface is up and configured? */
			if ((netif_is_up(netif)) && (!ip_addr_isany(&(netif->ip_addr)))) {
				/* unicast to this interface address? */
				if (ip_addr_cmp(&(iphdr->dest), &(netif->ip_addr)) ||
						/* or broadcast on this interface network address? */
						ip_addr_isbroadcast(&(iphdr->dest), netif)) {
					LWIP_DEBUGF(IP_DEBUG, ("ip_input: packet accepted on interface %c%c\n",
								netif->name[0], netif->name[1]));
					/* break out of for loop */
					break;
				}
			}
			if (first) {
				first = 0;
				netif = netif_list;
			} else {
				netif = netif->next;
			}
			if (netif == inp) {
				netif = netif->next;
			}
		} while(netif != NULL);
	}

#if LWIP_DHCP
	/* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
	 * using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
	 * According to RFC 1542 section 3.1.1, referred by RFC 2131).
	 */
	if (netif == NULL) {
		/* remote port is DHCP server? */
		if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
			LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | 1, ("ip_input: UDP packet to DHCP client port %"U16_F"\n",
						ntohs(((struct udp_hdr *)((u8_t *)iphdr + iphdr_hlen))->dest)));
			if (ntohs(((struct udp_hdr *)((u8_t *)iphdr + iphdr_hlen))->dest) == DHCP_CLIENT_PORT) {
				LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | 1, ("ip_input: DHCP packet accepted.\n"));
				netif = inp;
				check_ip_src = 0;
			}
		}
	}
#endif /* LWIP_DHCP */

	/* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */
#if LWIP_DHCP
	if (check_ip_src)
#endif /* LWIP_DHCP */
	{  if ((ip_addr_isbroadcast(&(iphdr->src), inp)) ||
			(ip_addr_ismulticast(&(iphdr->src)))) {
		/* packet source is not valid */
		LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | 1, ("ip_input: packet source is not valid.\n"));
		/* free (drop) packet pbufs */
		pbuf_free(p);
		IP_STATS_INC(ip.drop);
		snmp_inc_ipinaddrerrors();
		snmp_inc_ipindiscards();
		return ERR_OK;
	}
	}

	/* packet not for us? */
	if (netif == NULL) {
		/* packet not for us, route or discard */
		LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | 1, ("ip_input: packet not for us.\n"));
#if IP_FORWARD
		/* non-broadcast packet? */
		if (!ip_addr_isbroadcast(&(iphdr->dest), inp)) {
			/* try to forward IP packet on (other) interfaces */
			ip_forward(p, iphdr, inp);
		} else
#endif /* IP_FORWARD */
		{
			snmp_inc_ipinaddrerrors();
			snmp_inc_ipindiscards();
		}
		pbuf_free(p);
		return ERR_OK;
	}
	/* packet consists of multiple fragments? */
	if ((IPH_OFFSET(iphdr) & htons(IP_OFFMASK | IP_MF)) != 0) {
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
		LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip_reass()\n",
					ntohs(IPH_ID(iphdr)), p->tot_len, ntohs(IPH_LEN(iphdr)), !!(IPH_OFFSET(iphdr) & htons(IP_MF)), (ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK)*8));
		/* reassemble the packet*/
		p = ip_reass(p);
		/* packet not fully reassembled yet? */
		if (p == NULL) {
			return ERR_OK;
		}
		iphdr = p->payload;
#else /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
		pbuf_free(p);
		LWIP_DEBUGF(IP_DEBUG | 2, ("IP packet dropped since it was fragmented (0x%"X16_F") (while IP_REASSEMBLY == 0).\n",
					ntohs(IPH_OFFSET(iphdr))));
		IP_STATS_INC(ip.opterr);
		IP_STATS_INC(ip.drop);
		/* unsupported protocol feature */
		snmp_inc_ipinunknownprotos();
		return ERR_OK;
#endif /* IP_REASSEMBLY */
	}

#if IP_OPTIONS_ALLOWED == 0 /* no support for IP options in the IP header? */

#if LWIP_IGMP
	/* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
	if((iphdr_hlen > IP_HLEN &&  (IPH_PROTO(iphdr) != IP_PROTO_IGMP)) {
#else
	if (iphdr_hlen > IP_HLEN) {
#endif /* LWIP_IGMP */
		LWIP_DEBUGF(IP_DEBUG | 2, ("IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n"));
		pbuf_free(p);
		IP_STATS_INC(ip.opterr);
		IP_STATS_INC(ip.drop);
		/* unsupported protocol feature */
		snmp_inc_ipinunknownprotos();
		return ERR_OK;
	}
#endif /* IP_OPTIONS_ALLOWED == 0 */

	/* send to upper layers */
	LWIP_DEBUGF(IP_DEBUG, ("ip_input: \n"));
	ip_debug_print(p);
	LWIP_DEBUGF(IP_DEBUG, ("ip_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

#if LWIP_RAW
	/* raw input did not eat the packet? */
	if (raw_input(p, inp) == 0)
#endif /* LWIP_RAW */
	{

		switch (IPH_PROTO(iphdr)) {
#if LWIP_UDP
			case IP_PROTO_UDP:
#if LWIP_UDPLITE
			case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
				snmp_inc_ipindelivers();
				udp_input(p, inp);
				break;
#endif /* LWIP_UDP */
#if LWIP_TCP
			case IP_PROTO_TCP:
				snmp_inc_ipindelivers();
				tcp_input(p, inp);
				break;
#endif /* LWIP_TCP */
#if LWIP_ICMP
			case IP_PROTO_ICMP:
				snmp_inc_ipindelivers();
				icmp_input(p, inp);
				break;
#endif /* LWIP_ICMP */
#if LWIP_IGMP
			case IP_PROTO_IGMP:
				igmp_input(p,inp,&(iphdr->dest));
				break;
#endif /* LWIP_IGMP */
			default:
#if LWIP_ICMP
				/* send ICMP destination protocol unreachable unless is was a broadcast */
				if (!ip_addr_isbroadcast(&(iphdr->dest), inp) &&
						!ip_addr_ismulticast(&(iphdr->dest))) {
					p->payload = iphdr;
					icmp_dest_unreach(p, ICMP_DUR_PROTO);
				}
#endif /* LWIP_ICMP */
				pbuf_free(p);

				LWIP_DEBUGF(IP_DEBUG | 2, ("Unsupported transport protocol %"U16_F"\n", IPH_PROTO(iphdr)));

				IP_STATS_INC(ip.proterr);
				IP_STATS_INC(ip.drop);
				snmp_inc_ipinunknownprotos();
		}
	}

	return ERR_OK;
}

/**
 * Sends an IP packet on a network interface. This function constructs
 * the IP header and calculates the IP header checksum. If the source
 * IP address is NULL, the IP address of the outgoing network
 * interface is filled in as source address.
 * If the destination IP address is IP_HDRINCL, p is assumed to already
 * include an IP header and p->payload points to it instead of the data.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 *
 * @note ip_id: RFC791 "some host may be able to simply use
 *  unique identifiers independent of destination"
 */
err_t
ip_output_if(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
             u8_t ttl, u8_t tos,
             u8_t proto, struct netif *netif)
{
	struct ip_hdr *iphdr;
	static u16_t ip_id = 0;

	snmp_inc_ipoutrequests();

	/* Should the IP header be generated or is it already included in p? */
	if (dest != IP_HDRINCL) {
		/* generate IP header */
		if (pbuf_header(p, IP_HLEN)) {
			LWIP_DEBUGF(IP_DEBUG | 2, ("ip_output: not enough room for IP header in pbuf\n"));

			IP_STATS_INC(ip.err);
			snmp_inc_ipoutdiscards();
			return ERR_BUF;
		}

		iphdr = p->payload;
		LWIP_ASSERT("check that first pbuf can hold struct ip_hdr",
				(p->len >= sizeof(struct ip_hdr)));

		IPH_TTL_SET(iphdr, ttl);
		IPH_PROTO_SET(iphdr, proto);

		ip_addr_set(&(iphdr->dest), dest);

		IPH_VHLTOS_SET(iphdr, 4, IP_HLEN / 4, tos);
		IPH_LEN_SET(iphdr, htons(p->tot_len));
		IPH_OFFSET_SET(iphdr, 0);
		IPH_ID_SET(iphdr, htons(ip_id));
		++ip_id;

		if (ip_addr_isany(src)) {
			ip_addr_set(&(iphdr->src), &(netif->ip_addr));
		} else {
			ip_addr_set(&(iphdr->src), src);
		}

		IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
		IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));
#endif
	} else {
		/* IP header already included in p */
		iphdr = p->payload;
		dest = &(iphdr->dest);
	}

#if IP_FRAG
	/* don't fragment if interface has mtu set to 0 [loopif] */
	if (netif->mtu && (p->tot_len > netif->mtu))
		return ip_frag(p,netif,dest);
#endif

	IP_STATS_INC(ip.xmit);

	LWIP_DEBUGF(IP_DEBUG, ("ip_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], netif->num));
	ip_debug_print(p);

#if (LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF)
	if (ip_addr_cmp(dest, &netif->ip_addr)) {
		/* Packet to self, enqueue it for loopback */
		LWIP_DEBUGF("netif_loop_output()");
		return netif_loop_output(netif, p, dest);
	} else
#endif /* (LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF) */
	{
		LWIP_DEBUGF(IP_DEBUG, ("netif->output()"));
		return netif->output(netif, p, dest);
	}
}

/**
 * Simple interface to ip_output_if. It finds the outgoing network
 * interface and calls upon ip_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
err_t
ip_output(struct pbuf *p, struct ip_addr *src, struct ip_addr *dest,
          u8_t ttl, u8_t tos, u8_t proto)
{
  struct netif *netif;

  if ((netif = ip_route(dest)) == NULL) {
    return ERR_RTE;
  }

  return ip_output_if(p, src, dest, ttl, tos, proto, netif);
}

#if IP_DEBUG
/* Print an IP header by using LWIP_DEBUGF
 * @param p an IP packet, p->payload pointing to the IP header
 */
void
ip_debug_print(struct pbuf *p)
{
  struct ip_hdr *iphdr = p->payload;
  u8_t *payload;

  payload = (u8_t *)iphdr + IP_HLEN;

  pr_debug("IP header:\n");
  pr_debug("+-------------------------------+\n");
  pr_debug("|%2"S16_F" |%2"S16_F" |  0x%02"X16_F" |     %5"U16_F"     | (v, hl, tos, len)\n",
                    IPH_V(iphdr),
                    IPH_HL(iphdr),
                    IPH_TOS(iphdr),
                    ntohs(IPH_LEN(iphdr)));
  pr_debug("+-------------------------------+\n");
  pr_debug("|    %5"U16_F"      |%"U16_F"%"U16_F"%"U16_F"|    %4"U16_F"   | (id, flags, offset)\n",
                    ntohs(IPH_ID(iphdr)),
                    ntohs(IPH_OFFSET(iphdr)) >> 15 & 1,
                    ntohs(IPH_OFFSET(iphdr)) >> 14 & 1,
                    ntohs(IPH_OFFSET(iphdr)) >> 13 & 1,
                    ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK);
  pr_debug("+-------------------------------+\n");
  pr_debug("|  %3"U16_F"  |  %3"U16_F"  |    0x%04"X16_F"     | (ttl, proto, chksum)\n",
                    IPH_TTL(iphdr),
                    IPH_PROTO(iphdr),
                    ntohs(IPH_CHKSUM(iphdr)));
  pr_debug("+-------------------------------+\n");
  pr_debug("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (src)\n",
                    ip4_addr1(&iphdr->src),
                    ip4_addr2(&iphdr->src),
                    ip4_addr3(&iphdr->src),
                    ip4_addr4(&iphdr->src));
  pr_debug("+-------------------------------+\n");
  pr_debug("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (dest)\n",
                    ip4_addr1(&iphdr->dest),
                    ip4_addr2(&iphdr->dest),
                    ip4_addr3(&iphdr->dest),
                    ip4_addr4(&iphdr->dest));
  pr_debug("+-------------------------------+\n");
}
#endif /* IP_DEBUG */
