#ifndef LEGO_LWIP_LWIPOPTS_H
#define LEGO_LWIP_LWIPOPTS_H

// Huge hack to include memcpy. Since this is the only file that is
// consistently included in all of lwip, a definition of memcpy can be added
// here to make it lwip visible. I am hiding lwip because LEGO seems to want to
// do so. There is a declaration of memcpy in LEGO but not a definition.
#ifdef _LEGO_LINUX_MODULE_
#include <linux/types.h>
#else
#include <lego/types.h>
#endif /* _LEGO_LINUX_MODULE_ */
void *memcpy(void *dst, const void *src, size_t n);

#define NO_SYS 1

#define LWIP_RAW    0
#define LWIP_UDP    0
#define LWIP_DHCP   0
#define LWIP_TCP    1

#define LWIP_STATS		0
#define LWIP_STATS_DISPLAY	0
#define LWIP_COMPAT_SOCKETS	1
//#define SYS_LIGHTWEIGHT_PROT	1
#define LWIP_PROVIDE_ERRNO      1

#define LWIP_TCP_KEEPALIVE    1

// Various tuning knobs, see:
// http://lists.gnu.org/archive/html/lwip-users/2006-11/msg00007.html

#define MEM_ALIGNMENT		4

#define MEMP_NUM_PBUF		128
#define MEMP_NUM_RAW_PCB    0
#define MEMP_NUM_UDP_PCB	0
#define MEMP_NUM_TCP_PCB	3
#define MEMP_NUM_TCP_PCB_LISTEN	MEMP_NUM_TCP_PCB
#define MEMP_NUM_TCP_SEG	TCP_SND_QUEUELEN// at least as big as TCP_SND_QUEUELEN
#define MEMP_NUM_NETBUF		0
#define MEMP_NUM_NETCONN	0
#define MEMP_NUM_SYS_TIMEOUT    0

#define PER_TCP_PCB_BUFFER	(16 * 4096)
#define MEM_SIZE		(PER_TCP_PCB_BUFFER*MEMP_NUM_TCP_SEG + 4096*MEMP_NUM_TCP_SEG)

#define PBUF_POOL_SIZE		512
#define PBUF_POOL_BUFSIZE	2000

#define TCP_MSS			1460
#define TCP_WND			24000
#define TCP_SND_BUF		(16 * TCP_MSS)
#define TCP_SND_QUEUELEN	(4 * TCP_SND_BUF/TCP_MSS)

// Print error messages when we run out of memory
#define LWIP_DEBUG	1
#define TCP_DEBUG	        LWIP_DBG_OFF
#define TCP_INPUT_DEBUG     (LWIP_DBG_OFF && TCP_DEBUG)
#define TCP_OUTPUT_DEBUG    (LWIP_DBG_OFF && TCP_DEBUG)
#define TCP_CWND_DEBUG      (LWIP_DBG_OFF && TCP_DEBUG)
#define TCP_QLEN_DEBUG      (LWIP_DBG_OFF && TCP_DEBUG)
#define UDP_DEBUG           LWIP_DBG_OFF
#define IP_DEBUG            LWIP_DBG_OFF
#define ETHARP_DEBUG        LWIP_DBG_OFF
#define INET_DEBUG          LWIP_DBG_OFF
#define IP_REASS_DEBUG      LWIP_DBG_OFF
//#define MEMP_DEBUG	    LWIP_DBG_ON
#define NETIF_DEBUG         LWIP_DBG_OFF
#define SOCKETS_DEBUG	    LWIP_DBG_OFF
//#define DBG_TYPES_ON	    LWIP_DBG_ON
//#define PBUF_DEBUG      LWIP_DBG_ON
//#define API_LIB_DEBUG   LWIP_DBG_ON

#define ETHARP_STATS    0

#define DBG_MIN_LEVEL	DBG_LEVEL_SERIOUS
#define LWIP_DBG_MIN_LEVEL	0
#define MEMP_SANITY_CHECK	0

#define ERRNO

#endif
