#ifndef _E1000_H_
#define _E1000_H_

#include <lego/types.h>

#define TX_DESC_NUM      32
#define TX_PACKET_SIZE   2048

#define RX_DESC_NUM	     64
#define RX_PACKET_SIZE   2048

/* Register Set
 * 
 * RW - register is both readable and writable
 * 
 */
#define E1000_DEVICE_STATUS   0x00008  /* Device Status - RO */

#define E1000_ICR      0x000C0	/* Interrupt Cause Read - R/clr */
#define E1000_ICS      0x000C8  /* Interrupt Cause Set - WO */
#define E1000_IMS      0x000D0  /* Interrupt Mask Set - RW */
#define E1000_IMC      0x000D8	/* Interrupt Mask Clear - WO */

#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_TCTL     0x00400  /* TX Control - RW */

#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
#define E1000_RA       0x05400  /* Receive Address - RW Array */

#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0X03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */

#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */

#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */

/* Transmit Control */
#define E1000_TCTL_RST    0x00000001    /* Reserved */
#define E1000_TCTL_EN     0x00000002    /* enable tx */
#define E1000_TCTL_BCE    0x00000004    /* Reserved */
#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
#define E1000_TCTL_CT     0x00000ff0    /* collision threshold */
#define E1000_TCTL_COLD   0x003ff000    /* collision distance */
#define E1000_TCTL_SWXOFF 0x00400000    /* SW Xoff transmission */
#define E1000_TCTL_PBE    0x00800000    /* Reserved */
#define E1000_TCTL_RTLC   0x01000000    /* Re-transmit on late collision */
#define E1000_TCTL_NRTU   0x02000000    /* No Re-transmit on underrun */
#define E1000_TCTL_MULR   0x10000000    /* Reserved */

#define E1000_RCTL_EN     0x00000002    /* enable */
#define E1000_RCTL_BAM    0x00008000    /* broadcast enable */
#define E1000_RCTL_SECRC  0x04000000    /* Strip Ethernet CRC */

/* Transmit Descriptor bit definitions */
#define E1000_TXD_DTYP_D     0x00100000 /* Data Descriptor */
#define E1000_TXD_DTYP_C     0x00000000 /* Context Descriptor */

#define E1000_TXD_CMD_EOP    0x01 /* End of Packet */
#define E1000_TXD_CMD_RS     0x08 /* Report Status */

#define E1000_TXD_STAT_DD    0x00000001 /* Descriptor Done */
#define E1000_TXD_STAT_EC    0x00000002 /* Excess Collisions */
#define E1000_TXD_STAT_LC    0x00000004 /* Late Collisions */
#define E1000_TXD_STAT_TU    0x00000008 /* Transmit underrun */
#define E1000_TXD_STAT_TC    0x00000004 /* Tx Underrun */

/* Receive Descriptor bit definitions */
#define E1000_RAH_AV            0x80000000        	/* Receive descriptor valid */
#define E1000_RXD_STAT_DD       0x01    			/* Descriptor Done */
#define E1000_RXD_STAT_EOP      0x02    			/* End of Packet */

/* these buffer sizes are valid if E1000_RCTL_BSEX is 0 */
#define E1000_RCTL_SZ_2048        0x00000000    /* rx buffer size 2048 */
#define E1000_RCTL_SZ_1024        0x00010000    /* rx buffer size 1024 */
#define E1000_RCTL_SZ_512         0x00020000    /* rx buffer size 512 */
#define E1000_RCTL_SZ_256         0x00030000    /* rx buffer size 256 */
/* these buffer sizes are valid if E1000_RCTL_BSEX is 1 */
#define E1000_RCTL_SZ_16384       0x00010000    /* rx buffer size 16384 */
#define E1000_RCTL_SZ_8192        0x00020000    /* rx buffer size 8192 */
#define E1000_RCTL_SZ_4096        0x00030000    /* rx buffer size 4096 */

#define E1000_LOCATE(offset)  (offset >> 2)

/* Interrupt Cause Read */
#define E1000_ICR_TXDW          0x00000001	/* Transmit desc written back */
#define E1000_ICR_TXQE          0x00000002	/* Transmit Queue empty */
#define E1000_ICR_LSC           0x00000004	/* Link Status Change */
#define E1000_ICR_RXSEQ         0x00000008	/* rx sequence error */
#define E1000_ICR_RXDMT0        0x00000010	/* rx desc min. threshold (0) */
#define E1000_ICR_RXO           0x00000040	/* rx overrun */
#define E1000_ICR_RXT0          0x00000080	/* rx timer intr (ring 0) */
#define E1000_ICR_MDAC          0x00000200	/* MDIO access complete */
#define E1000_ICR_RXCFG         0x00000400	/* RX /c/ ordered set */
#define E1000_ICR_GPI_EN0       0x00000800	/* GP Int 0 */
#define E1000_ICR_GPI_EN1       0x00001000	/* GP Int 1 */
#define E1000_ICR_GPI_EN2       0x00002000	/* GP Int 2 */
#define E1000_ICR_GPI_EN3       0x00004000	/* GP Int 3 */
#define E1000_ICR_TXD_LOW       0x00008000
#define E1000_ICR_SRPD          0x00010000
#define E1000_ICR_ACK           0x00020000	/* Receive Ack frame */
#define E1000_ICR_MNG           0x00040000	/* Manageability event */
#define E1000_ICR_DOCK          0x00080000	/* Dock/Undock */
#define E1000_ICR_INT_ASSERTED  0x80000000	/* If this bit asserted, the driver should claim the interrupt */
#define E1000_ICR_RXD_FIFO_PAR0 0x00100000	/* queue 0 Rx descriptor FIFO parity error */
#define E1000_ICR_TXD_FIFO_PAR0 0x00200000	/* queue 0 Tx descriptor FIFO parity error */
#define E1000_ICR_HOST_ARB_PAR  0x00400000	/* host arb read buffer parity error */
#define E1000_ICR_PB_PAR        0x00800000	/* packet buffer parity error */
#define E1000_ICR_RXD_FIFO_PAR1 0x01000000	/* queue 1 Rx descriptor FIFO parity error */
#define E1000_ICR_TXD_FIFO_PAR1 0x02000000	/* queue 1 Tx descriptor FIFO parity error */
#define E1000_ICR_ALL_PARITY    0x03F00000	/* all parity error bits */
#define E1000_ICR_DSW           0x00000020	/* FW changed the status of DISSW bit in the FWSM */
#define E1000_ICR_PHYINT        0x00001000	/* LAN connected device generates an interrupt */
#define E1000_ICR_EPRST         0x00100000	/* ME hardware reset occurs */

/* Interrupt Cause Set */
#define E1000_ICS_TXDW      E1000_ICR_TXDW	/* Transmit desc written back */
#define E1000_ICS_TXQE      E1000_ICR_TXQE	/* Transmit Queue empty */
#define E1000_ICS_LSC       E1000_ICR_LSC	/* Link Status Change */
#define E1000_ICS_RXSEQ     E1000_ICR_RXSEQ	/* rx sequence error */
#define E1000_ICS_RXDMT0    E1000_ICR_RXDMT0	/* rx desc min. threshold */
#define E1000_ICS_RXO       E1000_ICR_RXO	/* rx overrun */
#define E1000_ICS_RXT0      E1000_ICR_RXT0	/* rx timer intr */
#define E1000_ICS_MDAC      E1000_ICR_MDAC	/* MDIO access complete */
#define E1000_ICS_RXCFG     E1000_ICR_RXCFG	/* RX /c/ ordered set */
#define E1000_ICS_GPI_EN0   E1000_ICR_GPI_EN0	/* GP Int 0 */
#define E1000_ICS_GPI_EN1   E1000_ICR_GPI_EN1	/* GP Int 1 */
#define E1000_ICS_GPI_EN2   E1000_ICR_GPI_EN2	/* GP Int 2 */
#define E1000_ICS_GPI_EN3   E1000_ICR_GPI_EN3	/* GP Int 3 */
#define E1000_ICS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_ICS_SRPD      E1000_ICR_SRPD
#define E1000_ICS_ACK       E1000_ICR_ACK	/* Receive Ack frame */
#define E1000_ICS_MNG       E1000_ICR_MNG	/* Manageability event */
#define E1000_ICS_DOCK      E1000_ICR_DOCK	/* Dock/Undock */
#define E1000_ICS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0	/* queue 0 Rx descriptor FIFO parity error */
#define E1000_ICS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0	/* queue 0 Tx descriptor FIFO parity error */
#define E1000_ICS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR	/* host arb read buffer parity error */
#define E1000_ICS_PB_PAR        E1000_ICR_PB_PAR	/* packet buffer parity error */
#define E1000_ICS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1	/* queue 1 Rx descriptor FIFO parity error */
#define E1000_ICS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1	/* queue 1 Tx descriptor FIFO parity error */
#define E1000_ICS_DSW       E1000_ICR_DSW
#define E1000_ICS_PHYINT    E1000_ICR_PHYINT
#define E1000_ICS_EPRST     E1000_ICR_EPRST

/* Interrupt Mask Set */
#define E1000_IMS_TXDW      E1000_ICR_TXDW	/* Transmit desc written back */
#define E1000_IMS_TXQE      E1000_ICR_TXQE	/* Transmit Queue empty */
#define E1000_IMS_LSC       E1000_ICR_LSC	/* Link Status Change */
#define E1000_IMS_RXSEQ     E1000_ICR_RXSEQ	/* rx sequence error */
#define E1000_IMS_RXDMT0    E1000_ICR_RXDMT0	/* rx desc min. threshold */
#define E1000_IMS_RXO       E1000_ICR_RXO	/* rx overrun */
#define E1000_IMS_RXT0      E1000_ICR_RXT0	/* rx timer intr */
#define E1000_IMS_MDAC      E1000_ICR_MDAC	/* MDIO access complete */
#define E1000_IMS_RXCFG     E1000_ICR_RXCFG	/* RX /c/ ordered set */
#define E1000_IMS_GPI_EN0   E1000_ICR_GPI_EN0	/* GP Int 0 */
#define E1000_IMS_GPI_EN1   E1000_ICR_GPI_EN1	/* GP Int 1 */
#define E1000_IMS_GPI_EN2   E1000_ICR_GPI_EN2	/* GP Int 2 */
#define E1000_IMS_GPI_EN3   E1000_ICR_GPI_EN3	/* GP Int 3 */
#define E1000_IMS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_IMS_SRPD      E1000_ICR_SRPD
#define E1000_IMS_ACK       E1000_ICR_ACK	/* Receive Ack frame */
#define E1000_IMS_MNG       E1000_ICR_MNG	/* Manageability event */
#define E1000_IMS_DOCK      E1000_ICR_DOCK	/* Dock/Undock */
#define E1000_IMS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0	/* queue 0 Rx descriptor FIFO parity error */
#define E1000_IMS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0	/* queue 0 Tx descriptor FIFO parity error */
#define E1000_IMS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR	/* host arb read buffer parity error */
#define E1000_IMS_PB_PAR        E1000_ICR_PB_PAR	/* packet buffer parity error */
#define E1000_IMS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1	/* queue 1 Rx descriptor FIFO parity error */
#define E1000_IMS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1	/* queue 1 Tx descriptor FIFO parity error */
#define E1000_IMS_DSW       E1000_ICR_DSW
#define E1000_IMS_PHYINT    E1000_ICR_PHYINT
#define E1000_IMS_EPRST     E1000_ICR_EPRST

/* This defines the bits that are set in the Interrupt Mask
 * Set/Read Register.  Each bit is documented below:
 *   o RXT0   = Receiver Timer Interrupt (ring 0)
 *   o TXDW   = Transmit Descriptor Written Back
 *   o RXDMT0 = Receive Descriptor Minimum Threshold hit (ring 0)
 *   o RXSEQ  = Receive Sequence Error
 *   o LSC    = Link Status Change
 */
#define IMS_ENABLE_MASK ( \
    E1000_IMS_RXT0   |    \
    E1000_IMS_TXDW   |    \
    E1000_IMS_RXDMT0 |    \
    E1000_IMS_RXSEQ  |    \
    E1000_IMS_LSC)

/* Transmit Descriptor */
struct E1000TxDesc {
    u64 buffer_addr;       /* Address of the descriptor's data buffer */
	u16 length;    /* Data buffer length */
    u8 cso;        /* Checksum offset */
    u8 cmd;        /* Descriptor control */
    u8 status;     /* Descriptor status */
    u8 css;        /* Checksum start */
    u16 special;

}__attribute__((packed));

/* Receive Descriptor */
struct E1000RxDesc {
	u64 buffer_addr;
	u16 length;             /* Data buffer length */
	u16 chksum;             /* Check Sum */
	u8  status;
	u8  err;
	u16 special;
};

#endif 	// _E1000_H_