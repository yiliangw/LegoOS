#include "asm/page.h"
#include "asm/page_types.h"
#include <lego/errno.h>
#include <lego/kernel.h>
#include <lego/printk.h>
#include <lego/pci.h>
#include <lego/types.h>
#include <lego/irq.h>
#include <lego/irqdesc.h>
#include <lego/mm.h>

#include <asm/io.h>
#include <net/netif/etharp.h>
#include <net/e1000.h>

#define GITHUB_SOURCE


#define E1000_LOCATE(offset)	(offset >> 2)

#define TX_DESC_SIZE     32
#define TX_PACKET_SIZE   2048

#define RX_DESC_SIZE     128
#define RX_PACKET_SIZE   2048

/* Register Set
 * 
 * RW - register is both readable and writable
 * 
 */
#define E1000_DEVICE_STATUS   0x00008  /* Device Status - RO */

#define E1000_ICS      0x000C8  /* Interrupt Cause Set - WO */
#define E1000_IMS      0x000D0  /* Interrupt Mask Set - RW */

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


/* Transmit Descriptor */
struct E1000TxDesc {
    uint64_t buffer_addr;       /* Address of the descriptor's data buffer */

	uint16_t length;    /* Data buffer length */
    uint8_t cso;        /* Checksum offset */
    uint8_t cmd;        /* Descriptor control */

    uint8_t status;     /* Descriptor status */
    uint8_t css;        /* Checksum start */
    uint16_t special;

}__attribute__((packed));

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

/* Receive Descriptor */
struct E1000RxDesc {
	uint64_t buffer_addr;
	uint16_t length;             /* Data buffer length */
	uint16_t chksum;             /* Check Sum */
	uint8_t  status;
	uint8_t  err;
	uint16_t special;
};

/* Transmit Descriptor bit definitions */
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
static volatile uint32_t *e1000;

struct E1000TxDesc tx_desc_list[TX_DESC_SIZE] __attribute__((aligned (PAGE_SIZE))) ;
char tx_pbuf[TX_DESC_SIZE][TX_PACKET_SIZE] __attribute__((aligned (PAGE_SIZE))) ;

struct E1000RxDesc rx_desc_list[RX_DESC_SIZE] __attribute__((aligned (PAGE_SIZE))) ;
char rx_pbuf[RX_DESC_SIZE][RX_PACKET_SIZE] __attribute__((aligned (PAGE_SIZE))) ;

void (*e1000_input_callback)(void) = NULL;
u8 e1000_mac[ETHARP_HWADDR_LEN];

#define INTEL_E1000_ETHERNET_DEVICE(device_id) {\
	PCI_DEVICE(PCI_VENDOR_ID_INTEL, device_id)}
static DEFINE_PCI_DEVICE_TABLE(e1000_pci_tbl) = {
	INTEL_E1000_ETHERNET_DEVICE(0x1000),
	INTEL_E1000_ETHERNET_DEVICE(0x1001),
	INTEL_E1000_ETHERNET_DEVICE(0x1004),
	INTEL_E1000_ETHERNET_DEVICE(0x1008),
	INTEL_E1000_ETHERNET_DEVICE(0x1009),
	INTEL_E1000_ETHERNET_DEVICE(0x100C),
	INTEL_E1000_ETHERNET_DEVICE(0x100D),
	INTEL_E1000_ETHERNET_DEVICE(0x100E),
	INTEL_E1000_ETHERNET_DEVICE(0x100F),
	INTEL_E1000_ETHERNET_DEVICE(0x1010),
	INTEL_E1000_ETHERNET_DEVICE(0x1011),
	INTEL_E1000_ETHERNET_DEVICE(0x1012),
	INTEL_E1000_ETHERNET_DEVICE(0x1013),
	INTEL_E1000_ETHERNET_DEVICE(0x1014),
	INTEL_E1000_ETHERNET_DEVICE(0x1015),
	INTEL_E1000_ETHERNET_DEVICE(0x1016),
	INTEL_E1000_ETHERNET_DEVICE(0x1017),
	INTEL_E1000_ETHERNET_DEVICE(0x1018),
	INTEL_E1000_ETHERNET_DEVICE(0x1019),
	INTEL_E1000_ETHERNET_DEVICE(0x101A),
	INTEL_E1000_ETHERNET_DEVICE(0x101D),
	INTEL_E1000_ETHERNET_DEVICE(0x101E),
	INTEL_E1000_ETHERNET_DEVICE(0x1026),
	INTEL_E1000_ETHERNET_DEVICE(0x1027),
	INTEL_E1000_ETHERNET_DEVICE(0x1028),
	INTEL_E1000_ETHERNET_DEVICE(0x1075),
	INTEL_E1000_ETHERNET_DEVICE(0x1076),
	INTEL_E1000_ETHERNET_DEVICE(0x1077),
	INTEL_E1000_ETHERNET_DEVICE(0x1078),
	INTEL_E1000_ETHERNET_DEVICE(0x1079),
	INTEL_E1000_ETHERNET_DEVICE(0x107A),
	INTEL_E1000_ETHERNET_DEVICE(0x107B),
	INTEL_E1000_ETHERNET_DEVICE(0x107C),
	INTEL_E1000_ETHERNET_DEVICE(0x108A),
	INTEL_E1000_ETHERNET_DEVICE(0x1099),
	INTEL_E1000_ETHERNET_DEVICE(0x10B5),
	INTEL_E1000_ETHERNET_DEVICE(0x2E6E),
	/* required last entry */
	{0,}
};

static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void e1000_remove(struct pci_dev *pdev);
static struct pci_driver e1000_driver = {
	.name		= "e1000",
	.id_table	= e1000_pci_tbl,
	.probe		= e1000_probe,
	.remove		= e1000_remove,
};

int __init e1000_init(void)
{
	int ret;

	ret = pci_register_driver(&e1000_driver);
	if (ret) {
		pr_err("e1000: pci_register_driver failed %d\n", ret);
		return ret;
	}

	return 0;
}

int e1000_transmit(const void *addr, u16 len)
{
	pr_debug("e1000: Transmiting a packet len=%u\n", len);
	size_t tdt = e1000[E1000_LOCATE(E1000_TDT)];
	struct E1000TxDesc *tail_desc = &tx_desc_list[tdt];
	
	if ( !(tail_desc->status & E1000_TXD_STAT_DD )) {
		// Status is not DD
		return -ENODATA;
	}
	memmove(tx_pbuf[tdt], addr, len);
	
	tail_desc->length = (uint16_t )len;
	// clear DD 
	tail_desc->status &= (~E1000_TXD_STAT_DD);

	e1000[E1000_LOCATE(E1000_TDT)] = (tdt+1) % TX_DESC_SIZE;

	pr_debug("e1000: Transmission done\n");
	return 0;
}

int e1000_receive(void *buf, u16 *len)
{
	static size_t next = 0;
	size_t tail = e1000[E1000_LOCATE(E1000_RDT)];
	if ( !(rx_desc_list[next].status & E1000_RXD_STAT_DD) ) {
		return -1;
	}
	*len = rx_desc_list[next].length;
	memcpy(buf, rx_pbuf[next], *len);

	rx_desc_list[next].status &= ~E1000_RXD_STAT_DD; 
	next = (next + 1) % RX_DESC_SIZE;
	e1000[E1000_LOCATE(E1000_RDT)] = (tail + 1 ) % RX_DESC_SIZE;
	return 0;
}

static int e1000_set_mac(void)
{
#if ETHARP_HWADDR_LEN != 6
#error ETHARP_HWADDR_LEN must be 6 for ethernet
#endif
	u32 mac[6] = {};
	u32 low, high;
	int i, ret;

	ret = sscanf(CONFIG_E1000_NETIF_MAC, "%x:%x:%x:%x:%x:%x",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (ret != 6) {
		pr_err("e1000: Fail to get mac from CONFIG_E1000_NETIF_MAC: %s\n", CONFIG_E1000_NETIF_MAC);
		return -1;
	}

	low = high = 0;
	for (i = 0; i < 4; i++) {
		low |= (mac[i] << (i * 8));
		e1000_mac[i] = mac[i];
	}
	for (i = 4; i < 6; i++) {
		high |= (mac[i] << ((i - 4) * 8));
		e1000_mac[i] = mac[i];
	}

	e1000[E1000_LOCATE(E1000_RA)] = low;
	e1000[E1000_LOCATE(E1000_RA) + 1] = high | E1000_RAH_AV;

	pr_info("e1000: Set mac address to %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return 0;
}

static void e1000_transmit_init(void) 
{
	size_t i;
	memset(tx_desc_list, 0 , sizeof(struct E1000TxDesc) * TX_DESC_SIZE);
	for (i = 0; i < TX_DESC_SIZE; i++) {
		tx_desc_list[i].buffer_addr = virt_to_phys(tx_pbuf[i]);
		tx_desc_list[i].status = E1000_TXD_STAT_DD;
		tx_desc_list[i].cmd    =  E1000_TXD_CMD_RS | E1000_TXD_CMD_EOP;
		
	}

	e1000[E1000_LOCATE(E1000_TDBAL)] = virt_to_phys(tx_desc_list);
	e1000[E1000_LOCATE(E1000_TDBAH)] = 0;
	e1000[E1000_LOCATE(E1000_TDLEN)] = sizeof(struct E1000TxDesc) * TX_DESC_SIZE;
	// ensure that TDH and TDT are 0 index not offset
	e1000[E1000_LOCATE(E1000_TDH)] = 0;
	e1000[E1000_LOCATE(E1000_TDT)] = 0;

	// Initialize the Transmit Control Register (TCTL)
	e1000[E1000_LOCATE(E1000_TCTL)] = E1000_TCTL_EN | 
									  E1000_TCTL_PSP |
									  (E1000_TCTL_CT & (0x10 << 4)) |
									  (E1000_TCTL_COLD & (0x40 << 12));

	// 10 8 6 
	// 10 8 12
	e1000[E1000_LOCATE(E1000_TIPG)] = 10 | (8 << 10) | (12 << 20);
}

static void e1000_receive_init(void)
{
	size_t i;
	memset(rx_desc_list, 0 , sizeof(struct E1000RxDesc) * RX_DESC_SIZE);
	for (i = 0; i < RX_DESC_SIZE; i++) {
		rx_desc_list[i].buffer_addr = virt_to_phys(rx_pbuf[i]);
	}
	
	e1000[E1000_LOCATE(E1000_ICS)] = 0;
	e1000[E1000_LOCATE(E1000_IMS)] = 0;
	e1000[E1000_LOCATE(E1000_RDBAL)] = virt_to_phys(rx_desc_list);
	e1000[E1000_LOCATE(E1000_RDBAH)] = 0;

	e1000[E1000_LOCATE(E1000_RDLEN)] = sizeof(struct E1000RxDesc) * RX_DESC_SIZE;
	e1000[E1000_LOCATE(E1000_RDT)] = RX_DESC_SIZE - 1;

	e1000[E1000_LOCATE(E1000_RDH)] = 0;

	e1000[E1000_LOCATE(E1000_RCTL)] = E1000_RCTL_EN | E1000_RCTL_SECRC | E1000_RCTL_BAM | E1000_RCTL_SZ_2048;

	e1000_set_mac();
}

static irqreturn_t e1000_intr_handler(int irq, void *data)
{
	struct pci_dev *pdev;

	pdev = (struct pci_dev *) data;
	if (irq != pdev->irq)
		return IRQ_NONE;

	if (e1000_input_callback)
		e1000_input_callback();

	return IRQ_HANDLED;
}

static int e1000_request_irq(struct pci_dev *pdev)
{
	irq_handler_t handler = e1000_intr_handler;
	int irq_flags = IRQF_SHARED;
	int err;

	err = request_irq(pdev->irq, handler, irq_flags, pci_name(pdev), pdev);

	return err;
}

static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int err;

	err = pci_enable_device(pdev);
	if (err) {
		pr_err("e1000: pci_enable_device: %d\n", err);
		return err;
	}

	err = pci_request_regions(pdev, "e1000");
	if (err) {
		pr_err("e1000: pci_request_regions: %d\n", err);
		return err;
	}

	err = e1000_request_irq(pdev);
	if (err) {
		pr_err("e1000: request_irq: %d\n", err);
		return err;
	}

	pr_debug("e1000: pdev %p\n", pdev);

	e1000 = (uint32_t *)ioremap_nocache(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
	e1000_transmit_init();
	e1000_receive_init();
	pr_debug("e1000: Initialized\n");
}

static void e1000_remove(struct pci_dev *pdev)
{
}
