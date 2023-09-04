#ifdef _LEGO_LINUX_MODULE_
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/mm.h>
#else
#include <lego/device.h>
#include <lego/dma-mapping.h>
#include <lego/errno.h>
#include <lego/kernel.h>
#include <lego/printk.h>
#include <lego/pci.h>
#include <lego/types.h>
#include <lego/irq.h>
#include <lego/irqdesc.h>
#include <lego/mm.h>
#endif /* _LEGO_LINUX_MODULE_ */

#include <net/netif/etharp.h>
#include <net/e1000.h>

#include "e1000.h"


static volatile u32 *e1000;

struct E1000TxDesc *tx_desc_list;
u8 *tx_pbuf;

struct E1000RxDesc *rx_desc_list;
u8 *rx_pbuf;

void (*e1000_input_callback)(void) = NULL;
u8 e1000_mac[ETHARP_HWADDR_LEN];

#define INTEL_E1000_ETHERNET_DEVICE(device_id) {\
	PCI_DEVICE(PCI_VENDOR_ID_INTEL, device_id)}
static const struct pci_device_id e1000_pci_tbl[] = {
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
		e1000_err("pci_register_driver failed %d\n", ret);
		return ret;
	}

	return 0;
}

void e1000_exit(void)
{
	pci_unregister_driver(&e1000_driver);
}

int e1000_prepare(const void *src, size_t len, off_t offset)
{
	size_t tdt, tdh;
	struct E1000TxDesc *tail_desc;

	if (offset + len > TX_PACKET_SIZE) {
		e1000_err("Packet size too large\n");
		return -EINVAL;
	}

	tdt = e1000[E1000_LOCATE(E1000_TDT)];
	tdh = e1000[E1000_LOCATE(E1000_TDH)];

	if ((tdt + 1) % TX_DESC_NUM == tdh) {
		e1000_warn("%s transmission queue full\n", __func__);
		return -ENOMEM;
	}

	tail_desc = tx_desc_list + tdt;
	
	if ( !(tail_desc->status & E1000_TXD_STAT_DD )) {
		/* This really should not happen */
		e1000_err("Status is not DD\n");
		return -EPERM;
	}

	memcpy(tx_pbuf + TX_PACKET_SIZE * tdt + offset, src, len);
	
	e1000_debug("Preparation done. offset=%ld, length=%lu\n", offset, len);
	return 0;
}

int e1000_transmit(size_t len)
{
	size_t tdt, tdh;
	struct E1000TxDesc *tail_desc;

	if (len > TX_PACKET_SIZE) {
		e1000_err("Packet size too large\n");
		return -EINVAL;
	}

	tdt = e1000[E1000_LOCATE(E1000_TDT)];
	tdh = e1000[E1000_LOCATE(E1000_TDH)];

	if ((tdt + 1) % TX_DESC_NUM == tdh) {
		e1000_warn("%s trasmission queue full\n", __func__);
		return -EPERM;
	}

	tail_desc = tx_desc_list + tdt;
	if ( !(tail_desc->status & E1000_TXD_STAT_DD )) {
		e1000_debug("Transmiting status is not DD\n");
		return -ENODATA;
	}

	e1000_debug("Transmiting a packet len=%lu\n", len);
	
	tail_desc->length = (uint16_t )len;
	tail_desc->status &= (~E1000_TXD_STAT_DD);

	e1000[E1000_LOCATE(E1000_TDT)] = (tdt+1) % TX_DESC_NUM;

	e1000_debug("Transmission done\n");
	return 0;
}

static inline size_t __pending_reception(u32 rdt, u32 rdh)
{
	return (rdh + RX_DESC_NUM - rdt - 1) % RX_DESC_NUM;	
}

size_t e1000_pending_reception(void)
{
	u32 rdt, rdh;
	rdt = e1000[E1000_LOCATE(E1000_RDT)];
	rdh = e1000[E1000_LOCATE(E1000_RDH)];
	return __pending_reception(rdt, rdh);
}

void e1000_clear_pending_reception(size_t num)
{
	u32 rdt, rdh;
	size_t pending;
	/* Notice that the head can keep being changed by the hardware */
	rdh = e1000[E1000_LOCATE(E1000_RDH)];
	rdt = e1000[E1000_LOCATE(E1000_RDT)];
	pending = __pending_reception(rdt, rdh);
	num = min(num, pending);
	e1000[E1000_LOCATE(E1000_RDT)] = (rdt + num + RX_DESC_NUM) % RX_DESC_NUM;
}

int e1000_receive(void *buf, u16 *len)
{
	u32 rdt, rdh, next;

	rdt = e1000[E1000_LOCATE(E1000_RDT)];
	rdh = e1000[E1000_LOCATE(E1000_RDH)];
	next = (rdt + 1) % RX_DESC_NUM;

	if (next == rdh) {
		return -ENODATA;
	}

	if (!(rx_desc_list[next].status & E1000_RXD_STAT_DD) ) {
		e1000_err("Receive status is not DD\n");
		return -EPERM;
	}

	*len = rx_desc_list[next].length;
	memcpy(buf, rx_pbuf + next * RX_PACKET_SIZE, *len);

	rx_desc_list[next].status &= ~E1000_RXD_STAT_DD; 
	e1000[E1000_LOCATE(E1000_RDT)] = next;
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

	ret = sscanf(E1000_NETIF_MAC, "%x:%x:%x:%x:%x:%x",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (ret != 6) {
		e1000_err("Fail to get mac from E1000_NETIF_MAC: %s\n", E1000_NETIF_MAC);
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

	e1000_info("Set mac address to %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return 0;
}

static void e1000_transmit_init(struct pci_dev *pdev) 
{
	size_t i;
	dma_addr_t desc_dma_addr, pbuf_dma_addr;
	
	const size_t desc_size = sizeof(struct E1000TxDesc) * TX_DESC_NUM;
	const size_t buf_size = TX_DESC_NUM * TX_PACKET_SIZE;

	// initialize DMA for transmit descriptors and buffers
	tx_desc_list = (struct E1000TxDesc *)dma_alloc_coherent(&pdev->dev, desc_size, &desc_dma_addr, GFP_KERNEL);
	if (tx_desc_list == NULL) {
		e1000_err("dma_alloc_coherent failed 1\n");
		return;
	}
	tx_pbuf = dma_alloc_coherent(&pdev->dev, buf_size, &pbuf_dma_addr, GFP_KERNEL);
	if (tx_pbuf == NULL) {
		e1000_err("dma_alloc_coherent failed 2\n");
		return;
	}
	memset(tx_desc_list, 0 , desc_size);
	for (i = 0; i < TX_DESC_NUM; i++) {
		tx_desc_list[i].buffer_addr = pbuf_dma_addr + i * TX_PACKET_SIZE;
		tx_desc_list[i].status = E1000_TXD_STAT_DD;
		tx_desc_list[i].cmd    =  E1000_TXD_CMD_RS | E1000_TXD_CMD_EOP;
	}
	e1000[E1000_LOCATE(E1000_TDBAL)] = desc_dma_addr & 0xFFFFFFFF;
	e1000[E1000_LOCATE(E1000_TDBAH)] = (desc_dma_addr >> 32) & 0xFFFFFFFF;
	e1000[E1000_LOCATE(E1000_TDLEN)] = desc_size;
	// ensure that TDH and TDT are 0 index not offset
	e1000[E1000_LOCATE(E1000_TDH)] = 0;
	e1000[E1000_LOCATE(E1000_TDT)] = 0;

	// initialize the Transmit Control Register (TCTL)
	e1000[E1000_LOCATE(E1000_TCTL)] = E1000_TCTL_EN | 
									  E1000_TCTL_PSP |
									  (E1000_TCTL_CT & (0x10 << 4)) |
									  (E1000_TCTL_COLD & (0x40 << 12));

	// 10 8 6 
	// 10 8 12
	e1000[E1000_LOCATE(E1000_TIPG)] = 10 | (8 << 10) | (12 << 20);
	e1000_debug("Transmit init done\n");
}

static void e1000_receive_init(struct pci_dev *pdev)
{
	size_t i;
	dma_addr_t desc_dma_addr, pbuf_dma_addr;
	const size_t desc_size = sizeof(struct E1000RxDesc) * RX_DESC_NUM;
	const size_t buf_size = RX_DESC_NUM * RX_PACKET_SIZE;

	// initialize DMA for receive descriptors and buffers
	rx_desc_list = (struct E1000RxDesc *)dma_alloc_coherent(&pdev->dev, desc_size, &desc_dma_addr, GFP_KERNEL);
	if (rx_desc_list == NULL) {
		e1000_err("dma_alloc_coherent\n");
		return;
	}
	rx_pbuf = dma_alloc_coherent(&pdev->dev, buf_size, &pbuf_dma_addr, GFP_KERNEL);
	if (rx_pbuf == NULL) {
		e1000_err("dma_alloc_coherent 3\n");
		return;
	}
	memset(rx_desc_list, 0 , desc_size);
	for (i = 0; i < RX_DESC_NUM; i++) {
		rx_desc_list[i].buffer_addr = pbuf_dma_addr + i * RX_PACKET_SIZE;
	}
	e1000[E1000_LOCATE(E1000_RDBAL)] = desc_dma_addr & 0xFFFFFFFF;
	e1000[E1000_LOCATE(E1000_RDBAH)] = (desc_dma_addr >> 32) & 0xFFFFFFFF;
	e1000[E1000_LOCATE(E1000_RDLEN)] = desc_size;

	e1000[E1000_LOCATE(E1000_RDH)] = 0;
	e1000[E1000_LOCATE(E1000_RDT)] = RX_DESC_NUM - 1;

	e1000[E1000_LOCATE(E1000_RCTL)] = E1000_RCTL_EN | E1000_RCTL_SECRC | E1000_RCTL_BAM | E1000_RCTL_SZ_2048;

	e1000_set_mac();

	e1000_debug("Receive init done\n");
}

static irqreturn_t e1000_intr_handler(int irq, void *data)
{
	struct pci_dev *pdev;
	u32 icr;

	icr = e1000[E1000_LOCATE(E1000_ICR)];
	// e1000_debug("Interrupt handler, cause=%x\n", cause);

	pdev = (struct pci_dev *) data;
	if (irq != pdev->irq)
		return IRQ_NONE;

	if ((icr & E1000_IMS_RXT0) && e1000_input_callback) {
		e1000_debug("Received interrupt\n");
		e1000_input_callback();
	}

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
		e1000_err("pci_enable_device: %d\n", err);
		return err;
	}

	// initialize Memory-mapped I/O
	err = pci_request_regions(pdev, "e1000");
	if (err) {
		e1000_err("pci_request_regions: %d\n", err);
		return err;
	}
	e1000 = (u32 *)ioremap(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));

	// initialize Interrupt
	err = e1000_request_irq(pdev);
	if (err) {
		e1000_err("request_irq: %d\n", err);
		return err;
	}
	e1000[E1000_LOCATE(E1000_IMS)] = IMS_ENABLE_MASK;
	// fire a link status change interrupt to start the watchdog
	e1000[E1000_LOCATE(E1000_ICS)] = E1000_ICS_LSC;

	e1000_debug("pdev %p\n", pdev);


	// initialize DMA
	pci_set_master(pdev);
	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		e1000_err("dma_set_mask_and_coherent: %d\n", err);
		return err;
	}

	e1000_transmit_init(pdev);
	e1000_receive_init(pdev);

	e1000_debug("Initialized\n");
	return 0;
}

static void e1000_remove(struct pci_dev *pdev)
{
	e1000_warn("%s not implemented.", __func__);
}
