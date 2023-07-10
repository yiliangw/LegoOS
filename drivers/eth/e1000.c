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

#define E1000_TXDMAC   0x03000  /* TX DMA Control - RW */
#define E1000_KABGTXD  0x03004  /* AFE Band Gap Transmit Ref Data */
#define E1000_TDFH     0x03410  /* TX Data FIFO Head - RW */
#define E1000_TDFT     0x03418  /* TX Data FIFO Tail - RW */
#define E1000_TDFHS    0x03420  /* TX Data FIFO Head Saved - RW */
#define E1000_TDFTS    0x03428  /* TX Data FIFO Tail Saved - RW */
#define E1000_TDFPC    0x03430  /* TX Data FIFO Packet Count - RW */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
#define E1000_TIDV     0x03820  /* TX Interrupt Delay Value - RW */
#define E1000_TXDCTL   0x03828  /* TX Descriptor Control - RW */
#define E1000_TADV     0x0382C  /* TX Interrupt Absolute Delay Val - RW */
#define E1000_TSPMT    0x03830  /* TCP Segmentation PAD & Min Threshold - RW */
#define E1000_TARC0    0x03840  /* TX Arbitration Count (0) */
#define E1000_TDBAL1   0x03900  /* TX Desc Base Address Low (1) - RW */
#define E1000_TDBAH1   0x03904  /* TX Desc Base Address High (1) - RW */
#define E1000_TDLEN1   0x03908  /* TX Desc Length (1) - RW */
#define E1000_TDH1     0x03910  /* TX Desc Head (1) - RW */
#define E1000_TDT1     0x03918  /* TX Desc Tail (1) - RW */
#define E1000_TXDCTL1  0x03928  /* TX Descriptor Control (1) - RW */
#define E1000_TARC1    0x03940  /* TX Arbitration Count (1) */
#define E1000_TXD_BUFFER_LENGTH 0x5EE
#define E1000_RXD_BUFFER_LENGTH 0x5EE
#define NUM_TX_DESC 64
#define NUM_RX_DESC 128

#define E1000_RA       0x05400  /* Receive Address - RW Array */

#define E1000_RAH_AV            0x80000000		/* Receive descriptor valid */

#define E1000_LOCATE(offset)	(offset >> 2)

struct tx_desc {
	u64 addr;
	u16 length;
	u8 cso;
	u8 cmd;
	u8 status;
	u8 css;
	u16 special;
};

struct rx_desc {
	u64 addr;
	u16 length;
	u16 chcksum;
	u8 status;
	u8 errors;
	u16 special;
};

static struct tx_desc txDescArr[NUM_TX_DESC] __attribute__ ((aligned (PAGE_SIZE)))  =  {{0, 0, 0, 0, 0, 0, 0}};
static struct rx_desc rxDescArr[NUM_RX_DESC] __attribute__ ((aligned (PAGE_SIZE)))  =  {{0, 0, 0, 0, 0, 0}};

static int tx_desc_head = 0;
static int tx_desc_tail = 0;
static int rx_desc_head = 0;
static int rx_desc_tail = 0;
static volatile u32 *map_region;

static struct netif e1000_netif;
static char rxbuf[PAGE_SIZE];

void (*e1000_input)(const void *src, u16 len) = NULL;

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

int e1000_transmit(const void *src, u16 len)
{ //Need to check for more parameters
	void * va;

	pr_debug("Inside pci_transmit_packet %d\n", tx_desc_tail);
	pr_debug("String %s size %d\n",src, len);

	if(len > E1000_TXD_BUFFER_LENGTH){
		pr_debug("This should not fail\n");
		return -1;
	}

	/*check if free descriptors are available*/
	if(!(txDescArr[tx_desc_tail].status & 0x1)){
		pr_debug("Tx Desc is not free [%d] and [%d]\n",txDescArr[tx_desc_tail].status, tx_desc_tail);
		return -1;
	}

	va = __va(txDescArr[tx_desc_tail].addr);
	memmove(va, src, len);

	//set packet length
	txDescArr[tx_desc_tail].length = len;
	//txDescArr[tx_desc_tail].length = n+14;  //taking ethernet header in consideration 
						//but script is failing with this
	//Reset the status as not free
	txDescArr[tx_desc_tail].status = 0x0;											  

	//Update the tail pointer
	tx_desc_tail = (tx_desc_tail + 1) % NUM_TX_DESC;
	map_region[0x3818 >> 2] = tx_desc_tail;	
	
	pr_debug("sending packet tail %d\n", tx_desc_tail);
	return 0;
}

int e1000_receive(void *dst, u16 *len)
{ //Need to check for more parameters
	const void * va;
	int n = 0;

	//pr_debug("Inside pci_receive_packet %d\n", rx_desc_tail);
	rx_desc_tail = (rx_desc_tail + 1) % NUM_RX_DESC;

	/*check if descriptors has been filled*/
	if(!(rxDescArr[rx_desc_tail].status & 0x1)){
		//pr_debug("Rx packet is not available yet [%d] and [%d]\n",rxDescArr[rx_desc_tail].status, rx_desc_tail);
		rx_desc_tail = map_region[0x2818 >> 2]; 
		return -1;
	}

	n = rxDescArr[rx_desc_tail].length;

	va = __va(rxDescArr[rx_desc_tail].addr);
	memmove(dst, va, n);

	//Reset the status as free descriptor
	rxDescArr[rx_desc_tail].status &= ~0x03;
	
	//rx_desc_tail = (rx_desc_tail + 1) % NUM_RX_DESC;

	//Update the tail pointer
	map_region[0x2818 >> 2] = rx_desc_tail;	
	
	pr_debug("receiving packet rx_desc_tail %d\n", rx_desc_tail);

	//return length of packet
	return 0;
}

static void initializeTxDescriptors(void)
{
	int i;
	struct page* page;
	for (i = 0; i < NUM_TX_DESC; i++){
		page = alloc_page();
		txDescArr[i].addr = page_to_phys(page);
		txDescArr[i].cmd = 0x09;
		txDescArr[i].length = E1000_TXD_BUFFER_LENGTH;
		txDescArr[i].status = 0x1;
	}
}

static void initializeRxDescriptors(void)
{
	int i;
	struct page* page;
	for (i = 0; i < NUM_RX_DESC; i++){
		page = alloc_page();
		rxDescArr[i].addr = page_to_phys(page);
		//no cmd to give
		//length will get set by hardware based on incoming packet size
		//status set deafult as 0 so no need to update here
	}
}

static irqreturn_t e1000_intr_handler(int irq, void *data)
{
	struct pci_dev *pdev;
	int ret;
	u16 len;

	pdev = (struct pci_dev *) data;
	if (irq != pdev->irq)
		return IRQ_NONE;

	ret = e1000_receive(rxbuf, &len);
	if (ret) {
		pr_err("e1000: Fail to receive packet\n");
	} else {
		pr_info("e1000: Receive %u bytes\n", len);
		if (e1000_input)
			e1000_input(rxbuf, len);
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
	for (i = 0; i < 4; i++)
		low |= (mac[i] << (i * 8));
	for (i = 4; i < 6; i++)
		high |= (mac[i] << ((i - 4) * 8));

	map_region[E1000_LOCATE(E1000_RA)] = low;
	map_region[E1000_LOCATE(E1000_RA) + 1] = high | E1000_RAH_AV;

	pr_info("e1000: Set mac address to %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return 0;
}

static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int err;
	uint8_t mac[6];

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
	map_region = (u32 *)ioremap_nocache(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
	pr_debug("e1000: Device status reg is %x\n",map_region[2]);

	/*Sending intialize start*/
	map_region[0x3810 >> 2] = 0x0; //TDH set to 0b
	map_region[0x3818 >> 2] = 0x0; //TDT set to 0b

	map_region[0x400 >> 2] = 0x4008A; //TCTL
	map_region[0x410 >> 2] = 0x60200A; //TIPG  /*binary: 00000000011000000010000000001010*/
	map_region[0x3800 >> 2] = __pa(txDescArr); //TDBAL & TDBAH
	map_region[0x3808 >> 2] = NUM_TX_DESC << 4;	//TDLEN set to 1024 = 64*16 = 0x400
	/*Sending intialize end*/

	/*Receiving intialize start*/
	map_region[0x2810 >> 2] = 0x01; //RDH set to 0b
	map_region[0x2818 >> 2] = 0x0; //RDT set to 0b

	map_region[0x100 >> 2] = 0x4018002; //RCTL  /* Binary 00000100 00000001 10000000 00000010 */
	/* set bits SECRC/BSIZE/BAM/EN */
	map_region[0x2800 >> 2] = __pa(rxDescArr); //RDBAL & RDBAH
	map_region[0x2808 >> 2] = NUM_RX_DESC << 4;	//RDLEN set to 1024 = 64*16 = 0x400
	map_region[0x5200 >> 2] = 0x0;	//MTA (Multicast Tablr Array) set to 0 for now

	map_region[0x5400 >> 2] = 0x12005452;
	map_region[0x5404 >> 2] = 0x5634 | 0x80000000;

	err = e1000_set_mac();
	if (err)
		return err;

	initializeTxDescriptors();
	initializeRxDescriptors();

	pr_debug("e1000: Initialized\n");
	return 0;
}

static void e1000_remove(struct pci_dev *pdev)
{
}

