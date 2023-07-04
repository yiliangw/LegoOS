#include "lego/irq.h"
#include "lego/irqdesc.h"
#include "lego/kernel.h"
#include "lego/printk.h"
#include "lego/types.h"
#include "net/lwip/inet.h"
#include <net/e1000.h>
#include "e1000.h"
#include <lego/pci.h>
#include <lego/string.h>
#include <lego/mm.h>
#include <net/netif/etharp.h>
#include <asm/io.h>

static struct tx_desc txDescArr[NUM_TX_DESC] __attribute__ ((aligned (PAGE_SIZE)))  =  {{0, 0, 0, 0, 0, 0, 0}};
static struct rx_desc rxDescArr[NUM_RX_DESC] __attribute__ ((aligned (PAGE_SIZE)))  =  {{0, 0, 0, 0, 0, 0}};

static int tx_desc_head = 0;
static int tx_desc_tail = 0;
static int rx_desc_head = 0;
static int rx_desc_tail = 0;
static volatile u32 *map_region;

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

static struct netif e1000_nif;
static char rxbuf[PAGE_SIZE];

/** Interrupt handler **/
void jif_input(struct netif *netif, void *va);

static irqreturn_t e1000_intr_handler(int irq, void *data)
{
	struct pci_dev *pdev;
	int ret;
	size_t len;

	pdev = (struct pci_dev *) data;
	if (irq != pdev->irq)
		return IRQ_NONE;

	ret = e1000_receive(rxbuf, &len);
	if (ret) {
		pr_err("%s: Fail to receive packet\n", __func__);
	} else {
		pr_info("%s: Receive %lu bytes\n", __func__, len);
	 	jif_input(&e1000_nif, rxbuf);
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

/** MAC address initialization **/
static int e1000_set_mac(void)
{
	#if ETHARP_HWADDR_LEN != 6
	#error ETHARP_HWADDR_LEN not equal to 6
	#endif

	uint32_t mac[6];
	uint32_t low = 0, high = 0;
	int i, ret;

	ret = sscanf(CONFIG_E1000_NETIF_MAC, "%x:%x:%x:%x:%x:%x",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (ret != 6)
		panic("%s: Fail to convert MAC address\n", __func__);

	for (i = 0; i < 4; i++)
		low |= mac[i] << (8 * i);

	for (i = 4; i < 6; i++)
		high |= mac[i] << (8 * i);

	map_region[E1000_LOCATE(E1000_RA)] = low;
	map_region[E1000_LOCATE(E1000_RA) + 1] = high | E1000_RAH_AV;

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

static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int err;
	uint8_t mac[6];

	err = pci_enable_device(pdev);
	if (err) {
		pr_err("Fail to enable e1000\n");
		return err;
	}

	err = pci_request_regions(pdev, "e1000");
	if (err) {
		pr_err("pci %s: Couldn't get PCI resources, aborting\n",
			pci_name(pdev));
		return err;
	}

	err = e1000_request_irq(pdev);
	if (err) {
		pr_err("Unable to allocate interrupt Error: %d\n", err);
		return err;
	}

	pr_debug("pci_func_attach_E1000 pdev %p\n", pdev);
	map_region = (u32 *)ioremap_nocache(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
	pr_debug("Device status reg is %x\n",map_region[2]);

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
	if (err) {
		pr_err("Fail to set e1000 MAC addr\n");
		return err;
	}
		
	initializeTxDescriptors();
	initializeRxDescriptors();

	pr_debug("Initialized E1000 device\n");
	return 0;
}

static void e1000_remove(struct pci_dev *pdev)
{
}

static struct pci_driver e1000_driver = {
	.name		= "e1000",
	.id_table	= e1000_pci_tbl,
	.probe		= e1000_probe,
	.remove		= e1000_remove,
};

/** Network interface initialization */
err_t jif_init(struct netif *netif);

static int e1000_init_lwip_netif(void *if_state,
        uint32_t init_addr, uint32_t init_mask, uint32_t init_gw, int default_nif)
{
    struct ip_addr ipaddr, netmask, gateway;
    ipaddr.addr  = init_addr;
    netmask.addr = init_mask;
    gateway.addr = init_gw;

    if (netif_add(&e1000_nif, &ipaddr, &netmask, &gateway,
			if_state, jif_init, ip_input) == NULL) {
        panic("%s: netif_add failed\n", __func__);
		return -1;
	}

	pr_info("%s: added netif\n", __func__);

	if (default_nif) {
   		netif_set_default(&e1000_nif);
		pr_info("%s: set as default netif\n", __func__);
	}
	
    netif_set_up(&e1000_nif);

	return 0;
}

int __init e1000_init(void)
{
	int ret;

	/* Initialize lwip netwok interface */
	ret = e1000_init_lwip_netif(NULL, inet_addr(CONFIG_E1000_NETIF_IP),
		inet_addr(CONFIG_E1000_NETIF_MASK), inet_addr(CONFIG_E1000_NETIF_GATEWAY), true);
	if (ret)
		panic("Fail to initialize lwip network interface\n");

	ret = pci_register_driver(&e1000_driver);
	if (ret)
		panic("Fail to register e1000 PCI drive\n");
}


int e1000_transmit(const void *src, size_t len){ //Need to check for more parameters
	void * va;

	pr_debug("%s: packet length: %lu\n", __func__, len);

	if(len > E1000_TXD_BUFFER_LENGTH) {
		pr_debug("%s: packet too long\n", __func__);
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
	
	pr_debug("%s: sending packet tail %d\n", __func__, tx_desc_tail);
	return 0;
}

int e1000_receive(void *buf, size_t *len)
{ //Need to check for more parameters
	const void * va;
	int n = 0;

	//pr_debug("Inside pci_receive_packet %d\n", rx_desc_tail);
	rx_desc_tail = (rx_desc_tail + 1) % NUM_RX_DESC;

	/*check if descriptors has been filled*/
	if(!(rxDescArr[rx_desc_tail].status & E1000_RXD_STAT_DD)){
		//pr_debug("Rx packet is not available yet [%d] and [%d]\n",rxDescArr[rx_desc_tail].status, rx_desc_tail);
		rx_desc_tail = map_region[0x2818 >> 2];
		return -1;
	}

	n = rxDescArr[rx_desc_tail].length;

	va = __va(rxDescArr[rx_desc_tail].addr);
	memmove(buf, va, n);
	*len = n;

	//Reset the status as free descriptor
	rxDescArr[rx_desc_tail].status &= ~0x03;
	
	//rx_desc_tail = (rx_desc_tail + 1) % NUM_RX_DESC;

	//Update the tail pointer
	map_region[0x2818 >> 2] = rx_desc_tail;
	
	pr_debug("receiving packet rx_desc_tail %d\n", rx_desc_tail);

	//return length of packet
	return 0;
}



#define IP "192.168.60.2"
#define MASK "255.255.255.0"
#define DEFAULT "192.168.60.1"




