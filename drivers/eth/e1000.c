#include "asm/types.h"
#include <net/e1000.h>
#include <lego/pci.h>
#include <lego/types.h>
//#include <lego/pmap.h>
#include <lego/string.h>
#include <lego/mm.h>
#include <net/netif/etharp.h>
#include <asm/io.h>

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
	return n;
}

int pci_func_attach_E1000(struct pci_dev *f)
{
	pci_func_enable(f);
	pr_debug("pci_func_attach_E1000 f %p\n", f);
	map_region = (u32 *)ioremap_nocache(f->reg_base[0] ,(size_t)f->reg_size[0]);
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
		
	//Setting mac address    
	//uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56}; //from testoutput.c
	//memmove((void*)&map_region[0x5400 >> 2], mac,  ETHARP_HWADDR_LEN);	//RAL and RAH

	//pr_debug("hex 1 %x vs 0x12005452\n",map_region[0x5400]);
	//pr_debug("hex 2 %x vs 0x5634\n",map_region[0x5404]);
	/*Receiving intialize end*/

	initializeTxDescriptors();
	initializeRxDescriptors();

	pr_debug("Initialized E1000 device\n");
	return 0;
}

