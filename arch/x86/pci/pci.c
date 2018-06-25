#include <lego/string.h>
#include <lego/bug.h>
#include <lego/pci.h>
#include <lego/kernel.h>
#include <asm/io.h>

// Flag to do "lspci" at bootup
static int pci_show_devs = 1;
static int pci_show_addrs = 1;

// PCI "configuration mechanism one"
static u32 pci_conf1_addr_ioport = 0x0cf8;
static u32 pci_conf1_data_ioport = 0x0cfc;
// Forward declarations
static int pci_bridge_attach(struct pci_dev *pcif);

// PCI driver table
struct _pci_driver {
	u32 vendor, device;
	int (*attachfn) (struct pci_dev *pcif); /* New device inserted */
//	const struct pci_device_id *id_table;	/* must be non-NULL for probe to be called */
	void (*remove) (struct pci_dev *pcif);	/* Device removed (NULL if not a hot-plug capable driver) */
//	void (*shutdown) (struct pci_dev *pcif);
};

// pci_attach_class matches the class and subclass of a PCI device
struct _pci_driver pci_attach_class[] = {
	{ PCI_CLASS_BRIDGE, PCI_SUBCLASS_BRIDGE_PCI, &pci_bridge_attach },
	{ 0, 0, 0 },
};

// pci_attach_vendor matches the vendor ID and device ID of a PCI device
struct _pci_driver pci_attach_vendor[] = {
//	{ 0x8086, 0x100E, &pci_func_attach_E1000 }, // #define PCI_VENDOR_ID_INTEL 8086
//	{ 0x8086, 0x1015, &pci_func_attach_E1000 },
	{ 0x15b3, 0x1003, &mlx4_init_one }, // #define PCI_VENDOR_ID_MELLANOX 15b3
	{ 0, 0, 0 },
};

static void
pci_conf1_set_addr(u32 bus,
		   u32 dev,
		   u32 func,
		   u32 offset)
{
	u32 v = (1 << 31) |		// config-space
		(bus << 16) | (dev << 11) | (func << 8) | (offset);

	BUG_ON(!(bus < 256));
	BUG_ON(!(dev < 32));
	BUG_ON(!(func < 8));
	BUG_ON(!(offset < 256));
	BUG_ON(!((offset & 0x3) == 0));

	outl(v, pci_conf1_addr_ioport);
}

u32 pci_conf_read(struct pci_dev *f, u32 off, int len)
{
	u32 val;

	pci_conf1_set_addr(f->bus->number, f->dev, f->func, off);
	switch (len) {
		case 1:
			val = inb(pci_conf1_data_ioport);
			break;
		case 2:
			val = inw(pci_conf1_data_ioport);
			break;
		case 3:
			val = inl(pci_conf1_data_ioport);
			break;
	}

	return val;
}

void pci_conf_write(struct pci_dev *f, u32 off, u32 v, int len)
{
	pci_conf1_set_addr(f->bus->number, f->dev, f->func, off);
	switch (len) {
		case 1:
			outb(v, pci_conf1_data_ioport);
			break;
		case 2:
			outw(v, pci_conf1_data_ioport);
			break;
		case 3:
			outl(v, pci_conf1_data_ioport);
			break;
	}
	return;
}

static int __attribute__((warn_unused_result))
pci_attach_match(u32 vendor, u32 device,
		 struct _pci_driver *list, struct pci_dev *pcif)
{
	u32 i;

	for (i = 0; list[i].attachfn; i++) {
		if (list[i].vendor == vendor && list[i].device == device) {
			int r = list[i].attachfn(pcif);
			if (r > 0)
				return r;
			if (r < 0)
				pr_debug("pci_attach_match: attaching "
					"%x.%x (%p): e\n",
					vendor, device, list[i].attachfn);
		}
	}
	//pr_debug("pci_attach_match %x.%x no match\n", vendor, device);
	return 0;
}

static int pci_attach(struct pci_dev *f)
{
	return
		pci_attach_match(PCI_CLASS(f->dev_class),
				 PCI_SUBCLASS(f->dev_class),
				 &pci_attach_class[0], f) ||
		pci_attach_match(PCI_VENDOR(f->dev_id),
				 PCI_PRODUCT(f->dev_id),
				 &pci_attach_vendor[0], f);
}

static const char *pci_class[] =
{
	[0x0] = "Unknown",
	[0x1] = "Storage controller",
	[0x2] = "Network controller",
	[0x3] = "Display controller",
	[0x4] = "Multimedia device",
	[0x5] = "Memory controller",
	[0x6] = "Bridge device",
};

static void pci_print_func(struct pci_dev *f)
{
	const char *class = pci_class[0];
	if (PCI_CLASS(f->dev_class) < sizeof(pci_class) / sizeof(pci_class[0]))
		class = pci_class[PCI_CLASS(f->dev_class)];

	pr_debug("PCI: %02x:%02Lx.%d: %04x:%04x: class: %x.%x (%s) irq: %d\n",
		f->bus->number, f->dev, f->func,
		PCI_VENDOR(f->dev_id), PCI_PRODUCT(f->dev_id),
		PCI_CLASS(f->dev_class), PCI_SUBCLASS(f->dev_class), class,
		f->irq_line);
}

static int pci_scan_bus(struct pci_bus *bus)
{
	int totaldev = 0;
	struct pci_dev df;
	memset(&df, 0, sizeof(df));
	df.bus = bus;

	//pr_debug("pci_scan_bus enter bus %p\n", bus);
	for (df.dev = 0; df.dev < 32; df.dev++) {
		struct pci_dev f = df;
		u32 bhlc = pci_conf_read(&df, PCI_BHLC_REG, 3);

		if (PCI_HDRTYPE_TYPE(bhlc) > 1)	    // Unsupported or no device
			continue;

		totaldev++;

		for (f.func = 0; f.func < (PCI_HDRTYPE_MULTIFN(bhlc) ? 8 : 1);
		     f.func++) {
			struct pci_dev af = f;
			u32 intr;

			af.dev_id = pci_conf_read(&f, PCI_ID_REG, 3);
			if (PCI_VENDOR(af.dev_id) == 0xffff)
				continue;

			intr = pci_conf_read(&af, PCI_INTERRUPT_REG, 3);
			af.irq_line = PCI_INTERRUPT_LINE(intr);

			af.dev_class = pci_conf_read(&af, PCI_CLASS_REG, 3);
			if (pci_show_devs)
				pci_print_func(&af);
			pci_attach(&af);
		}
	}
	//pr_debug("pci_scan_bus exit bus %p\n", bus);

	return totaldev;
}

static int pci_bridge_attach(struct pci_dev *pcif)
{
	u32 ioreg  = pci_conf_read(pcif, PCI_BRIDGE_STATIO_REG, 3);
	u32 busreg = pci_conf_read(pcif, PCI_BRIDGE_BUS_REG, 3);
	struct pci_bus nbus;

	if (PCI_BRIDGE_IO_32BITS(ioreg)) {
		pr_debug("PCI: %02x:%02Lx.%d: 32-bit bridge IO not supported.\n",
			pcif->bus->number, pcif->dev, pcif->func);
		return 0;
	}

	memset(&nbus, 0, sizeof(nbus));
	nbus.parent = pcif;
	nbus.number = (busreg >> PCI_BRIDGE_BUS_SECONDARY_SHIFT) & 0xff;

	if (pci_show_devs)
		pr_debug("PCI: %02x:%02Lx.%d: bridge to PCI bus %d--%d\n",
			pcif->bus->number, pcif->dev, pcif->func,
			nbus.number,
			(busreg >> PCI_BRIDGE_BUS_SUBORDINATE_SHIFT) & 0xff);

	pci_scan_bus(&nbus);
	return 1;
}

void pci_func_enable(struct pci_dev *f)
{
	u32 bar_width;
	u32 bar;

	pci_conf_write(f, PCI_COMMAND_STATUS_REG,
		       PCI_COMMAND_IO_ENABLE |
		       PCI_COMMAND_MEM_ENABLE |
		       PCI_COMMAND_MASTER_ENABLE, 3);

	for (bar = PCI_MAPREG_START; bar < PCI_MAPREG_END;
	     bar += bar_width)
	{
		int regnum;
		u32 rv;
		u32 base, size;
		u32 oldv = pci_conf_read(f, bar, 3);

		bar_width = 4;
		pci_conf_write(f, bar, 0xffffffff, 3);
		rv = pci_conf_read(f, bar, 3);

		if (rv == 0)
			continue;

		regnum = PCI_MAPREG_NUM(bar);
		if (PCI_MAPREG_TYPE(rv) == PCI_MAPREG_TYPE_MEM) {
			if (PCI_MAPREG_MEM_TYPE(rv) == PCI_MAPREG_MEM_TYPE_64BIT)
				bar_width = 8;

			size = PCI_MAPREG_MEM_SIZE(rv);
			base = PCI_MAPREG_MEM_ADDR(oldv);
			if (pci_show_addrs)
				pr_debug("  mem region %d: %d bytes at 0x%x\n",
					regnum, size, base);
		} else {
			size = PCI_MAPREG_IO_SIZE(rv);
			base = PCI_MAPREG_IO_ADDR(oldv);
			if (pci_show_addrs)
				pr_debug("  io region %d: %d bytes at 0x%x\n",
					regnum, size, base);
		}

		pci_conf_write(f, bar, oldv, 3);
		f->reg_base[regnum] = base;
		f->reg_size[regnum] = size;

		if (size && !base)
			pr_debug("PCI device %02x:%02Lx.%d (%04x:%04x) "
				"may be misconfigured: "
				"region %d: base 0x%x, size %d\n",
				f->bus->number, f->dev, f->func,
				PCI_VENDOR(f->dev_id), PCI_PRODUCT(f->dev_id),
				regnum, base, size);
	}

	pr_debug("PCI function %02x:%02Lx.%d (%04x:%04x) enabled\n",
		f->bus->number, f->dev, f->func,
		PCI_VENDOR(f->dev_id), PCI_PRODUCT(f->dev_id));
}

int pci_init(void)
{
	int ret;
	static struct pci_bus root_bus;
	memset(&root_bus, 0, sizeof(root_bus));

	ret = pci_scan_bus(&root_bus);

	pr_debug("done pci_init\n");
	return ret;
}

