#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/initrd.h>
#include <linux/tty.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/root_dev.h>
#include <linux/cpu.h>
#include <linux/console.h>
#include <linux/lmb.h>

#include <asm/io.h>
#include <asm/prom.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include <asm/elf.h>
#include <asm/cputable.h>
#include <asm/bootx.h>
#include <asm/btext.h>
#include <asm/machdep.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/pmac_feature.h>
#include <asm/sections.h>
#include <asm/nvram.h>
#include <asm/xmon.h>
#include <asm/time.h>
#include <asm/serial.h>
#include <asm/udbg.h>
#include <asm/mmu_context.h>
#include <asm/swiotlb.h>

#include "setup.h"

#ifdef  MY_ABC_HERE
extern char gszSynoHWVersion[];
#endif

#ifdef MY_ABC_HERE
extern long g_internal_hd_num;
#endif

#ifdef MY_ABC_HERE
extern long g_internal_netif_num;
#endif

#ifdef MY_ABC_HERE
extern long g_hdd_hotplug;
#endif

#ifdef MY_ABC_HERE
extern char gszDiskIdxMap[16];
#endif

#ifdef MY_ABC_HERE
extern char giDiskSeqReverse[8];
#endif

#ifdef MY_ABC_HERE
extern int gSynoHasDynModule;
#endif

#ifdef MY_ABC_HERE
extern unsigned char grgbLanMac[4][16];
#endif

#ifdef MY_ABC_HERE
extern char gszSerialNum[32];
extern char gszCustomSerialNum[32];
#endif

#ifdef MY_ABC_HERE
extern long g_sata_led_special;
#endif

#ifdef MY_ABC_HERE
extern int gSynoFactoryUSBFastReset;
#endif

#ifdef MY_ABC_HERE
extern int gSynoFactoryUSB3Disable;
#endif

#define DBG(fmt...)

extern void bootx_init(unsigned long r4, unsigned long phys);

int boot_cpuid;
EXPORT_SYMBOL_GPL(boot_cpuid);
int boot_cpuid_phys;

int smp_hw_index[NR_CPUS];

unsigned long ISA_DMA_THRESHOLD;
unsigned int DMA_MODE_READ;
unsigned int DMA_MODE_WRITE;

#ifdef CONFIG_VGA_CONSOLE
unsigned long vgacon_remap_base;
EXPORT_SYMBOL(vgacon_remap_base);
#endif

int dcache_bsize;
int icache_bsize;
int ucache_bsize;

notrace unsigned long __init early_init(unsigned long dt_ptr)
{
	unsigned long offset = reloc_offset();
	struct cpu_spec *spec;

	memset_io((void __iomem *)PTRRELOC(&__bss_start), 0,
			__bss_stop - __bss_start);

	spec = identify_cpu(offset, mfspr(SPRN_PVR));

	do_feature_fixups(spec->cpu_features,
			  PTRRELOC(&__start___ftr_fixup),
			  PTRRELOC(&__stop___ftr_fixup));

	do_feature_fixups(spec->mmu_features,
			  PTRRELOC(&__start___mmu_ftr_fixup),
			  PTRRELOC(&__stop___mmu_ftr_fixup));

	do_lwsync_fixups(spec->cpu_features,
			 PTRRELOC(&__start___lwsync_fixup),
			 PTRRELOC(&__stop___lwsync_fixup));

	return KERNELBASE + offset;
}

notrace void __init machine_init(unsigned long dt_ptr)
{
	lockdep_init();

	udbg_early_init();

	early_init_devtree(__va(dt_ptr));

	probe_machine();

	setup_kdump_trampoline();

#ifdef CONFIG_6xx
	if (cpu_has_feature(CPU_FTR_CAN_DOZE) ||
	    cpu_has_feature(CPU_FTR_CAN_NAP))
		ppc_md.power_save = ppc6xx_idle;
#endif

#ifdef CONFIG_E500
	if (cpu_has_feature(CPU_FTR_CAN_DOZE) ||
	    cpu_has_feature(CPU_FTR_CAN_NAP))
		ppc_md.power_save = e500_idle;
#endif
	if (ppc_md.progress)
		ppc_md.progress("id mach(): done", 0x200);
}

#ifdef CONFIG_BOOKE_WDT
 
notrace int __init early_parse_wdt(char *p)
{
	if (p && strncmp(p, "0", 1) != 0)
	       booke_wdt_enabled = 1;

	return 0;
}
early_param("wdt", early_parse_wdt);

int __init early_parse_wdt_period (char *p)
{
	if (p)
		booke_wdt_period = simple_strtoul(p, NULL, 0);

	return 0;
}
early_param("wdt_period", early_parse_wdt_period);
#endif	 

int __init ppc_setup_l2cr(char *str)
{
	if (cpu_has_feature(CPU_FTR_L2CR)) {
		unsigned long val = simple_strtoul(str, NULL, 0);
		printk(KERN_INFO "l2cr set to %lx\n", val);
		_set_L2CR(0);		 
		_set_L2CR(val);		 
	}
	return 1;
}
__setup("l2cr=", ppc_setup_l2cr);

#ifdef MY_ABC_HERE
static int __init early_is_dyn_module(char *p)
{
	int iLen = 0;

	gSynoHasDynModule = 0;

	if ((NULL == p) || (0 == (iLen = strlen(p)))) {
		goto END;
	}

	if ( 0 == strcmp (p, "y")) {
		gSynoHasDynModule = 1;
		printk("Synology Dynamic Module support.\n");
	}

END:
	return 1;
}
__setup("syno_dyn_module=", early_is_dyn_module);
#endif

#ifdef MY_ABC_HERE
static int __init early_sataled_special(char *p)
{
	g_sata_led_special = simple_strtol(p, NULL, 10);

	if ( g_sata_led_special >= 0 ) {
		printk("Special Sata LEDs.\n");
	}

	return 1;
}
__setup("SataLedSpecial=", early_sataled_special);
#endif

#ifdef MY_ABC_HERE
static int __init early_mac1(char *p)
{
	snprintf(grgbLanMac[0], sizeof(grgbLanMac[0]), "%s", p);

	printk("Mac1: %s\n", grgbLanMac[0]);

	return 1;
}
__setup("mac1=", early_mac1);

static int __init early_mac2(char *p)
{
	snprintf(grgbLanMac[1], sizeof(grgbLanMac[1]), "%s", p);

	printk("Mac2: %s\n", grgbLanMac[1]);

	return 1;
}
__setup("mac2=", early_mac2);

static int __init early_mac3(char *p)
{
	snprintf(grgbLanMac[2], sizeof(grgbLanMac[2]), "%s", p);

	printk("Mac3: %s\n", grgbLanMac[2]);

	return 1;
}
__setup("mac3=", early_mac3);

static int __init early_mac4(char *p)
{
	snprintf(grgbLanMac[3], sizeof(grgbLanMac[3]), "%s", p);

	printk("Mac4: %s\n", grgbLanMac[3]);

	return 1;
}
__setup("mac4=", early_mac4);
#endif

#ifdef MY_ABC_HERE
static int __init early_sn(char *p)
{
        snprintf(gszSerialNum, sizeof(gszSerialNum), "%s", p);
        printk("Serial Number: %s\n", gszSerialNum);
        return 1;
}
__setup("sn=", early_sn);

static int __init early_custom_sn(char *p)
{
        snprintf(gszCustomSerialNum, sizeof(gszCustomSerialNum), "%s", p);
        printk("Custom Serial Number: %s\n", gszCustomSerialNum);
        return 1;
}
__setup("custom_sn=", early_custom_sn);
#endif

#ifdef MY_ABC_HERE
static int __init early_hw_version(char *p)
{
	char *szPtr;

	snprintf(gszSynoHWVersion, 16, "%s", p);

	szPtr = gszSynoHWVersion;
	while ((*szPtr != ' ') && (*szPtr != '\t') && (*szPtr != '\0')) {
		szPtr++;
	}
	*szPtr = 0;
	strcat(szPtr,"-j");

	printk("Synology Hardware Version: %s\n", gszSynoHWVersion);

	return 1;
}
__setup("syno_hw_version=", early_hw_version);
#endif

#ifdef MY_ABC_HERE
static int __init early_internal_hd_num(char *p)
{
	g_internal_hd_num = simple_strtol(p, NULL, 10);

	printk("Internal HD num: %d\n", (int)g_internal_hd_num);

	return 1;
}
__setup("ihd_num=", early_internal_hd_num);
#endif

#ifdef  MY_ABC_HERE
static int __init early_internal_netif_num(char *p)
{
	g_internal_netif_num = simple_strtol(p, NULL, 10);

	if ( g_internal_netif_num >= 0 ) {
		printk("Internal netif num: %d\n", (int)g_internal_netif_num);
	}

	return 1;
}
__setup("netif_num=", early_internal_netif_num);
#endif

#ifdef MY_ABC_HERE
static int __init early_hdd_hotplug(char *p)
{
	g_hdd_hotplug = simple_strtol(p, NULL, 10);

	if ( g_hdd_hotplug > 0 ) {
		printk("Support HDD Hotplug.\n");
	}

	return 1;
}
__setup("HddHotplug=", early_hdd_hotplug);
#endif

#ifdef MY_ABC_HERE
static int __init early_disk_idx_map(char *p)
{
	snprintf(gszDiskIdxMap, sizeof(gszDiskIdxMap), "%s", p);

	if('\0' != gszDiskIdxMap[0]) {
		printk("Disk Index Map: %s\n", gszDiskIdxMap);
	}

	return 1;
}
__setup("DiskIdxMap=", early_disk_idx_map);
#endif

#ifdef MY_ABC_HERE
static int __init early_disk_seq_reserve(char *p)
{
	snprintf(giDiskSeqReverse, sizeof(giDiskSeqReverse), "%s", p);

	if('\0' != giDiskSeqReverse[0]) {
		printk("Disk Sequence Reverse: %s\n", giDiskSeqReverse);
	}

	return 1;
}
__setup("DiskSeqReverse=", early_disk_seq_reserve);
#endif

int __init ppc_setup_l3cr(char *str)
{
	if (cpu_has_feature(CPU_FTR_L3CR)) {
		unsigned long val = simple_strtoul(str, NULL, 0);
		printk(KERN_INFO "l3cr set to %lx\n", val);
		_set_L3CR(val);		 
	}
	return 1;
}
__setup("l3cr=", ppc_setup_l3cr);

#ifdef MY_ABC_HERE
static int __init early_factory_usb_fast_reset(char *p)
{
	gSynoFactoryUSBFastReset = simple_strtol(p, NULL, 10);

	printk("Factory USB Fast Reset: %d\n", (int)gSynoFactoryUSBFastReset);

	return 1;
}
__setup("syno_usb_fast_reset=", early_factory_usb_fast_reset);
#endif

#ifdef MY_ABC_HERE
static int __init early_factory_usb3_disable(char *p)
{
	gSynoFactoryUSB3Disable = simple_strtol(p, NULL, 10);

	printk("Factory USB3 Disable: %d\n", (int)gSynoFactoryUSB3Disable);

	return 1;
}
__setup("syno_disable_usb3=", early_factory_usb3_disable);
#endif

#ifdef CONFIG_GENERIC_NVRAM

unsigned char nvram_read_byte(int addr)
{
	if (ppc_md.nvram_read_val)
		return ppc_md.nvram_read_val(addr);
	return 0xff;
}
EXPORT_SYMBOL(nvram_read_byte);

void nvram_write_byte(unsigned char val, int addr)
{
	if (ppc_md.nvram_write_val)
		ppc_md.nvram_write_val(addr, val);
}
EXPORT_SYMBOL(nvram_write_byte);

ssize_t nvram_get_size(void)
{
	if (ppc_md.nvram_size)
		return ppc_md.nvram_size();
	return -1;
}
EXPORT_SYMBOL(nvram_get_size);

void nvram_sync(void)
{
	if (ppc_md.nvram_sync)
		ppc_md.nvram_sync();
}
EXPORT_SYMBOL(nvram_sync);

#endif  

int __init ppc_init(void)
{
	 
	if (ppc_md.progress)
		ppc_md.progress("             ", 0xffff);

	if (ppc_md.init != NULL) {
		ppc_md.init();
	}
	return 0;
}

arch_initcall(ppc_init);

#ifdef CONFIG_IRQSTACKS
static void __init irqstack_early_init(void)
{
	unsigned int i;

	for_each_possible_cpu(i) {
		softirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
		hardirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
	}
}
#else
#define irqstack_early_init()
#endif

#if defined(CONFIG_BOOKE) || defined(CONFIG_40x)
static void __init exc_lvl_early_init(void)
{
	unsigned int i;

	for_each_possible_cpu(i) {
		critirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
#ifdef CONFIG_BOOKE
		dbgirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
		mcheckirq_ctx[i] = (struct thread_info *)
			__va(lmb_alloc(THREAD_SIZE, THREAD_SIZE));
#endif
	}
}
#else
#define exc_lvl_early_init()
#endif

void __init setup_arch(char **cmdline_p)
{
	*cmdline_p = cmd_line;

	loops_per_jiffy = 500000000 / HZ;

	unflatten_device_tree();
#ifdef CONFIG_SYNO_MPC85XX_COMMON
{
	extern void cam_mapin_extra_chip_select(void);
	cam_mapin_extra_chip_select();
}
#endif
	check_for_initrd();

	if (ppc_md.init_early)
		ppc_md.init_early();

	find_legacy_serial_ports();

	smp_setup_cpu_maps();

	register_early_udbg_console();

	xmon_setup();

	dcache_bsize = cur_cpu_spec->dcache_bsize;
	icache_bsize = cur_cpu_spec->icache_bsize;
	ucache_bsize = 0;
	if (cpu_has_feature(CPU_FTR_UNIFIED_ID_CACHE))
		ucache_bsize = icache_bsize = dcache_bsize;

	panic_timeout = 180;

	if (ppc_md.panic)
		setup_panic();

	init_mm.start_code = (unsigned long)_stext;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = klimit;

	exc_lvl_early_init();

	irqstack_early_init();

	do_init_bootmem();
	if ( ppc_md.progress ) ppc_md.progress("setup_arch: bootmem", 0x3eab);

#ifdef CONFIG_DUMMY_CONSOLE
	conswitchp = &dummy_con;
#endif

	if (ppc_md.setup_arch)
		ppc_md.setup_arch();
	if ( ppc_md.progress ) ppc_md.progress("arch: exit", 0x3eab);

#ifdef CONFIG_SWIOTLB
	if (ppc_swiotlb_enable)
		swiotlb_init();
#endif

	paging_init();

	mmu_context_init();

}

#ifdef CONFIG_SYNO_QORIQ
void cpu_die(void)
{
	if (ppc_md.cpu_die)
		ppc_md.cpu_die();
}
#endif
