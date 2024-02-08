 
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/serial.h>
#include <linux/serial_core.h>
#include <linux/serial_8250.h>
#include <linux/io.h>
#include <linux/spi/spi.h>
#include <linux/spi/flash.h>
#include <asm/sizes.h>
#include <asm/setup.h>
#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/hardware/gic.h>
#include <mach/hardware.h>
#include <mach/dma.h>
#include <mach/rps-irq.h>
#ifdef CONFIG_SYNO_PLX_PORTING
#include <linux/mtd/physmap.h>
#endif

#ifdef CONFIG_LEON_START_EARLY
#include <mach/leon.h>
#include <mach/leon-early-prog.h>
#endif  

#ifdef CONFIG_OXNAS_SATA_POWER_GPIO_1
#if (CONFIG_OXNAS_SATA_POWER_GPIO_1 < SYS_CTRL_NUM_PINS)
#define SATA_POWER_1_NUM            CONFIG_OXNAS_SATA_POWER_GPIO_1
#define SATA_POWER_1_PRISEL_REG     SYS_CTRL_GPIO_PRIMSEL_CTRL_0
#define SATA_POWER_1_SECSEL_REG     SYS_CTRL_GPIO_SECSEL_CTRL_0
#define SATA_POWER_1_TERSEL_REG     SYS_CTRL_GPIO_TERTSEL_CTRL_0
#define SATA_POWER_1_SET_OE_REG     GPIO_A_OUTPUT_ENABLE_SET
#define SATA_POWER_1_OUTPUT_SET_REG GPIO_A_OUTPUT_SET
#define SATA_POWER_1_OUTPUT_CLR_REG GPIO_A_OUTPUT_CLEAR
#else
#define SATA_POWER_1_NUM            ((CONFIG_OXNAS_SATA_POWER_GPIO_1) - SYS_CTRL_NUM_PINS)
#define SATA_POWER_1_PRISEL_REG     SYS_CTRL_GPIO_PRIMSEL_CTRL_1
#define SATA_POWER_1_SECSEL_REG     SYS_CTRL_GPIO_SECSEL_CTRL_1
#define SATA_POWER_1_TERSEL_REG     SYS_CTRL_GPIO_TERTSEL_CTRL_1
#define SATA_POWER_1_SET_OE_REG     GPIO_B_OUTPUT_ENABLE_SET
#define SATA_POWER_1_OUTPUT_SET_REG GPIO_B_OUTPUT_SET
#define SATA_POWER_1_OUTPUT_CLR_REG GPIO_B_OUTPUT_CLEAR
#endif

#define SATA_POWER_1_MASK   (1UL << (SATA_POWER_1_NUM))
#endif  

#ifdef CONFIG_OXNAS_SATA_POWER_GPIO_2
#if (CONFIG_OXNAS_SATA_POWER_GPIO_2 < SYS_CTRL_NUM_PINS)
#define SATA_POWER_2_NUM            CONFIG_OXNAS_SATA_POWER_GPIO_2
#define SATA_POWER_2_PRISEL_REG     SYS_CTRL_GPIO_PRIMSEL_CTRL_0
#define SATA_POWER_2_SECSEL_REG     SYS_CTRL_GPIO_SECSEL_CTRL_0
#define SATA_POWER_2_TERSEL_REG     SYS_CTRL_GPIO_TERTSEL_CTRL_0
#define SATA_POWER_2_SET_OE_REG     GPIO_A_OUTPUT_ENABLE_SET
#define SATA_POWER_2_OUTPUT_SET_REG GPIO_A_OUTPUT_SET
#define SATA_POWER_2_OUTPUT_CLR_REG GPIO_A_OUTPUT_CLEAR
#else
#define SATA_POWER_2_NUM            ((CONFIG_OXNAS_SATA_POWER_GPIO_2) - SYS_CTRL_NUM_PINS)
#define SATA_POWER_2_PRISEL_REG     SYS_CTRL_GPIO_PRIMSEL_CTRL_1
#define SATA_POWER_2_SECSEL_REG     SYS_CTRL_GPIO_SECSEL_CTRL_1
#define SATA_POWER_2_TERSEL_REG     SYS_CTRL_GPIO_TERTSEL_CTRL_1
#define SATA_POWER_2_SET_OE_REG     GPIO_B_OUTPUT_ENABLE_SET
#define SATA_POWER_2_OUTPUT_SET_REG GPIO_B_OUTPUT_SET
#define SATA_POWER_2_OUTPUT_CLR_REG GPIO_B_OUTPUT_CLEAR
#endif

#define SATA_POWER_2_MASK   (1UL << (SATA_POWER_2_NUM))
#endif  

#ifdef CONFIG_OXNAS_USB_HUB_RESET_GPIO
#if (CONFIG_OXNAS_USB_HUB_RESET_GPIO < SYS_CTRL_NUM_PINS)
#define USB_HUB_RESET_NUM            CONFIG_OXNAS_USB_HUB_RESET_GPIO
#define USB_HUB_RESET_PRISEL_REG     SYS_CTRL_GPIO_PRIMSEL_CTRL_0
#define USB_HUB_RESET_SECSEL_REG     SYS_CTRL_GPIO_SECSEL_CTRL_0
#define USB_HUB_RESET_TERSEL_REG     SYS_CTRL_GPIO_TERTSEL_CTRL_0
#define USB_HUB_RESET_SET_OE_REG     GPIO_A_OUTPUT_ENABLE_SET
#define USB_HUB_RESET_OUTPUT_SET_REG GPIO_A_OUTPUT_SET
#define USB_HUB_RESET_OUTPUT_CLR_REG GPIO_A_OUTPUT_CLEAR
#else
#define USB_HUB_RESET_NUM            ((CONFIG_OXNAS_USB_HUB_RESET_GPIO) - SYS_CTRL_NUM_PINS)
#define USB_HUB_RESET_PRISEL_REG     SYS_CTRL_GPIO_PRIMSEL_CTRL_1
#define USB_HUB_RESET_SECSEL_REG     SYS_CTRL_GPIO_SECSEL_CTRL_1
#define USB_HUB_RESET_TERSEL_REG     SYS_CTRL_GPIO_TERTSEL_CTRL_1
#define USB_HUB_RESET_SET_OE_REG     GPIO_B_OUTPUT_ENABLE_SET
#define USB_HUB_RESET_OUTPUT_SET_REG GPIO_B_OUTPUT_SET
#define USB_HUB_RESET_OUTPUT_CLR_REG GPIO_B_OUTPUT_CLEAR
#endif

#define USB_HUB_RESET_MASK	(1UL << (USB_HUB_RESET_NUM))
#endif  

extern struct sys_timer oxnas_timer;

spinlock_t oxnas_gpio_spinlock;
EXPORT_SYMBOL(oxnas_gpio_spinlock);

int oxnas_global_invert_leds = 0;
#include <linux/module.h>
EXPORT_SYMBOL(oxnas_global_invert_leds);

static struct map_desc oxnas_io_desc[] __initdata = {
    { USBHOST_BASE,         __phys_to_pfn(USBHOST_BASE_PA),         SZ_2M,  MT_DEVICE },
    { ETHA_BASE,            __phys_to_pfn(ETHA_BASE_PA),            SZ_2M,  MT_DEVICE },
    { ETHB_BASE,            __phys_to_pfn(ETHB_BASE_PA),            SZ_2M,  MT_DEVICE },
    { USBDEV_BASE,          __phys_to_pfn(USBDEV_BASE_PA),          SZ_2M,  MT_DEVICE },
    { STATIC_CS0_BASE,      __phys_to_pfn(STATIC_CS0_BASE_PA),      SZ_4M,  MT_DEVICE },
    { STATIC_CS1_BASE,      __phys_to_pfn(STATIC_CS1_BASE_PA),      SZ_4M,  MT_DEVICE },
    { STATIC_CONTROL_BASE,  __phys_to_pfn(STATIC_CONTROL_BASE_PA),  SZ_4K,  MT_DEVICE },
    { CIPHER_BASE,          __phys_to_pfn(CIPHER_BASE_PA),          SZ_2M,  MT_DEVICE },
    { GPIO_A_BASE,          __phys_to_pfn(GPIO_A_BASE_PA),          SZ_4K,  MT_DEVICE },
    { GPIO_B_BASE,          __phys_to_pfn(GPIO_B_BASE_PA),          SZ_4K,  MT_DEVICE },
    { UART_1_BASE,          __phys_to_pfn(UART_1_BASE_PA),          SZ_16,  MT_DEVICE },
    { UART_2_BASE,          __phys_to_pfn(UART_2_BASE_PA),          SZ_16,  MT_DEVICE },
    { RPSA_BASE,            __phys_to_pfn(RPSA_BASE_PA),            SZ_1K,  MT_DEVICE },
    { RPSC_BASE,            __phys_to_pfn(RPSC_BASE_PA),            SZ_1K,  MT_DEVICE },
    { FAN_MON_BASE,         __phys_to_pfn(FAN_MON_BASE_PA),         SZ_1M,  MT_DEVICE },
    { DDR_REGS_BASE,        __phys_to_pfn(DDR_REGS_BASE_PA),        SZ_1M,  MT_DEVICE },
    { IRRX_BASE,            __phys_to_pfn(IRRX_BASE_PA),            SZ_1M,  MT_DEVICE },
    { SATA_PHY_BASE,        __phys_to_pfn(SATA_PHY_BASE_PA),        SZ_1M,  MT_DEVICE },
    { PCIE_PHY,             __phys_to_pfn(PCIE_PHY_PA),             SZ_1M,  MT_DEVICE },
    { AHB_MON_BASE,         __phys_to_pfn(AHB_MON_BASE_PA),         SZ_1M,  MT_DEVICE },
    { SYS_CONTROL_BASE,     __phys_to_pfn(SYS_CONTROL_BASE_PA),     SZ_1M,  MT_DEVICE },
    { SEC_CONTROL_BASE,     __phys_to_pfn(SEC_CONTROL_BASE_PA),     SZ_1M,  MT_DEVICE },
    { SD_REG_BASE,          __phys_to_pfn(SD_REG_BASE_PA),          SZ_1M,  MT_DEVICE },
    { AUDIO_BASE,           __phys_to_pfn(AUDIO_BASE_PA),           SZ_1M,  MT_DEVICE },
    { DMA_BASE,             __phys_to_pfn(DMA_BASE_PA),             SZ_1M,  MT_DEVICE },
    { CIPHER_REG_BASE,      __phys_to_pfn(CIPHER_REG_BASE_PA),      SZ_1M,  MT_DEVICE },
    { SATA_REG_BASE,        __phys_to_pfn(SATA_REG_BASE_PA),        SZ_1M,  MT_DEVICE },
    { COPRO_REGS_BASE,      __phys_to_pfn(COPRO_REGS_BASE_PA),      SZ_1M,  MT_DEVICE },
    { PERIPH_BASE,          __phys_to_pfn(PERIPH_BASE_PA),          SZ_8K,  MT_DEVICE },
    { PCIEA_DBI_BASE,       __phys_to_pfn(PCIEA_DBI_BASE_PA),       SZ_1M,  MT_DEVICE },
    { PCIEA_ELBI_BASE,      __phys_to_pfn(PCIEA_ELBI_BASE_PA),      SZ_1M,  MT_DEVICE },
    { PCIEB_DBI_BASE,       __phys_to_pfn(PCIEB_DBI_BASE_PA),       SZ_1M,  MT_DEVICE },
    { PCIEB_ELBI_BASE,      __phys_to_pfn(PCIEB_ELBI_BASE_PA),      SZ_1M,  MT_DEVICE },
    { PCIEA_CLIENT_BASE,	__phys_to_pfn(PCIEA_CLIENT_BASE_PA),	SZ_64M,	MT_DEVICE },
    { PCIEB_CLIENT_BASE,	__phys_to_pfn(PCIEB_CLIENT_BASE_PA),	SZ_64M,	MT_DEVICE }

#ifdef CONFIG_SUPPORT_LEON
	 
#if (CONFIG_LEON_PAGES == 1)
   ,{ LEON_IMAGE_BASE,			__phys_to_pfn(LEON_IMAGE_BASE_PA),			SZ_4K, MT_DEVICE }
#elif (CONFIG_LEON_PAGES == 2)
   ,{ LEON_IMAGE_BASE,			__phys_to_pfn(LEON_IMAGE_BASE_PA),			SZ_8K, MT_DEVICE }
#elif (CONFIG_LEON_PAGES == 3)
   ,{ LEON_IMAGE_BASE,		    __phys_to_pfn(LEON_IMAGE_BASE_PA),			SZ_8K, MT_DEVICE }
   ,{ LEON_IMAGE_BASE+0x2000,	__phys_to_pfn(LEON_IMAGE_BASE_PA+0x2000),	SZ_4K, MT_DEVICE }
#elif (CONFIG_LEON_PAGES == 4)
   ,{ LEON_IMAGE_BASE,		    __phys_to_pfn(LEON_IMAGE_BASE_PA),	  		SZ_8K, MT_DEVICE }
   ,{ LEON_IMAGE_BASE+0x2000,	__phys_to_pfn(LEON_IMAGE_BASE_PA+0x2000),	SZ_8K, MT_DEVICE }
#elif (CONFIG_LEON_PAGES == 5)
   ,{ LEON_IMAGE_BASE,		    __phys_to_pfn(LEON_IMAGE_BASE_PA),	  		SZ_16K, MT_DEVICE }
   ,{ LEON_IMAGE_BASE+0x4000,	__phys_to_pfn(LEON_IMAGE_BASE_PA+0x4000),	SZ_4K,  MT_DEVICE }
#elif (CONFIG_LEON_PAGES == 6)
   ,{ LEON_IMAGE_BASE,		    __phys_to_pfn(LEON_IMAGE_BASE_PA),	  		SZ_16K, MT_DEVICE }
   ,{ LEON_IMAGE_BASE+0x4000,	__phys_to_pfn(LEON_IMAGE_BASE_PA+0x4000),	SZ_8K,  MT_DEVICE }
#else
#error "Unsupported number of Leon code pages"
#endif  
#endif  
	 
   ,{ SRAM_BASE,		__phys_to_pfn(SRAM_PA),			SZ_16K,	MT_DEVICE }
   ,{ SRAM_BASE+0x4000,	__phys_to_pfn(SRAM_PA+0x4000),	SZ_16K,	MT_DEVICE }
   ,{ SRAM_BASE+0x8000,	__phys_to_pfn(SRAM_PA+0x8000),	SZ_8K,	MT_DEVICE }
};

static struct resource usb_resources[] = {
	[0] = {
		.start		= USBHOST_BASE_PA,
		.end		= USBHOST_BASE_PA + 0x10000 - 1,
		.flags		= IORESOURCE_MEM,
	},
	[1] = {
		.start		= USBHOST_INTERRUPT,
		.end		= USBHOST_INTERRUPT,
		.flags		= IORESOURCE_IRQ,
	},
};

static u64 usb_dmamask = ~(u32)0;
#ifdef CONFIG_SPI

#ifdef CONFIG_SYNO_PLX_PORTING
static struct mtd_partition syno_ox820_partitions[] = {
	{
		.name   = "RedBoot",             
		.offset = 0x00010000,
		.size   = 0x00020000,            
	},
	{
		.name   = "zImage",                      
		.offset = 0x00030000,
		.size   = 0x00240000,            
	},
	{
		.name   = "rd.gz",                       
		.offset = 0x00270000,
		.size   = 0x00170000,            
	},
	{
		.name   = "vendor",                      
		.offset = 0x003E0000,
		.size   = 0x00010000,            
	},
	{
		.name   = "RedBoot Config",      
		.offset = 0x00000000,
		.size   = 0x00010000,            
	},
	{
		.name   = "FIS directory",       
		.offset = 0x003F0000,
		.size   = 0x00010000,            
	},
};
#endif
static const struct flash_platform_data ox820_spi_slave_data = {
#ifdef CONFIG_SYNO_PLX_PORTING
	.name		= "spi_flash",
	.parts		= syno_ox820_partitions,
	.nr_parts	= ARRAY_SIZE(syno_ox820_partitions),
#endif
};

static struct spi_board_info ox820_spi_board_info[] __initdata = {
	{
		.modalias	= "m25p80",
		.bus_num	= 0,
		.chip_select	= 0,
		.irq		= -1,
		.max_speed_hz	= 10000000,
		.platform_data	= &ox820_spi_slave_data, 
	},
};

 ;

static struct platform_device ox820_spi = {
	.name		= "spi_ox820_gpio",
	.id		= 0,
	 
	.dev		= {
		 
	},
 
};

#endif

static struct platform_device usb_host = {
	.name		= "oxnas-ehci",
	.id		= 0,
	.dev = {
		.dma_mask		= &usb_dmamask,
		.coherent_dma_mask	= 0xffffffff,
	},
	.num_resources	= ARRAY_SIZE(usb_resources),
	.resource	= usb_resources,
};

static struct resource gadget_resources[] = {
	[0] = {
		.start		= USBDEV_BASE_PA,
		.end		= USBDEV_BASE_PA + 0x100000 - 1,
		.flags		= IORESOURCE_MEM,
	},
	[1] = {
		.start		= USBDEV_INTERRUPT,
		.end		= USBDEV_INTERRUPT,
		.flags		= IORESOURCE_IRQ,
	},
};
static struct platform_device usb_device = {
	.name		= "plx_usb_gadget",
	.id		= 1,
	.num_resources	= ARRAY_SIZE(gadget_resources),
	.resource	= gadget_resources,
};

static struct platform_device *platform_devices[] __initdata = {
	&usb_host,
	&usb_device,
#ifdef CONFIG_SPI	
	&ox820_spi,
#endif
};

void __iomem *gic_cpu_base_addr;

#define STD_COM_FLAGS (ASYNC_BOOT_AUTOCONF | ASYNC_SKIP_TEST )

#define INT_UART_BASE_BAUD (CONFIG_NOMINAL_RPSCLK_FREQ)

#ifdef CONFIG_ARCH_OXNAS_UART1
static struct uart_port internal_serial_port_1 = {
	.membase	= (char *)(UART_1_BASE),
	.mapbase	= UART_1_BASE_PA,
	.irq		= UART_1_INTERRUPT,
	.flags		= STD_COM_FLAGS,
	.iotype		= UPIO_MEM,
	.regshift	= 0,
	.uartclk	= INT_UART_BASE_BAUD,
	.line		= 0,
	.type		= PORT_16550A,
	.fifosize	= 16
};
#endif  

#ifdef CONFIG_ARCH_OXNAS_UART2
static struct uart_port internal_serial_port_2 = {
	.membase	= (char *)(UART_2_BASE),
	.mapbase	= UART_2_BASE_PA,
	.irq		= UART_2_INTERRUPT,
	.flags		= STD_COM_FLAGS,
	.iotype		= UPIO_MEM,
	.regshift	= 0,
	.uartclk	= INT_UART_BASE_BAUD,
	.line		= 0,
	.type		= PORT_16550A,
	.fifosize	= 16
};
#endif  

static void __init oxnas_mapio(void)
{
    unsigned int uart_line=0;

    iotable_init(oxnas_io_desc, ARRAY_SIZE(oxnas_io_desc));

#ifdef CONFIG_ARCH_OXNAS_UART1
#if (CONFIG_ARCH_OXNAS_CONSOLE_UART != 1)
    {
		 
		unsigned long pins = (1UL << UART_A_SIN_GPIOA_PIN) |
						 	 (1UL << UART_A_SOUT_GPIOA_PIN);

        *(volatile unsigned long*)SYS_CTRL_SECONDARY_SEL   &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_TERTIARY_SEL    &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_QUATERNARY_SEL  &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_DEBUG_SEL       &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_ALTERNATIVE_SEL |=  pins;

		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_SET   |= (1UL << UART_A_SOUT_GPIOA_PIN);
	
		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_CLEAR |= (1UL << UART_A_SIN_GPIOA_PIN);
    }
#endif  

#ifdef CONFIG_ARCH_OXNAS_UART1_MODEM
    {
		 
		unsigned long pins = (1UL << UART_A_CTS_GPIOA_PIN) |
							 (1UL << UART_A_RTS_GPIOA_PIN);

        *(volatile unsigned long*)SYS_CTRL_SECONDARY_SEL   &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_TERTIARY_SEL    &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_QUATERNARY_SEL  &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_DEBUG_SEL       &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_ALTERNATIVE_SEL |=  pins;

		pins = (1UL << UART_A_RI_GPIOA_PIN) |
			   (1UL << UART_A_CD_GPIOA_PIN) |
			   (1UL << UART_A_DSR_GPIOA_PIN) |
			   (1UL << UART_A_DTR_GPIOA_PIN);

        *(volatile unsigned long*)SYS_CTRL_SECONDARY_SEL   &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_TERTIARY_SEL    &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_QUATERNARY_SEL  &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_DEBUG_SEL       |=  pins;
        *(volatile unsigned long*)SYS_CTRL_ALTERNATIVE_SEL &= ~pins;

		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_SET |= ((1UL << UART_A_RI_GPIOA_PIN) |
													 (1UL << UART_A_CD_GPIOA_PIN) |
													 (1UL << UART_A_DSR_GPIOA_PIN) |
													 (1UL << UART_A_CTS_GPIOA_PIN));

		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_CLEAR |= ((1UL << UART_A_DTR_GPIOA_PIN) |
													   (1UL << UART_A_RTS_GPIOA_PIN));
    }
#endif  

    internal_serial_port_1.line = uart_line++;
    early_serial_setup(&internal_serial_port_1);
#endif  

#ifdef CONFIG_ARCH_OXNAS_UART2
#if (CONFIG_ARCH_OXNAS_CONSOLE_UART != 2)
    {
		 
		unsigned long pins = (1UL << UART_B_SIN_GPIOA_PIN) |
							 (1UL << UART_B_SOUT_GPIOA_PIN);

#ifdef CONFIG_SYNO_PLX_PORTING
        *(volatile unsigned long*)SEC_CTRL_SECONDARY_SEL   &= ~pins;
        *(volatile unsigned long*)SEC_CTRL_TERTIARY_SEL    &= ~pins;
        *(volatile unsigned long*)SEC_CTRL_QUATERNARY_SEL  &= ~pins ;
        *(volatile unsigned long*)SEC_CTRL_DEBUG_SEL       &= ~pins;
        *(volatile unsigned long*)SEC_CTRL_ALTERNATIVE_SEL |= pins;
#else
        *(volatile unsigned long*)SYS_CTRL_SECONDARY_SEL   &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_TERTIARY_SEL    &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_QUATERNARY_SEL  &= ~pins ;
        *(volatile unsigned long*)SYS_CTRL_DEBUG_SEL       |=  pins;
        *(volatile unsigned long*)SYS_CTRL_ALTERNATIVE_SEL &= ~pins;
#endif

		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_SET   |= (1UL << UART_B_SOUT_GPIOA_PIN);

		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_CLEAR |= (1UL << UART_B_SIN_GPIOA_PIN);
    }
#endif  

#ifdef CONFIG_ARCH_OXNAS_UART2_MODEM
    {
		 
		unsigned long pins = (1UL << UART_B_CTS_GPIOA_PIN) |
							 (1UL << UART_B_RTS_GPIOA_PIN);

        *(volatile unsigned long*)SYS_CTRL_SECONDARY_SEL   &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_TERTIARY_SEL    &= ~pins;
        *(volatile unsigned long*)SYS_CTRL_QUATERNARY_SEL  &= ~pins ;
        *(volatile unsigned long*)SYS_CTRL_DEBUG_SEL       |=  pins;
        *(volatile unsigned long*)SYS_CTRL_ALTERNATIVE_SEL &= ~pins;

		pins = (1UL << UART_B_RI_GPIOB_PIN) |
			   (1UL << UART_B_CD_GPIOB_PIN) |
			   (1UL << UART_B_DSR_GPIOB_PIN) |
			   (1UL << UART_B_DTR_GPIOB_PIN);

        *(volatile unsigned long*)SEC_CTRL_SECONDARY_SEL   &= ~pins;
        *(volatile unsigned long*)SEC_CTRL_TERTIARY_SEL    &= ~pins;
        *(volatile unsigned long*)SEC_CTRL_QUATERNARY_SEL  &= ~pins ;
        *(volatile unsigned long*)SEC_CTRL_DEBUG_SEL       |=  pins;
        *(volatile unsigned long*)SEC_CTRL_ALTERNATIVE_SEL &= ~pins;

		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_SET |= (1UL << UART_B_CTS_GPIOA_PIN);

		*(volatile u32*)GPIO_B_OUTPUT_ENABLE_SET |= ((1UL << UART_B_RI_GPIOB_PIN) |
													 (1UL << UART_B_CD_GPIOB_PIN) |
													 (1UL << UART_B_DSR_GPIOB_PIN));

		*(volatile u32*)GPIO_A_OUTPUT_ENABLE_CLEAR |= (1UL << UART_B_RTS_GPIOA_PIN);

		*(volatile u32*)GPIO_B_OUTPUT_ENABLE_CLEAR |= (1UL << UART_B_DTR_GPIOB_PIN);
	}
#endif  

    internal_serial_port_2.line = uart_line++;
    early_serial_setup(&internal_serial_port_2);
#endif  

#ifdef CONFIG_OXNAS_SATA_POWER_1
     
    writel(readl(SATA_POWER_1_PRISEL_REG) & ~SATA_POWER_1_MASK, SATA_POWER_1_PRISEL_REG);
    writel(readl(SATA_POWER_1_SECSEL_REG) & ~SATA_POWER_1_MASK, SATA_POWER_1_SECSEL_REG);
    writel(readl(SATA_POWER_1_TERSEL_REG) & ~SATA_POWER_1_MASK, SATA_POWER_1_TERSEL_REG);

    writel(SATA_POWER_1_MASK, SATA_POWER_1_OUTPUT_SET_REG);

    writel(SATA_POWER_1_MASK, SATA_POWER_1_SET_OE_REG);
#endif  

#ifdef CONFIG_OXNAS_SATA_POWER_2
     
    writel(readl(SATA_POWER_2_PRISEL_REG) & ~SATA_POWER_2_MASK, SATA_POWER_2_PRISEL_REG);
    writel(readl(SATA_POWER_2_SECSEL_REG) & ~SATA_POWER_2_MASK, SATA_POWER_2_SECSEL_REG);
    writel(readl(SATA_POWER_2_TERSEL_REG) & ~SATA_POWER_2_MASK, SATA_POWER_2_TERSEL_REG);

    writel(SATA_POWER_2_MASK, SATA_POWER_2_OUTPUT_SET_REG);

    writel(SATA_POWER_2_MASK, SATA_POWER_2_SET_OE_REG);
#endif  

    {
        unsigned long pins = (1 << MACA_MDC_MF_PIN ) |
                             (1 << MACA_MDIO_MF_PIN) ;
        *(volatile u32*)SYS_CTRL_SECONDARY_SEL   |=  pins ;
        *(volatile u32*)SYS_CTRL_TERTIARY_SEL    &= ~pins ;
        *(volatile u32*)SYS_CTRL_QUATERNARY_SEL  &= ~pins ;
        *(volatile u32*)SYS_CTRL_DEBUG_SEL       &= ~pins ;
        *(volatile u32*)SYS_CTRL_ALTERNATIVE_SEL &= ~pins ;
	}

#ifdef	CONFIG_PCI
#if (CONFIG_OXNAS_PCIE_RESET_GPIO < SYS_CTRL_NUM_PINS)
#define PCIE_RESET_PIN		CONFIG_OXNAS_PCIE_RESET_GPIO
#define	PCIE_RESET_SECONDARY_SEL	SYS_CTRL_SECONDARY_SEL
#define	PCIE_RESET_TERTIARY_SEL	SYS_CTRL_TERTIARY_SEL
#define	PCIE_RESET_QUATERNARY_SEL	SYS_CTRL_QUATERNARY_SEL
#define	PCIE_RESET_DEBUG_SEL	SYS_CTRL_DEBUG_SEL
#define	PCIE_RESET_ALTERNATIVE_SEL	SYS_CTRL_ALTERNATIVE_SEL
#else
#define PCIE_RESET_PIN          (CONFIG_OXNAS_PCIE_RESET_GPIO - SYS_CTRL_NUM_PINS)
#define	PCIE_RESET_SECONDARY_SEL	SEC_CTRL_SECONDARY_SEL
#define	PCIE_RESET_TERTIARY_SEL	SEC_CTRL_TERTIARY_SEL
#define	PCIE_RESET_QUATERNARY_SEL	SEC_CTRL_QUATERNARY_SEL
#define	PCIE_RESET_DEBUG_SEL	SEC_CTRL_DEBUG_SEL
#define	PCIE_RESET_ALTERNATIVE_SEL	SEC_CTRL_ALTERNATIVE_SEL
#endif
    {
	 
	unsigned long pin = ( 1 << PCIE_RESET_PIN);
        *(volatile u32*)PCIE_RESET_SECONDARY_SEL   &= ~pin ;
        *(volatile u32*)PCIE_RESET_TERTIARY_SEL    &= ~pin ;
        *(volatile u32*)PCIE_RESET_QUATERNARY_SEL  &= ~pin ;
        *(volatile u32*)PCIE_RESET_DEBUG_SEL       &= ~pin ;
        *(volatile u32*)PCIE_RESET_ALTERNATIVE_SEL &= ~pin ;
    }
#endif  
}

static void __init oxnas_fixup(
    struct machine_desc *desc,
    struct tag *tags,
    char **cmdline,
    struct meminfo *mi)
{
    mi->nr_banks = 0;
    mi->bank[mi->nr_banks].start = SDRAM_PA;
    mi->bank[mi->nr_banks].size  = SDRAM_SIZE;
    mi->bank[mi->nr_banks].node = mi->nr_banks;
    ++mi->nr_banks;
#ifdef CONFIG_DISCONTIGMEM
    mi->bank[mi->nr_banks].start = SRAM_PA;
    mi->bank[mi->nr_banks].size  = SRAM_SIZE;
#ifdef LEON_IMAGE_IN_SRAM
    mi->bank[mi->nr_banks].size -= LEON_IMAGE_SIZE;
#endif
    mi->bank[mi->nr_banks].node = mi->nr_banks;
    ++mi->nr_banks;
#endif

printk(KERN_NOTICE "%d memory %s\n", mi->nr_banks, (mi->nr_banks > 1) ? "regions" : "region");
}

#if defined(CONFIG_LEON_POWER_BUTTON_MONITOR) || defined(CONFIG_LEON_POWER_BUTTON_MONITOR_MODULE)
#include <mach/leon.h>
#include <mach/leon-power-button-prog.h>
#endif  

static void sata_power_off(void)
{
#ifdef CONFIG_OXNAS_SATA_POWER_1
     
    printk(KERN_INFO "Turning off disk 1\n");
    writel(SATA_POWER_1_MASK, SATA_POWER_1_OUTPUT_CLR_REG);
#endif  

#ifdef CONFIG_OXNAS_SATA_POWER_2
     
    printk(KERN_INFO "Turning off disk 2\n");
    writel(SATA_POWER_2_MASK, SATA_POWER_2_OUTPUT_CLR_REG);
#endif  
}

static void arch_poweroff(void)
{
#if defined(CONFIG_LEON_POWER_BUTTON_MONITOR) || defined(CONFIG_LEON_POWER_BUTTON_MONITOR_MODULE)
     
    init_copro(leon_srec, oxnas_global_invert_leds);
#endif  

    sata_power_off();
#ifdef CONFIG_SYNO_PLX_PORTING
#define	SOFTWARE_SHUTDOWN		0x31
#define	SOFTWARE_REBOOT			0x43
	writel(SOFTWARE_SHUTDOWN, UART_2_BASE);
#endif
}

#ifdef CONFIG_SYNO_PLX_PORTING
static void synology_restart(char mode, const char *cmd)
{
	writel(SOFTWARE_REBOOT, UART_2_BASE);
}
#endif

#ifdef CONFIG_SYNO_PLX_PORTING
extern void synology_gpio_init();
#endif
static void __init oxnas_init_machine(void)
{
     
    spin_lock_init(&oxnas_gpio_spinlock);

    oxnas_dma_init();

#ifdef CONFIG_LEON_START_EARLY
    init_copro(leon_early_srec, 0);
#endif  
#ifdef CONFIG_SPI	
	spi_register_board_info(ox820_spi_board_info,
		ARRAY_SIZE(ox820_spi_board_info));
#endif

	platform_add_devices(platform_devices, ARRAY_SIZE(platform_devices));

	pm_power_off = arch_poweroff;
#ifdef CONFIG_SYNO_PLX_PORTING
	arm_pm_restart = synology_restart;
#endif

#ifdef CONFIG_SYNO_PLX_PORTING
	synology_gpio_init();
#endif
}

static void __init oxnas_init_irq(void)
{
     
    OX820_RPS_init_irq(OX820_RPS_IRQ_START, OX820_RPS_IRQ_START + NR_RPS_IRQS);

	gic_cpu_base_addr = __io_address(OX820_GIC_CPU_BASE_ADDR);

	gic_dist_init(0, __io_address(OX820_GIC_DIST_BASE_ADDR), 29);
	gic_cpu_init(0, gic_cpu_base_addr);
    OX820_RPS_cascade_irq( RPSA_IRQ_INTERRUPT);
}

MACHINE_START(OXNAS, "Oxsemi NAS")
     
#ifdef CONFIG_ARCH_OXNAS_UART1
    .phys_io = UART_1_BASE_PA,
    .io_pg_offst = (((u32)UART_1_BASE) >> 18) & 0xfffc,
#elif defined(CONFIG_ARCH_OXNAS_UART2)
    .phys_io = UART_2_BASE_PA,
    .io_pg_offst = (((u32)UART_2_BASE) >> 18) & 0xfffc,
#endif
    .boot_params = SDRAM_PA + 0x100,
    .fixup = oxnas_fixup,
    .map_io = oxnas_mapio,
    .init_irq = oxnas_init_irq,
    .timer = &oxnas_timer,
    .init_machine = oxnas_init_machine,
MACHINE_END
