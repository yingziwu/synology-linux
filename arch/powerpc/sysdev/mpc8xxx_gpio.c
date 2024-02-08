 
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#ifdef CONFIG_SYNO_QORIQ_FIX_DEEP_WAKE_FAIL
#include <linux/delay.h>
#endif
#ifdef CONFIG_SYNO_QORIQ_EN_DEEP_WAKE_PIN
#include <linux/interrupt.h>
#endif

#ifdef CONFIG_SYNO_QORIQ
#define MPC8XXX_GPIO_PINS	87
#else
#define MPC8XXX_GPIO_PINS	32
#endif

#ifdef CONFIG_SYNO_QORIQ
#define IN_GPIO3(x)			(x & ~(0x3f))
#define IN_GPIO2(x)			(x & ~(0x1f))
#define GPIO2_OFFSET		0x100
#define GPIO3_OFFSET		0x200
#endif
#define GPIO_DIR		0x00
#define GPIO_ODR		0x04
#define GPIO_DAT		0x08
#define GPIO_IER		0x0c
#define GPIO_IMR		0x10
#define GPIO_ICR		0x14

struct mpc8xxx_gpio_chip {
	struct of_mm_gpio_chip mm_gc;
	spinlock_t lock;

#ifdef CONFIG_SYNO_QORIQ
	u32 *pData;
	u32 data_1;
	u32 data_2;
	u32 data_3;
#else
	u32 data;
#endif
};

#ifdef CONFIG_SYNO_QORIQ_EN_DEEP_WAKE_PIN
extern int SYNOQorIQGPIOWakeInterruptClear(void);
#endif

static inline u32 mpc8xxx_gpio2mask(unsigned int gpio)
{
#ifdef CONFIG_SYNO_QORIQ
	return 1u << (32 - 1 - gpio);
#else
	return 1u << (MPC8XXX_GPIO_PINS - 1 - gpio);
#endif
}

static inline struct mpc8xxx_gpio_chip *
to_mpc8xxx_gpio_chip(struct of_mm_gpio_chip *mm)
{
	return container_of(mm, struct mpc8xxx_gpio_chip, mm_gc);
}

static void mpc8xxx_gpio_save_regs(struct of_mm_gpio_chip *mm)
{
	struct mpc8xxx_gpio_chip *mpc8xxx_gc = to_mpc8xxx_gpio_chip(mm);

#ifdef CONFIG_SYNO_QORIQ
	mpc8xxx_gc->pData = &mpc8xxx_gc->data_1;
	mpc8xxx_gc->data_1 = in_be32(mm->regs + GPIO_DAT);
	mpc8xxx_gc->data_2 = in_be32(mm->regs + GPIO2_OFFSET + GPIO_DAT);
	mpc8xxx_gc->data_3 = in_be32(mm->regs + GPIO3_OFFSET + GPIO_DAT);
#else
	mpc8xxx_gc->data = in_be32(mm->regs + GPIO_DAT);
#endif
}

static int mpc8xxx_gpio_get(struct gpio_chip *gc, unsigned int gpio)
{
	struct of_mm_gpio_chip *mm = to_of_mm_gpio_chip(gc);

#ifdef CONFIG_SYNO_QORIQ
	if (IN_GPIO3(gpio))
		return in_be32(mm->regs + GPIO3_OFFSET + GPIO_DAT) & mpc8xxx_gpio2mask(gpio - 64);
	else if (IN_GPIO2(gpio))
		return in_be32(mm->regs + GPIO2_OFFSET + GPIO_DAT) & mpc8xxx_gpio2mask(gpio - 32);
	else
		return in_be32(mm->regs + GPIO_DAT) & mpc8xxx_gpio2mask(gpio);
#else
	return in_be32(mm->regs + GPIO_DAT) & mpc8xxx_gpio2mask(gpio);
#endif
}

static void mpc8xxx_gpio_set(struct gpio_chip *gc, unsigned int gpio, int val)
{
	struct of_mm_gpio_chip *mm = to_of_mm_gpio_chip(gc);
	struct mpc8xxx_gpio_chip *mpc8xxx_gc = to_mpc8xxx_gpio_chip(mm);
	unsigned long flags;
#ifdef CONFIG_SYNO_QORIQ
	unsigned long offset = 0;
#endif

	spin_lock_irqsave(&mpc8xxx_gc->lock, flags);

#ifdef CONFIG_SYNO_QORIQ
	if (IN_GPIO3(gpio)) {
		gpio -= 64;
		offset = GPIO3_OFFSET;
		mpc8xxx_gc->pData = &mpc8xxx_gc->data_3;
	} else if (IN_GPIO2(gpio)) {
		gpio -= 32;
		offset = GPIO2_OFFSET;
		mpc8xxx_gc->pData = &mpc8xxx_gc->data_2;
	} else {
		mpc8xxx_gc->pData = &mpc8xxx_gc->data_1;
		offset = 0;
	}

	if (val)
		*mpc8xxx_gc->pData |= mpc8xxx_gpio2mask(gpio);
	else
		*mpc8xxx_gc->pData &= ~mpc8xxx_gpio2mask(gpio);

	out_be32(mm->regs + offset + GPIO_DAT, *mpc8xxx_gc->pData);
#else
	if (val)
		mpc8xxx_gc->data |= mpc8xxx_gpio2mask(gpio);
	else
		mpc8xxx_gc->data &= ~mpc8xxx_gpio2mask(gpio);

	out_be32(mm->regs + GPIO_DAT, mpc8xxx_gc->data);
#endif

	spin_unlock_irqrestore(&mpc8xxx_gc->lock, flags);
}

static int mpc8xxx_gpio_dir_in(struct gpio_chip *gc, unsigned int gpio)
{
	struct of_mm_gpio_chip *mm = to_of_mm_gpio_chip(gc);
	struct mpc8xxx_gpio_chip *mpc8xxx_gc = to_mpc8xxx_gpio_chip(mm);
	unsigned long flags;
#ifdef CONFIG_SYNO_QORIQ
	unsigned long offset = 0;
#endif

	spin_lock_irqsave(&mpc8xxx_gc->lock, flags);

#ifdef CONFIG_SYNO_QORIQ
	if (IN_GPIO3(gpio)) {
		gpio -= 64;
		offset = GPIO3_OFFSET;
	} else if (IN_GPIO2(gpio)) {
		gpio -= 32;
		offset = GPIO2_OFFSET;
	} else {
		offset = 0;
	}

	clrbits32(mm->regs + offset + GPIO_DIR, mpc8xxx_gpio2mask(gpio));
#else
	clrbits32(mm->regs + GPIO_DIR, mpc8xxx_gpio2mask(gpio));
#endif

	spin_unlock_irqrestore(&mpc8xxx_gc->lock, flags);

	return 0;
}

static int mpc8xxx_gpio_dir_out(struct gpio_chip *gc, unsigned int gpio, int val)
{
	struct of_mm_gpio_chip *mm = to_of_mm_gpio_chip(gc);
	struct mpc8xxx_gpio_chip *mpc8xxx_gc = to_mpc8xxx_gpio_chip(mm);
	unsigned long flags;
#ifdef CONFIG_SYNO_QORIQ
	unsigned long offset = 0;
#endif

	mpc8xxx_gpio_set(gc, gpio, val);

	spin_lock_irqsave(&mpc8xxx_gc->lock, flags);

#ifdef CONFIG_SYNO_QORIQ
	if (IN_GPIO3(gpio)) {
		gpio -= 64;
		offset = GPIO3_OFFSET;
	} else if (IN_GPIO2(gpio)) {
		gpio -= 32;
		offset = GPIO2_OFFSET;
	} else {
		offset = 0;
	}

	setbits32(mm->regs + offset + GPIO_DIR, mpc8xxx_gpio2mask(gpio));
#else
	setbits32(mm->regs + GPIO_DIR, mpc8xxx_gpio2mask(gpio));
#endif

	spin_unlock_irqrestore(&mpc8xxx_gc->lock, flags);

	return 0;
}

#ifdef CONFIG_SYNO_QORIQ_FIX_DEEP_WAKE_FAIL
static void iMpc8xxxHWReset(struct gpio_chip *gc, unsigned int gpio)
{
	struct of_mm_gpio_chip *mm = to_of_mm_gpio_chip(gc);
	struct mpc8xxx_gpio_chip *mpc8xxx_gc = to_mpc8xxx_gpio_chip(mm);
	unsigned long flags;
	unsigned long offset = 0;

	spin_lock_irqsave(&mpc8xxx_gc->lock, flags);

	if (IN_GPIO3(gpio)) {
		gpio -= 64;
		offset = GPIO3_OFFSET;
		mpc8xxx_gc->pData = &mpc8xxx_gc->data_3;
	} else if (IN_GPIO2(gpio)) {
		gpio -= 32;
		offset = GPIO2_OFFSET;
		mpc8xxx_gc->pData = &mpc8xxx_gc->data_2;
	} else {
		mpc8xxx_gc->pData = &mpc8xxx_gc->data_1;
		offset = 0;
	}

	*mpc8xxx_gc->pData &= ~mpc8xxx_gpio2mask(gpio);
	out_be32(mm->regs + offset + GPIO_DAT, *mpc8xxx_gc->pData);
	mdelay(200);
	*mpc8xxx_gc->pData |= mpc8xxx_gpio2mask(gpio);
	out_be32(mm->regs + offset + GPIO_DAT, *mpc8xxx_gc->pData);
	mdelay(200);

	spin_unlock_irqrestore(&mpc8xxx_gc->lock, flags);
}
#endif

#ifdef CONFIG_SYNO_QORIQ_EN_DEEP_WAKE_PIN
static int iMpc8xxxGpioInterruptClear(struct gpio_chip *gc, const unsigned int gpio)
{
	struct of_mm_gpio_chip *mm = to_of_mm_gpio_chip(gc);
	struct mpc8xxx_gpio_chip *mpc8xxx_gc = to_mpc8xxx_gpio_chip(mm);
	unsigned long flags = 0x0;
	unsigned long offset = 0;
	unsigned int uiGpioTran = gpio;

	spin_lock_irqsave(&mpc8xxx_gc->lock, flags);

	if (IN_GPIO3(gpio)) {
		uiGpioTran -= 64;
		offset = GPIO3_OFFSET;
	} else if (IN_GPIO2(gpio)) {
		uiGpioTran -= 32;
		offset = GPIO2_OFFSET;
	} else {
		offset = 0;
	}

	out_be32(mm->regs + offset + GPIO_IER, in_be32(mm->regs + offset + GPIO_IER));

	spin_unlock_irqrestore(&mpc8xxx_gc->lock, flags);

	return 0;
}

static unsigned char should_wake = 0;
void GPIOSuspend(void)
{
	should_wake = 0;
}
EXPORT_SYMBOL(GPIOSuspend);

unsigned char GPIOShouldWake(void)
{
	return should_wake;
}
EXPORT_SYMBOL(GPIOShouldWake);

static irqreturn_t ClearGpioIrq(int irq, void *dev_id)
{
	SYNOQorIQGPIOWakeInterruptClear();
	should_wake = 1;

	return IRQ_HANDLED;
}
#endif

static void __init mpc8xxx_add_controller(struct device_node *np)
{
	struct mpc8xxx_gpio_chip *mpc8xxx_gc;
	struct of_mm_gpio_chip *mm_gc;
	struct of_gpio_chip *of_gc;
	struct gpio_chip *gc;
	int ret;
#ifdef CONFIG_SYNO_QORIQ_EN_DEEP_WAKE_PIN
	int irq = 0;
#endif

	mpc8xxx_gc = kzalloc(sizeof(*mpc8xxx_gc), GFP_KERNEL);
	if (!mpc8xxx_gc) {
		ret = -ENOMEM;
		goto err;
	}

	spin_lock_init(&mpc8xxx_gc->lock);

	mm_gc = &mpc8xxx_gc->mm_gc;
	of_gc = &mm_gc->of_gc;
	gc = &of_gc->gc;

	mm_gc->save_regs = mpc8xxx_gpio_save_regs;
	of_gc->gpio_cells = 2;
	gc->ngpio = MPC8XXX_GPIO_PINS;
	gc->direction_input = mpc8xxx_gpio_dir_in;
	gc->direction_output = mpc8xxx_gpio_dir_out;
	gc->get = mpc8xxx_gpio_get;
	gc->set = mpc8xxx_gpio_set;
#ifdef CONFIG_SYNO_QORIQ_FIX_DEEP_WAKE_FAIL
	gc->iHWReset = iMpc8xxxHWReset;
#endif
#ifdef CONFIG_SYNO_QORIQ_EN_DEEP_WAKE_PIN
	gc->iInterruptClear = iMpc8xxxGpioInterruptClear;

	if (NO_IRQ == (irq = irq_of_parse_and_map(np, 0))) {
		printk("No GPIO IRQ\n");
	} else if ((ret = request_irq(irq, ClearGpioIrq, 0, "Clear GPIO Interrupt", NULL))) {
		printk("error %d requesting GPIO IRQ\n", ret);
	}
#endif

	ret = of_mm_gpiochip_add(np, mm_gc);
	if (ret)
		goto err;

	return;

err:
	pr_err("%s: registration failed with status %d\n",
	       np->full_name, ret);
	kfree(mpc8xxx_gc);

	return;
}

static int __init mpc8xxx_add_gpiochips(void)
{
	struct device_node *np;

	for_each_compatible_node(np, NULL, "fsl,mpc8349-gpio")
		mpc8xxx_add_controller(np);

	for_each_compatible_node(np, NULL, "fsl,mpc8572-gpio")
		mpc8xxx_add_controller(np);

	for_each_compatible_node(np, NULL, "fsl,mpc8610-gpio")
		mpc8xxx_add_controller(np);

	return 0;
}
arch_initcall(mpc8xxx_add_gpiochips);
