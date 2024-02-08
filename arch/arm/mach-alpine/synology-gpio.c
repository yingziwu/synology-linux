#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#if defined(MY_DEF_HERE)

#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/synobios.h>
#include <linux/export.h>

#ifndef HW_DS2015xs
#define HW_DS2015xs "DS2015xs"
#endif
#ifndef HW_DS1515
#define HW_DS1515 "DS1515"
#endif
#ifndef HW_DS715
#define HW_DS715 "DS715"
#endif
#ifndef HW_DS215p
#define HW_DS215p "DS215+"
#endif
#ifndef HW_DS416
#define HW_DS416 "DS416"
#endif

#define GPIO_UNDEF				0xFF

#define DISK_LED_OFF			0
#define DISK_LED_GREEN_SOLID	1
#define DISK_LED_ORANGE_SOLID	2
#define DISK_LED_ORANGE_BLINK	3
#define DISK_LED_GREEN_BLINK    4

#define SYNO_LED_OFF		0
#define SYNO_LED_ON			1
#define SYNO_LED_BLINKING	2

#ifdef  MY_ABC_HERE
extern char gszSynoHWVersion[];
#endif

typedef struct __tag_SYNO_HDD_DETECT_GPIO {
	u8 hdd1_present_detect;
	u8 hdd2_present_detect;
	u8 hdd3_present_detect;
	u8 hdd4_present_detect;
	u8 hdd5_present_detect;
	u8 hdd6_present_detect;
	u8 hdd7_present_detect;
	u8 hdd8_present_detect;
} SYNO_HDD_DETECT_GPIO;

typedef struct __tag_SYNO_HDD_PM_GPIO {
	u8 hdd1_pm;
	u8 hdd2_pm;
	u8 hdd3_pm;
	u8 hdd4_pm;
	u8 hdd5_pm;
	u8 hdd6_pm;
	u8 hdd7_pm;
	u8 hdd8_pm;
} SYNO_HDD_PM_GPIO;

typedef struct __tag_SYNO_FAN_GPIO {
	u8 fan_1;
	u8 fan_2;
	u8 fan_fail;
	u8 fan_fail_2;
} SYNO_FAN_GPIO;

typedef struct __tag_SYNO_MODEL_GPIO {
	u8 model_id_0;
	u8 model_id_1;
	u8 model_id_2;
	u8 model_id_3;
} SYNO_MODEL_GPIO;

typedef struct __tag_SYNO_EXT_HDD_LED_GPIO {
	u8 hdd1_led_0;
	u8 hdd1_led_1;
	u8 hdd2_led_0;
	u8 hdd2_led_1;
	u8 hdd3_led_0;
	u8 hdd3_led_1;
	u8 hdd4_led_0;
	u8 hdd4_led_1;
	u8 hdd5_led_0;
	u8 hdd5_led_1;
	u8 hdd_led_mask;
} SYNO_EXT_HDD_LED_GPIO;

typedef struct __tag_SYNO_MULTI_BAY_GPIO {
	u8 inter_lock;
} SYNO_MULTI_BAY_GPIO;

typedef struct __tag_SYNO_SOC_HDD_LED_GPIO {
	u8 hdd1_fail_led;
	u8 hdd2_fail_led;
	u8 hdd3_fail_led;
	u8 hdd4_fail_led;
	u8 hdd5_fail_led;
	u8 hdd6_fail_led;
	u8 hdd7_fail_led;
	u8 hdd8_fail_led;
	u8 hdd1_act_led;
	u8 hdd2_act_led;
	u8 hdd3_act_led;
	u8 hdd4_act_led;
	u8 hdd5_act_led;
	u8 hdd6_act_led;
	u8 hdd7_act_led;
	u8 hdd8_act_led;
} SYNO_SOC_HDD_LED_GPIO;

typedef struct __tag_SYNO_RACK_GPIO {
	u8 buzzer_mute_req;
	u8 buzzer_mute_ack;
	u8 rps1_on;
	u8 rps2_on;
} SYNO_RACK_GPIO;

typedef struct __tag_SYNO_STATUS_LED_GPIO {
	u8 alarm_led;
	u8 power_led;
} SYNO_STATUS_LED_GPIO;

typedef struct __tag_SYNO_GPIO {
	SYNO_HDD_DETECT_GPIO    hdd_detect;
	SYNO_EXT_HDD_LED_GPIO	ext_sata_led;
	SYNO_SOC_HDD_LED_GPIO	soc_sata_led;
	SYNO_MODEL_GPIO			model;
	SYNO_FAN_GPIO			fan;
	SYNO_HDD_PM_GPIO		hdd_pm;
	SYNO_RACK_GPIO			rack;
	SYNO_MULTI_BAY_GPIO		multi_bay;
	SYNO_STATUS_LED_GPIO	status;
}SYNO_GPIO;

static SYNO_GPIO generic_gpio;

unsigned int SynoModelIDGet(SYNO_GPIO *pGpio)
{
	if (GPIO_UNDEF != pGpio->model.model_id_3) {
		return (((gpio_get_value(pGpio->model.model_id_0) ? 1 : 0) << 3) |
		        ((gpio_get_value(pGpio->model.model_id_1) ? 1 : 0) << 2) |
		        ((gpio_get_value(pGpio->model.model_id_2) ? 1 : 0) << 1) |
		        ((gpio_get_value(pGpio->model.model_id_3) ? 1 : 0) << 0));
	} else {
		return (((gpio_get_value(pGpio->model.model_id_0) ? 1 : 0) << 2) |
		        ((gpio_get_value(pGpio->model.model_id_1) ? 1 : 0) << 1) |
		        ((gpio_get_value(pGpio->model.model_id_2) ? 1 : 0) << 0));
	}
}

int
SYNO_ALPINE_GPIO_PIN(int pin, int *pValue, int isWrite)
{
	int ret = -1;

	if (!pValue)
		goto END;

	if (1 == isWrite)
		gpio_set_value(pin, *pValue);
	else
		*pValue = gpio_get_value(pin);

	ret = 0;
END:
	return 0;
}

void SYNO_MASK_HDD_LED(int blEnable)
{
	if (GPIO_UNDEF != generic_gpio.ext_sata_led.hdd_led_mask)
		gpio_set_value(generic_gpio.ext_sata_led.hdd_led_mask, blEnable ? 1 : 0);
}

int
SYNO_CTRL_EXT_CHIP_HDD_LED_SET(int index, int status)
{
	int ret = -1;
	int pin1 = 0, pin2 = 0, bit1 = 0, bit2 = 0;

	bit1 = ( status >> 0 ) & 0x1;
	bit2 = ( status >> 1 ) & 0x1;

	switch (index) {
	case 1:
		pin1 = generic_gpio.ext_sata_led.hdd1_led_0;
		pin2 = generic_gpio.ext_sata_led.hdd1_led_1;
		break;
	case 2:
		pin1 = generic_gpio.ext_sata_led.hdd2_led_0;
		pin2 = generic_gpio.ext_sata_led.hdd2_led_1;
		break;
	case 3:
		pin1 = generic_gpio.ext_sata_led.hdd3_led_0;
		pin2 = generic_gpio.ext_sata_led.hdd3_led_1;
		break;
	case 4:
		pin1 = generic_gpio.ext_sata_led.hdd4_led_0;
		pin2 = generic_gpio.ext_sata_led.hdd4_led_1;
		break;
	case 5:
		pin1 = generic_gpio.ext_sata_led.hdd5_led_0;
		pin2 = generic_gpio.ext_sata_led.hdd5_led_1;
		break;
	case 6:
		 
		ret = 0;
		goto END;
	default:
		printk("Wrong HDD number [%d]\n", index);
		goto END;
	}

	WARN_ON(pin1 == GPIO_UNDEF);
	WARN_ON(pin2 == GPIO_UNDEF);

	gpio_set_value(pin1, bit1);
	gpio_set_value(pin2, bit2);

    ret = 0;
END:
    return ret;
}

int SYNO_CTRL_HDD_POWERON(int index, int value)
{
	int ret = -1;

	switch (index) {
	case 1:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd1_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd1_pm, value);
		break;
	case 2:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd2_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd2_pm, value);
		break;
	case 3:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd3_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd3_pm, value);
		break;
	case 4:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd4_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd4_pm, value);
		break;
	case 5:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd5_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd5_pm, value);
		break;
	case 6:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd6_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd6_pm, value);
		break;
	case 7:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd7_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd7_pm, value);
		break;
	case 8:
		WARN_ON(GPIO_UNDEF == generic_gpio.hdd_pm.hdd8_pm);
		gpio_set_value(generic_gpio.hdd_pm.hdd8_pm, value);
		break;
	default:
		goto END;
	}

	ret = 0;
END:
	return ret;
}

int SYNO_CTRL_FAN_PERSISTER(int index, int status, int isWrite)
{
	int ret = 0;
	u8 pin = GPIO_UNDEF;

	switch (index) {
	case 1:
		pin = generic_gpio.fan.fan_1;
		break;
	case 2:
		pin = generic_gpio.fan.fan_2;
		break;
	default:
		ret = -1;
		printk("%s fan not match\n", __FUNCTION__);
		goto END;
	}

	WARN_ON(GPIO_UNDEF == pin);
	gpio_set_value(pin, status);
END:
	return ret;
}

int SYNO_CTRL_FAN_STATUS_GET(int index, int *pValue)
{
	int ret = 0;

	switch (index) {
		case 1:
			WARN_ON(GPIO_UNDEF == generic_gpio.fan.fan_fail);
			*pValue = gpio_get_value(generic_gpio.fan.fan_fail);
			break;
		case 2:
			WARN_ON(GPIO_UNDEF == generic_gpio.fan.fan_fail_2);
			*pValue = gpio_get_value(generic_gpio.fan.fan_fail_2);
			break;
		default:
			WARN_ON(1);
			break;
	}

	if(*pValue)
		*pValue = 0;
	else
		*pValue = 1;

	return ret;
}

int SYNO_CTRL_ALARM_LED_SET(int status)
{
	WARN_ON(GPIO_UNDEF == generic_gpio.status.alarm_led);

	gpio_set_value(generic_gpio.status.alarm_led, status);
	return 0;
}

int SYNO_CTRL_BACKPLANE_STATUS_GET(int *pStatus)
{
	WARN_ON(GPIO_UNDEF == generic_gpio.multi_bay.inter_lock);

	*pStatus = gpio_get_value(generic_gpio.multi_bay.inter_lock);
	return 0;
}

int SYNO_CTRL_BUZZER_CLEARED_GET(int *pValue)
{
	int tempVal = 0;

	WARN_ON(GPIO_UNDEF == generic_gpio.rack.buzzer_mute_req);

	tempVal = gpio_get_value(generic_gpio.rack.buzzer_mute_req);
	if ( tempVal ) {
		*pValue = 0;
	} else {
		*pValue = 1;
		tempVal = 1;
	}

	return 0;
}

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))
struct disk_info {
	char *hw_version;
	int	max_disk_id;
};
static struct disk_info alpine_family[] = {
	{HW_DS715, 2},
	{HW_DS215p, 2},
	{HW_DS416, 4}
};

unsigned char SYNOALPINEIsBoardNeedPowerUpHDD(u32 disk_id) {
	u8 ret = 0;
	int i;
	int def_max_disk = 0;

	if (0 == strncmp(gszSynoHWVersion, HW_DS2015xs, strlen(HW_DS2015xs))) {
	     
	    return 0;
	}
	if (0 == strncmp(gszSynoHWVersion, HW_DS1515, strlen(HW_DS1515))) {
	     
		return 0;
	}

	if (0 == strncmp(gszSynoHWVersion, HW_DS715, strlen(HW_DS715))) {
		def_max_disk = 2;
	} else if (0 == strncmp(gszSynoHWVersion, HW_DS215p, strlen(HW_DS215p))) {
		def_max_disk = 2;
	} else if (0 == strncmp(gszSynoHWVersion, HW_DS416, strlen(HW_DS416))) {
		def_max_disk = 4;
	}

	ret = (disk_id <= def_max_disk)? 1 : 0;
	for (i = 0; i < ARRAY_LEN(alpine_family); i++) {
		if (syno_is_hw_version(alpine_family[i].hw_version)) {
			if (disk_id <= alpine_family[i].max_disk_id) {
				ret = 1;
			}
			break;
		}
	}

	return ret;
}

int SYNO_CHECK_HDD_PRESENT(int index)
{
    int iPrzVal = 1;  

    switch (index) {
        case 1:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd1_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd1_present_detect);
            }
            break;
        case 2:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd2_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd2_present_detect);
            }
            break;
        case 3:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd3_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd3_present_detect);
            }
            break;
        case 4:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd4_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd4_present_detect);
            }
            break;
        case 5:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd5_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd5_present_detect);
            }
            break;
        case 6:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd6_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd6_present_detect);
            }
            break;
        case 7:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd7_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd7_present_detect);
            }
            break;
        case 8:
            if (GPIO_UNDEF != generic_gpio.hdd_detect.hdd8_present_detect) {
                iPrzVal = !gpio_get_value(generic_gpio.hdd_detect.hdd8_present_detect);
            }
            break;
        default:
            break;
    }

    return iPrzVal;
}

int
SYNO_SOC_HDD_LED_SET(int index, int status)
{
	int ret = -1;
	int fail_led = 0;
	int present_led = 0;

	WARN_ON(GPIO_UNDEF == generic_gpio.soc_sata_led.hdd1_fail_led);

	switch (index) {
		case 1:
			fail_led = generic_gpio.soc_sata_led.hdd1_fail_led;
			present_led = generic_gpio.hdd_detect.hdd1_present_detect;
			break;
		case 2:
			fail_led = generic_gpio.soc_sata_led.hdd2_fail_led;
			present_led = generic_gpio.hdd_detect.hdd2_present_detect;
			break;
		case 3:
			fail_led = generic_gpio.soc_sata_led.hdd3_fail_led;
			present_led = generic_gpio.hdd_detect.hdd3_present_detect;
			break;
		case 4:
			fail_led = generic_gpio.soc_sata_led.hdd4_fail_led;
			present_led = generic_gpio.hdd_detect.hdd4_present_detect;
			break;
		case 5:
			fail_led = generic_gpio.soc_sata_led.hdd5_fail_led;
			present_led = generic_gpio.hdd_detect.hdd5_present_detect;
			break;
		case 6:
			fail_led = generic_gpio.soc_sata_led.hdd6_fail_led;
			present_led = generic_gpio.hdd_detect.hdd6_present_detect;
			break;
		case 7:
			fail_led = generic_gpio.soc_sata_led.hdd7_fail_led;
			present_led = generic_gpio.hdd_detect.hdd7_present_detect;
			break;
		case 8:
			fail_led = generic_gpio.soc_sata_led.hdd8_fail_led;
			present_led = generic_gpio.hdd_detect.hdd8_present_detect;
			break;
		default:
			printk("Wrong HDD number [%d]\n", index);
			goto END;
	}

	if (DISK_LED_ORANGE_SOLID == status || DISK_LED_ORANGE_BLINK == status) {
		gpio_set_value(fail_led, 1);
		gpio_set_value(present_led, 0);
	} else if ( DISK_LED_GREEN_SOLID == status || DISK_LED_GREEN_BLINK == status) {
		gpio_set_value(fail_led, 0);
		gpio_set_value(present_led, 1);
	} else if (DISK_LED_OFF == status) {
		gpio_set_value(fail_led, 0);
		gpio_set_value(present_led, 0);
	} else {
		printk("Wrong HDD led status [%d]\n", status);
		goto END;
	}

	ret = 0;
END:
	return ret;
}

int SYNO_SUPPORT_HDD_DYNAMIC_ENABLE_POWER(void)
{
	int iRet = 0;

	if ((GPIO_UNDEF != generic_gpio.hdd_pm.hdd1_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd1_present_detect) ||
		(GPIO_UNDEF != generic_gpio.hdd_pm.hdd2_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd2_present_detect) ||
		(GPIO_UNDEF != generic_gpio.hdd_pm.hdd3_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd3_present_detect) ||
		(GPIO_UNDEF != generic_gpio.hdd_pm.hdd4_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd4_present_detect) ||
		(GPIO_UNDEF != generic_gpio.hdd_pm.hdd5_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd5_present_detect) ||
		(GPIO_UNDEF != generic_gpio.hdd_pm.hdd6_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd6_present_detect) ||
		(GPIO_UNDEF != generic_gpio.hdd_pm.hdd7_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd7_present_detect) ||
		(GPIO_UNDEF != generic_gpio.hdd_pm.hdd8_pm && GPIO_UNDEF != generic_gpio.hdd_detect.hdd8_present_detect)) {

		iRet = 1;
	}
	return iRet;
}

int SYNO_CTRL_HDD_ACT_NOTIFY(int index)
{
	int ret = 0;
	u32 pin = GPIO_UNDEF;
	int value = 0;
	static u32 disk_act_value[8] = {0};

	switch (index) {
	case 0:
		pin = generic_gpio.soc_sata_led.hdd1_act_led;
		break;
	case 1:
		pin = generic_gpio.soc_sata_led.hdd2_act_led;
		break;
	case 2:
		pin = generic_gpio.soc_sata_led.hdd3_act_led;
		break;
	case 3:
		pin = generic_gpio.soc_sata_led.hdd4_act_led;
		break;
	case 4:
		pin = generic_gpio.soc_sata_led.hdd5_act_led;
		break;
	case 5:
		pin = generic_gpio.soc_sata_led.hdd6_act_led;
		break;
	case 6:
		pin = generic_gpio.soc_sata_led.hdd7_act_led;
		break;
	case 7:
		pin = generic_gpio.soc_sata_led.hdd8_act_led;
		break;
	default:
			ret = -1;
			printk("%s: unsupported disk index [%d]\n", __FUNCTION__, index);
			goto END;
	}

	disk_act_value[index] = !disk_act_value[index];
	value = disk_act_value[index];

	WARN_ON(GPIO_UNDEF == pin);
	gpio_set_value(pin, value);

END:
	return ret;
}

EXPORT_SYMBOL(SYNO_CTRL_HDD_ACT_NOTIFY);
EXPORT_SYMBOL(SYNOALPINEIsBoardNeedPowerUpHDD);
EXPORT_SYMBOL(SYNO_ALPINE_GPIO_PIN);
EXPORT_SYMBOL(SYNO_MASK_HDD_LED);
EXPORT_SYMBOL(SYNO_CTRL_EXT_CHIP_HDD_LED_SET);
EXPORT_SYMBOL(SYNO_CTRL_HDD_POWERON);
EXPORT_SYMBOL(SYNO_CTRL_FAN_PERSISTER);
EXPORT_SYMBOL(SYNO_CTRL_FAN_STATUS_GET);
EXPORT_SYMBOL(SYNO_CTRL_ALARM_LED_SET);
EXPORT_SYMBOL(SYNO_CTRL_BACKPLANE_STATUS_GET);
EXPORT_SYMBOL(SYNO_CTRL_BUZZER_CLEARED_GET);
EXPORT_SYMBOL(SYNO_CHECK_HDD_PRESENT);
EXPORT_SYMBOL(SYNO_SUPPORT_HDD_DYNAMIC_ENABLE_POWER);
EXPORT_SYMBOL(SYNO_SOC_HDD_LED_SET);

static void
ALPINE_ds2015xs_GPIO_init(SYNO_GPIO *global_gpio)
{
	SYNO_GPIO gpio_ds2015xs = {
		.hdd_detect = {
			.hdd1_present_detect = 29,
			.hdd2_present_detect = 31,
			.hdd3_present_detect = 32,
			.hdd4_present_detect = 33,
			.hdd5_present_detect = 34,
			.hdd6_present_detect = 35,
			.hdd7_present_detect = 36,
			.hdd8_present_detect = 37,
		},
		.ext_sata_led = {
			.hdd1_led_0 = GPIO_UNDEF,
			.hdd1_led_1 = GPIO_UNDEF,
			.hdd2_led_0 = GPIO_UNDEF,
			.hdd2_led_1 = GPIO_UNDEF,
			.hdd3_led_0 = GPIO_UNDEF,
			.hdd3_led_1 = GPIO_UNDEF,
			.hdd4_led_0 = GPIO_UNDEF,
			.hdd4_led_1 = GPIO_UNDEF,
			.hdd5_led_0 = GPIO_UNDEF,
			.hdd5_led_1 = GPIO_UNDEF,
			.hdd_led_mask = GPIO_UNDEF,
		},
		.soc_sata_led = {
			.hdd1_fail_led = 38,
			.hdd2_fail_led = 39,
			.hdd3_fail_led = 40,
			.hdd4_fail_led = 41,
			.hdd5_fail_led = 42,
			.hdd6_fail_led = 2,
			.hdd7_fail_led = 3,
			.hdd8_fail_led = 4,
			.hdd1_act_led = 10,
			.hdd2_act_led = 11,
			.hdd3_act_led = 22,
			.hdd4_act_led = 23,
			.hdd5_act_led = 24,
			.hdd6_act_led = 25,
			.hdd7_act_led = 26,
			.hdd8_act_led = 27,
		},
		.model		  = {
			.model_id_0 = 42,   
			.model_id_1 = 41,   
			.model_id_2 = 40,   
			.model_id_3 = GPIO_UNDEF,
		},
		.fan		  = {
			.fan_1 = GPIO_UNDEF,
			.fan_2 = GPIO_UNDEF,
			.fan_fail = 0,
			.fan_fail_2 = 1,
		},
		.hdd_pm		  = {
			.hdd1_pm = GPIO_UNDEF,
			.hdd2_pm = GPIO_UNDEF,
			.hdd3_pm = GPIO_UNDEF,
			.hdd4_pm = GPIO_UNDEF,
			.hdd5_pm = GPIO_UNDEF,
			.hdd6_pm = GPIO_UNDEF,
			.hdd7_pm = GPIO_UNDEF,
			.hdd8_pm = GPIO_UNDEF,
		},
		.rack		  = {
			.buzzer_mute_req = GPIO_UNDEF,
			.buzzer_mute_ack = GPIO_UNDEF,
			.rps1_on = GPIO_UNDEF,
			.rps2_on = GPIO_UNDEF,
		},
		.multi_bay	  = {
			.inter_lock = GPIO_UNDEF,
		},
		.status		  = {
			.power_led = GPIO_UNDEF,
			.alarm_led = 18,
		},
	};

	*global_gpio = gpio_ds2015xs;
}

static void
ALPINE_ds1515_GPIO_init(SYNO_GPIO *global_gpio)
{
	SYNO_GPIO gpio_ds1515 = {
		.hdd_detect = {
			.hdd1_present_detect = 29,
			.hdd2_present_detect = 31,
			.hdd3_present_detect = 32,
			.hdd4_present_detect = 33,
			.hdd5_present_detect = 34,
			.hdd6_present_detect = GPIO_UNDEF,
			.hdd7_present_detect = GPIO_UNDEF,
			.hdd8_present_detect = GPIO_UNDEF,
		},
		.ext_sata_led = {
			.hdd1_led_0 = GPIO_UNDEF,
			.hdd1_led_1 = GPIO_UNDEF,
			.hdd2_led_0 = GPIO_UNDEF,
			.hdd2_led_1 = GPIO_UNDEF,
			.hdd3_led_0 = GPIO_UNDEF,
			.hdd3_led_1 = GPIO_UNDEF,
			.hdd4_led_0 = GPIO_UNDEF,
			.hdd4_led_1 = GPIO_UNDEF,
			.hdd5_led_0 = GPIO_UNDEF,
			.hdd5_led_1 = GPIO_UNDEF,
			.hdd_led_mask = GPIO_UNDEF,
		},
		.soc_sata_led = {
			.hdd1_fail_led = 38,
			.hdd2_fail_led = 39,
			.hdd3_fail_led = 40,
			.hdd4_fail_led = 41,
			.hdd5_fail_led = 42,
			.hdd6_fail_led = GPIO_UNDEF,
			.hdd7_fail_led = GPIO_UNDEF,
			.hdd8_fail_led = GPIO_UNDEF,
			.hdd1_act_led = 10,
			.hdd2_act_led = 11,
			.hdd3_act_led = 22,
			.hdd4_act_led = 23,
			.hdd5_act_led = 24,
			.hdd6_act_led = GPIO_UNDEF,
			.hdd7_act_led = GPIO_UNDEF,
			.hdd8_act_led = GPIO_UNDEF,
		},
		.model		  = {
			.model_id_0 = 42,   
			.model_id_1 = 41,   
			.model_id_2 = 40,   
			.model_id_3 = GPIO_UNDEF,
		},
		.fan		  = {
			.fan_1 = GPIO_UNDEF,
			.fan_2 = GPIO_UNDEF,
			.fan_fail = 0,
			.fan_fail_2 = 1,
		},
		.hdd_pm		  = {
			.hdd1_pm = GPIO_UNDEF,
			.hdd2_pm = GPIO_UNDEF,
			.hdd3_pm = GPIO_UNDEF,
			.hdd4_pm = GPIO_UNDEF,
			.hdd5_pm = GPIO_UNDEF,
			.hdd6_pm = GPIO_UNDEF,
			.hdd7_pm = GPIO_UNDEF,
			.hdd8_pm = GPIO_UNDEF,
		},
		.rack		  = {
			.buzzer_mute_req = GPIO_UNDEF,
			.buzzer_mute_ack = GPIO_UNDEF,
			.rps1_on = GPIO_UNDEF,
			.rps2_on = GPIO_UNDEF,
		},
		.multi_bay	  = {
			.inter_lock = GPIO_UNDEF,
		},
		.status		  = {
			.power_led = GPIO_UNDEF,
			.alarm_led = 18,
		},
	};

	*global_gpio = gpio_ds1515;
}

static void
ALPINE_2bay_GPIO_init(SYNO_GPIO *global_gpio)
{
	SYNO_GPIO gpio_2bay = {
		.hdd_detect = {
			.hdd1_present_detect = 29,
			.hdd2_present_detect = 31,
			.hdd3_present_detect = GPIO_UNDEF,
			.hdd4_present_detect = GPIO_UNDEF,
			.hdd5_present_detect = GPIO_UNDEF,
			.hdd6_present_detect = GPIO_UNDEF,
			.hdd7_present_detect = GPIO_UNDEF,
			.hdd8_present_detect = GPIO_UNDEF,
		},
		.ext_sata_led = {
			.hdd1_led_0 = GPIO_UNDEF,
			.hdd1_led_1 = GPIO_UNDEF,
			.hdd2_led_0 = GPIO_UNDEF,
			.hdd2_led_1 = GPIO_UNDEF,
			.hdd3_led_0 = GPIO_UNDEF,
			.hdd3_led_1 = GPIO_UNDEF,
			.hdd4_led_0 = GPIO_UNDEF,
			.hdd4_led_1 = GPIO_UNDEF,
			.hdd5_led_0 = GPIO_UNDEF,
			.hdd5_led_1 = GPIO_UNDEF,
			.hdd_led_mask = GPIO_UNDEF,
		},
		.soc_sata_led = {
			.hdd1_fail_led = 38,
			.hdd2_fail_led = 39,
			.hdd3_fail_led = GPIO_UNDEF,
			.hdd4_fail_led = GPIO_UNDEF,
			.hdd5_fail_led = GPIO_UNDEF,
			.hdd6_fail_led = GPIO_UNDEF,
			.hdd7_fail_led = GPIO_UNDEF,
			.hdd8_fail_led = GPIO_UNDEF,
			.hdd1_act_led = 10,
			.hdd2_act_led = 11,
			.hdd3_act_led = GPIO_UNDEF,
			.hdd4_act_led = GPIO_UNDEF,
			.hdd5_act_led = GPIO_UNDEF,
			.hdd6_act_led = GPIO_UNDEF,
			.hdd7_act_led = GPIO_UNDEF,
			.hdd8_act_led = GPIO_UNDEF,
		},
		.model		  = {
			.model_id_0 = 42,   
			.model_id_1 = 41,   
			.model_id_2 = 40,   
			.model_id_3 = GPIO_UNDEF,
		},
		.fan		  = {
			.fan_1 = GPIO_UNDEF,
			.fan_2 = GPIO_UNDEF,
			.fan_fail = 0,
			.fan_fail_2 = GPIO_UNDEF,
		},
		.hdd_pm		  = {
			.hdd1_pm = 22,
			.hdd2_pm = 23,
			.hdd3_pm = GPIO_UNDEF,
			.hdd4_pm = GPIO_UNDEF,
			.hdd5_pm = GPIO_UNDEF,
			.hdd6_pm = GPIO_UNDEF,
			.hdd7_pm = GPIO_UNDEF,
			.hdd8_pm = GPIO_UNDEF,
		},
		.rack		  = {
			.buzzer_mute_req = GPIO_UNDEF,
			.buzzer_mute_ack = GPIO_UNDEF,
			.rps1_on = GPIO_UNDEF,
			.rps2_on = GPIO_UNDEF,
		},
		.multi_bay	  = {
			.inter_lock = GPIO_UNDEF,
		},
		.status		  = {
			.power_led = GPIO_UNDEF,
			.alarm_led = GPIO_UNDEF,
		},
	};

	*global_gpio = gpio_2bay;
}

static void
ALPINE_ds416_GPIO_init(SYNO_GPIO *global_gpio)
{
	SYNO_GPIO gpio_ds416 = {
		.hdd_detect = {
			.hdd1_present_detect = 29,
			.hdd2_present_detect = 31,
			.hdd3_present_detect = 32,
			.hdd4_present_detect = 33,
			.hdd5_present_detect = GPIO_UNDEF,
			.hdd6_present_detect = GPIO_UNDEF,
			.hdd7_present_detect = GPIO_UNDEF,
			.hdd8_present_detect = GPIO_UNDEF,
		},
		.ext_sata_led = {
			.hdd1_led_0 = GPIO_UNDEF,
			.hdd1_led_1 = GPIO_UNDEF,
			.hdd2_led_0 = GPIO_UNDEF,
			.hdd2_led_1 = GPIO_UNDEF,
			.hdd3_led_0 = GPIO_UNDEF,
			.hdd3_led_1 = GPIO_UNDEF,
			.hdd4_led_0 = GPIO_UNDEF,
			.hdd4_led_1 = GPIO_UNDEF,
			.hdd5_led_0 = GPIO_UNDEF,
			.hdd5_led_1 = GPIO_UNDEF,
			.hdd_led_mask = GPIO_UNDEF,
		},
		.soc_sata_led = {
			.hdd1_fail_led = 38,
			.hdd2_fail_led = 39,
			.hdd3_fail_led = 40,
			.hdd4_fail_led = 41,
			.hdd5_fail_led = GPIO_UNDEF,
			.hdd6_fail_led = GPIO_UNDEF,
			.hdd7_fail_led = GPIO_UNDEF,
			.hdd8_fail_led = GPIO_UNDEF,
			.hdd1_act_led = 10,
			.hdd2_act_led = 11,
			.hdd3_act_led = 22,
			.hdd4_act_led = 23,
			.hdd5_act_led = GPIO_UNDEF,
			.hdd6_act_led = GPIO_UNDEF,
			.hdd7_act_led = GPIO_UNDEF,
			.hdd8_act_led = GPIO_UNDEF,
		},
		.model		  = {
			.model_id_0 = 42,   
			.model_id_1 = 41,   
			.model_id_2 = 40,   
			.model_id_3 = GPIO_UNDEF,
		},
		.fan		  = {
			.fan_1 = GPIO_UNDEF,
			.fan_2 = GPIO_UNDEF,
			.fan_fail = 0,
			.fan_fail_2 = 1,
		},
		.hdd_pm		  = {
			.hdd1_pm = 24,
			.hdd2_pm = 25,
			.hdd3_pm = 26,
			.hdd4_pm = 27,
			.hdd5_pm = GPIO_UNDEF,
			.hdd6_pm = GPIO_UNDEF,
			.hdd7_pm = GPIO_UNDEF,
			.hdd8_pm = GPIO_UNDEF,
		},
		.rack		  = {
			.buzzer_mute_req = GPIO_UNDEF,
			.buzzer_mute_ack = GPIO_UNDEF,
			.rps1_on = GPIO_UNDEF,
			.rps2_on = GPIO_UNDEF,
		},
		.multi_bay	  = {
			.inter_lock = GPIO_UNDEF,
		},
		.status		  = {
			.power_led = GPIO_UNDEF,
			.alarm_led = GPIO_UNDEF,
		},
	};

	*global_gpio = gpio_ds416;
}

static void
ALPINE_default_GPIO_init(SYNO_GPIO *global_gpio)
{
	SYNO_GPIO gpio_default = {
		.hdd_detect = {
			.hdd1_present_detect = GPIO_UNDEF,
			.hdd2_present_detect = GPIO_UNDEF,
			.hdd3_present_detect = GPIO_UNDEF,
			.hdd4_present_detect = GPIO_UNDEF,
			.hdd5_present_detect = GPIO_UNDEF,
			.hdd6_present_detect = GPIO_UNDEF,
			.hdd7_present_detect = GPIO_UNDEF,
			.hdd8_present_detect = GPIO_UNDEF,
		},
		.ext_sata_led = {
			.hdd1_led_0 = GPIO_UNDEF,
			.hdd1_led_1 = GPIO_UNDEF,
			.hdd2_led_0 = GPIO_UNDEF,
			.hdd2_led_1 = GPIO_UNDEF,
			.hdd3_led_0 = GPIO_UNDEF,
			.hdd3_led_1 = GPIO_UNDEF,
			.hdd4_led_0 = GPIO_UNDEF,
			.hdd4_led_1 = GPIO_UNDEF,
			.hdd5_led_0 = GPIO_UNDEF,
			.hdd5_led_1 = GPIO_UNDEF,
		},
		.soc_sata_led = {
			.hdd1_fail_led = GPIO_UNDEF,
			.hdd2_fail_led = GPIO_UNDEF,
			.hdd3_fail_led = GPIO_UNDEF,
			.hdd4_fail_led = GPIO_UNDEF,
			.hdd5_fail_led = GPIO_UNDEF,
			.hdd6_fail_led = GPIO_UNDEF,
			.hdd7_fail_led = GPIO_UNDEF,
			.hdd8_fail_led = GPIO_UNDEF,
			.hdd1_act_led = GPIO_UNDEF,
			.hdd2_act_led = GPIO_UNDEF,
			.hdd3_act_led = GPIO_UNDEF,
			.hdd4_act_led = GPIO_UNDEF,
			.hdd5_act_led = GPIO_UNDEF,
			.hdd6_act_led = GPIO_UNDEF,
			.hdd7_act_led = GPIO_UNDEF,
			.hdd8_act_led = GPIO_UNDEF,
		},
		.model		  = {
			.model_id_0 = GPIO_UNDEF,
			.model_id_1 = GPIO_UNDEF,
			.model_id_2 = GPIO_UNDEF,
			.model_id_3 = GPIO_UNDEF,
		},
		.fan		  = {
			.fan_1 = GPIO_UNDEF,
			.fan_2 = GPIO_UNDEF,
			.fan_fail = GPIO_UNDEF,
			.fan_fail_2 = GPIO_UNDEF,
		},
		.hdd_pm		  = {
			.hdd1_pm = GPIO_UNDEF,
			.hdd2_pm = GPIO_UNDEF,
			.hdd3_pm = GPIO_UNDEF,
			.hdd4_pm = GPIO_UNDEF,
			.hdd5_pm = GPIO_UNDEF,
			.hdd6_pm = GPIO_UNDEF,
			.hdd7_pm = GPIO_UNDEF,
			.hdd8_pm = GPIO_UNDEF,
		},
		.rack		  = {
			.buzzer_mute_req = GPIO_UNDEF,
			.buzzer_mute_ack = GPIO_UNDEF,
			.rps1_on = GPIO_UNDEF,
			.rps2_on = GPIO_UNDEF,
		},
		.multi_bay	  = {
			.inter_lock = GPIO_UNDEF,
		},
		.status		  = {
			.power_led = GPIO_UNDEF,
			.alarm_led = GPIO_UNDEF,
		},
	};

	*global_gpio = gpio_default;
}

void synology_gpio_init(void)
{
	if (0 == strncmp(gszSynoHWVersion, HW_DS2015xs, strlen(HW_DS2015xs))) {
		ALPINE_ds2015xs_GPIO_init(&generic_gpio);
		printk("Synology %s GPIO Init\n", HW_DS2015xs);
	} else if (0 == strncmp(gszSynoHWVersion, HW_DS1515, strlen(HW_DS1515))) {
		ALPINE_ds1515_GPIO_init(&generic_gpio);
		printk("Synology %s GPIO Init\n", HW_DS1515);
	} else if (0 == strncmp(gszSynoHWVersion, HW_DS715, strlen(HW_DS715))) {
		ALPINE_2bay_GPIO_init(&generic_gpio);
		printk("Synology %s GPIO Init\n", HW_DS715);
	} else if (0 == strncmp(gszSynoHWVersion, HW_DS215p, strlen(HW_DS215p))) {
		ALPINE_2bay_GPIO_init(&generic_gpio);
		printk("Synology %s GPIO Init\n", HW_DS215p);
	} else if (0 == strncmp(gszSynoHWVersion, HW_DS416, strlen(HW_DS416))) {
		ALPINE_ds416_GPIO_init(&generic_gpio);
		printk("Synology %s GPIO Init\n", HW_DS416);
	} else {
		ALPINE_default_GPIO_init(&generic_gpio);
		printk("Not supported hw version!\n");
	}
}
#endif  
