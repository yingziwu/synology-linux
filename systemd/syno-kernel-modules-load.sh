#!/bin/sh

SYNOINFO_DEF="/etc.defaults/synoinfo.conf"
# load usbhid for bromolow
SUPPORT_DUAL_HEAD=`get_key_value $SYNOINFO_DEF support_dual_head`
if [ "$SUPPORT_DUAL_HEAD" != "yes" ]; then
	modprobe usblp
	modprobe hid
	modprobe usbhid
	modprobe hid-generic
fi

# load synobios
modprobe synobios system_mode=1
/bin/mknod /dev/synobios c 201 0 2>/dev/null

# load syno_hddmon
SUPPORT_HDD_DYNAMIC_POWER=`get_key_value $SYNOINFO_DEF HddEnableDynamicPower`
if [ "$SUPPORT_HDD_DYNAMIC_POWER" = "yes" ]; then
	modprobe syno_hddmon
fi

# load intel aesni
SUPPORT_AESNI_INTEL=`get_key_value $SYNOINFO_DEF support_aesni_intel`
if [ "$SUPPORT_AESNI_INTEL" == "yes" ]; then
	modprobe ablk_helper
	modprobe gf128mul
	modprobe lrw
	modprobe glue_helper
	modprobe aesni-intel
fi

# load lp3943
SUPPORT_LP3943=`get_key_value $SYNOINFO_DEF support_leds_lp3943`
if [ "$SUPPORT_LP3943" == "yes" ]; then
	modprobe i2c-i801
	modprobe leds-lp3943
fi

# load IPMI
SUPPORT_IPMI=`get_key_value $SYNOINFO_DEF support_ipmi`
if [ "$SUPPORT_IPMI" == "yes" ]; then
	modprobe ipmi_msghandler
	modprobe ipmi_devintf
	modprobe ipmi_si
fi

# load ACM
SUPPORT_ACM=`get_key_value $SYNOINFO_DEF support_acm`
if [ "$SUPPORT_ACM" == "yes" ]; then
	modprobe cdc-acm
	if [ ! -e /dev/ttyACM0 ]; then
		/bin/mknod /dev/ttyACM0 c 166 0
	fi
fi
