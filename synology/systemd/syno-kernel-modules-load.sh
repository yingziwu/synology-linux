#!/bin/sh

check_feature() # $1: key
{
	[ "$(get_key_value "/etc.defaults/synoinfo.conf" "${1:-}")" = "yes" ]
}

probe_modules() # $@: module list
{
	for _m in "$@"; do
		modprobe "$_m"
	done
}

# load synobios
modprobe synobios system_mode=1
/bin/mknod /dev/synobios c 201 0 2>/dev/null

# load usbhid for bromolow
if check_feature "support_dual_head"; then
	probe_modules usblp hid usbhid hid-generic
fi

# load syno_hddmon
if check_feature "HddEnableDynamicPower"; then
	probe_modules syno_hddmon
fi

# load syno_smbus_hddmon
if check_feature "SMBusHddEnable"; then
	probe_modules syno_smbus_hddmon
fi

# load intel aesni
if check_feature "support_aesni_intel"; then
	probe_modules ablk_helper gf128mul lrw glue_helper aesni-intel
fi

# load lp3943
if check_feature "support_leds_lp3943"; then
	probe_modules i2c-i801 leds-lp3943
fi

# load atemga1608
if check_feature "support_leds_atmega1608"; then
    probe_modules leds-atmega1608
fi

# load IPMI
if check_feature "support_ipmi"; then
	probe_modules ipmi_msghandler ipmi_devintf ipmi_si
fi

# load ACM
if check_feature "support_acm"; then
	probe_modules cdc-acm
	mknod /dev/ttyACM0 c 166 0
fi

# load USB printer
if check_feature "support_printer"; then
	probe_modules usblp
fi
