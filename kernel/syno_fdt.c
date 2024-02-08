#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#include <linux/of.h>
#include <linux/syno_fdt.h>

int syno_pmbus_property_get(unsigned int *pmbus_property, const char *property_name, int index)
{
    int iRet = -1;
	if (NULL == pmbus_property || NULL == property_name) {
		goto END;
	}

    // if property name not exist, do nothing but return 0
    if (of_find_property(of_root, property_name, NULL)) {
        of_property_read_u32_index(of_root, property_name, index, pmbus_property);
    }

	iRet = 0;
END:
	return iRet;
}
EXPORT_SYMBOL(syno_pmbus_property_get);

#endif /* MY_ABC_HERE */
