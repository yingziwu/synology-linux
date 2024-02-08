#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#ifdef MY_ABC_HERE
#else
#ifndef _ASM_X86_CMDLINE_H
#define _ASM_X86_CMDLINE_H

int cmdline_find_option_bool(const char *cmdline_ptr, const char *option);
int cmdline_find_option(const char *cmdline_ptr, const char *option,
			char *buffer, int bufsize);

#endif /* _ASM_X86_CMDLINE_H */
#endif	/* MY_ABC_HERE */
