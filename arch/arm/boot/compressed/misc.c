#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
unsigned int __machine_arch_type;

#ifdef MY_ABC_HERE
#define _LINUX_STRING_H_
#endif

#include <linux/compiler.h>	 
#include <linux/types.h>	 
#include <linux/stddef.h>	 
#include <asm/string.h>
#ifdef MY_ABC_HERE
#include <linux/linkage.h>

#include <asm/unaligned.h>
#endif

#ifdef STANDALONE_DEBUG
#define putstr printf
#else

static void putstr(const char *ptr);

#include <mach/uncompress.h>

#ifdef CONFIG_DEBUG_ICEDCC

#ifdef CONFIG_CPU_V6

static void icedcc_putc(int ch)
{
	int status, i = 0x4000000;

	do {
		if (--i < 0)
			return;

		asm volatile ("mrc p14, 0, %0, c0, c1, 0" : "=r" (status));
	} while (status & (1 << 29));

	asm("mcr p14, 0, %0, c0, c5, 0" : : "r" (ch));
}
#elif defined(CONFIG_CPU_XSCALE)

static void icedcc_putc(int ch)
{
	int status, i = 0x4000000;

	do {
		if (--i < 0)
			return;

		asm volatile ("mrc p14, 0, %0, c14, c0, 0" : "=r" (status));
	} while (status & (1 << 28));

	asm("mcr p14, 0, %0, c8, c0, 0" : : "r" (ch));
}

#else

static void icedcc_putc(int ch)
{
	int status, i = 0x4000000;

	do {
		if (--i < 0)
			return;

		asm volatile ("mrc p14, 0, %0, c0, c0, 0" : "=r" (status));
	} while (status & 2);

	asm("mcr p14, 0, %0, c1, c0, 0" : : "r" (ch));
}

#endif

#define putc(ch)	icedcc_putc(ch)
#define flush()	do { } while (0)
#endif

#ifndef CONFIG_ARCH_FEROCEON
static void putstr(const char *ptr)
{
	char c;

	while ((c = *ptr++) != '\0') {
		if (c == '\n')
			putc('\r');
		putc(c);
	}

	flush();
}
#endif

#endif

#define __ptr_t void *

#define memzero(s,n) __memzero(s,n)

void __memzero (__ptr_t s, size_t n)
{
	union { void *vp; unsigned long *ulp; unsigned char *ucp; } u;
	int i;

	u.vp = s;

	for (i = n >> 5; i > 0; i--) {
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
	}

	if (n & 1 << 4) {
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
		*u.ulp++ = 0;
	}

	if (n & 1 << 3) {
		*u.ulp++ = 0;
		*u.ulp++ = 0;
	}

	if (n & 1 << 2)
		*u.ulp++ = 0;

	if (n & 1 << 1) {
		*u.ucp++ = 0;
		*u.ucp++ = 0;
	}

	if (n & 1)
		*u.ucp++ = 0;
}

static inline __ptr_t memcpy(__ptr_t __dest, __const __ptr_t __src,
			    size_t __n)
{
	int i = 0;
	unsigned char *d = (unsigned char *)__dest, *s = (unsigned char *)__src;

	for (i = __n >> 3; i > 0; i--) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1 << 2) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1 << 1) {
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1)
		*d++ = *s++;

	return __dest;
}

#ifndef MY_ABC_HERE
#define OF(args)  args
#endif
#define STATIC static

#ifndef MY_ABC_HERE
typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;

#define WSIZE 0x8000		 
				 
static uch *inbuf;		 
static uch window[WSIZE];	 

static unsigned insize;		 
static unsigned inptr;		 
static unsigned outcnt;		 

#define ASCII_FLAG   0x01  
#define CONTINUATION 0x02  
#define EXTRA_FIELD  0x04  
#define ORIG_NAME    0x08  
#define COMMENT      0x10  
#define ENCRYPTED    0x20  
#define RESERVED     0xC0  

#define get_byte()  (inptr < insize ? inbuf[inptr++] : fill_inbuf())
#endif

#ifdef DEBUG
#  define Assert(cond,msg) {if(!(cond)) error(msg);}
#  define Trace(x) fprintf x
#  define Tracev(x) {if (verbose) fprintf x ;}
#  define Tracevv(x) {if (verbose>1) fprintf x ;}
#  define Tracec(c,x) {if (verbose && (c)) fprintf x ;}
#  define Tracecv(c,x) {if (verbose>1 && (c)) fprintf x ;}
#else
#  define Assert(cond,msg)
#  define Trace(x)
#  define Tracev(x)
#  define Tracevv(x)
#  define Tracec(c,x)
#  define Tracecv(c,x)
#endif

#ifndef MY_ABC_HERE
static int  fill_inbuf(void);
static void flush_window(void);
#endif
static void error(char *m);

extern char input_data[];
extern char input_data_end[];

#ifdef MY_ABC_HERE
static unsigned char *output_data;
static unsigned long output_ptr;
#else
static uch *output_data;
static ulg output_ptr;
static ulg bytes_out;
#endif

static void error(char *m);

static void putstr(const char *);

#ifdef MY_ABC_HERE
static unsigned long free_mem_ptr;
static unsigned long free_mem_end_ptr;
#else
extern int end;
static ulg free_mem_ptr;
static ulg free_mem_end_ptr;
#endif

#ifdef STANDALONE_DEBUG
#define NO_INFLATE_MALLOC
#endif

#define ARCH_HAS_DECOMP_WDOG

#ifdef MY_ABC_HERE
#ifdef CONFIG_KERNEL_GZIP
#include "../../../../lib/decompress_inflate.c"
#endif

#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif

#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif
#else
#include "../../../../lib/inflate.c"

int fill_inbuf(void)
{
	if (insize != 0)
		error("ran out of input data");

	inbuf = input_data;
	insize = &input_data_end[0] - &input_data[0];

	inptr = 1;
	return inbuf[0];
}

void flush_window(void)
{
	ulg c = crc;
	unsigned n;
	uch *in, *out, ch;

	in = window;
	out = &output_data[output_ptr];
	for (n = 0; n < outcnt; n++) {
		ch = *out++ = *in++;
		c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
	}
	crc = c;
	bytes_out += (ulg)outcnt;
	output_ptr += (ulg)outcnt;
	outcnt = 0;
	putstr(".");
}

#endif
#ifndef arch_error
#define arch_error(x)
#endif

static void error(char *x)
{
	arch_error(x);

	putstr("\n\n");
	putstr(x);
	putstr("\n\n -- System halted");

	while(1);	 
}

#ifdef MY_ABC_HERE
asmlinkage void __div0(void)
{
        error("Attempting division by 0!");
}
#endif

#ifndef STANDALONE_DEBUG

#ifdef MY_ABC_HERE
unsigned long
decompress_kernel(unsigned long output_start, unsigned long free_mem_ptr_p,
                unsigned long free_mem_ptr_end_p,
                int arch_id)
#else
ulg
decompress_kernel(ulg output_start, ulg free_mem_ptr_p, ulg free_mem_ptr_end_p,
		  int arch_id)
#endif
{
#ifdef MY_ABC_HERE
	unsigned char *tmp;

	output_data             = (unsigned char *)output_start;
#else
	output_data		= (uch *)output_start;	 
#endif
	free_mem_ptr		= free_mem_ptr_p;
	free_mem_end_ptr	= free_mem_ptr_end_p;
	__machine_arch_type	= arch_id;

	arch_decomp_setup();

#ifdef MY_ABC_HERE
	tmp = (unsigned char *) (((unsigned long)input_data_end) - 4);
	output_ptr = get_unaligned_le32(tmp);
#else
	makecrc();
#endif

	putstr("Uncompressing Linux...");
#ifdef MY_ABC_HERE
	decompress(input_data, input_data_end - input_data,
				NULL, NULL, output_data, NULL, error);
#else
	gunzip();
#endif

	putstr(" done, booting the kernel.\n");
	return output_ptr;
}
#else

char output_buffer[1500*1024];

int main()
{
	output_data = output_buffer;

#ifndef MY_ABC_HERE
	makecrc();
#endif
	putstr("Uncompressing Linux...");
#ifndef MY_ABC_HERE
	gunzip();
#endif
#ifdef MY_ABC_HERE
	decompress(input_data, input_data_end - input_data,
					NULL, NULL, output_data, NULL, error);
#endif
	putstr("done.\n");
	return 0;
}
#endif
	