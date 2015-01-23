/* Author: pinghaiyuan@gmail.com
 Date: 2013.04.01
 File: main.c
 Version: 0.01
 */

#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>


#define PROC_CFG_INFO "cfginfo"
#define PAGE_ORDER   8
#define PAGES_NUMBER 256
#ifndef VM_RESERVED
#define VM_RESERVED 	0x00080000
#endif

void cfi_check_test(void);

struct proc_dir_entry *proc_cfg_info;

unsigned long kernel_memaddr = 0;
unsigned long kernel_memsize = 0;


/* data structures and functions for enforceing CFI */
typedef struct cfg_file_header{
	char szFlag[4];
	unsigned long cfg_srcbmp;
	unsigned long cfg_edge_hashmap;
	unsigned long nPrime;
}cfg_file_header;

typedef struct cfg_head_info{
	unsigned long vaImageBase; /* fix me */
	unsigned long cfg_srcbmp;
	unsigned long cfg_edge_hashmap;
	unsigned long nPrime;	
	unsigned long cfg_eptbmp;
}cfg_head_info;

typedef struct cfg_edge_hashmap {
	unsigned long lFrm;
	unsigned long tDst;
	unsigned long lNxt;
}cfg_edge_hashmap;

typedef struct cfg_dst{
	u16	nSize;
	u8	cFlag;
	u8	cInstType;
	unsigned long arDst[1];
}cfg_dst;

/* check integrity of source address */
inline int cfi_check_source(unsigned long cfg_srcbmp, unsigned long from)
{
	unsigned long oftBit, *oftDwrd;
	
	oftDwrd = (unsigned long*)(cfg_srcbmp + ((from >> 5) << 2));
	oftBit = from & 0x1F;

	//check source bitmap
	return test_bit(oftBit, oftDwrd);
}

/* check integrity of source address */
inline int cfi_check_destination(struct cfg_dst * tDst, unsigned long lTo)
{
	unsigned long lMask = tDst->arDst[lTo % tDst->nSize];

	return ((lTo & lMask) == lTo);
}

/* check integrity of entry-point */
inline int cfi_check_entry(unsigned long cfg_entrybmp, unsigned long to)
{
	return cfi_check_source(cfg_entrybmp, to);
}

/* get destination addresses a give source address */
struct cfg_dst* cfi_check_edge(struct cfg_edge_hashmap *edgeto, unsigned long nPrime, unsigned long lFrm)
{
	unsigned long nIdx = lFrm % nPrime;

	while (edgeto[nIdx].lFrm != lFrm) {
		nIdx = edgeto[nIdx].lNxt;
		if (nIdx == 0) {
			printk("Corrputed cfg file\n");
			return NULL;
		}
	}
	return (struct cfg_dst*)((char*)edgeto + edgeto[nIdx].tDst);
}

/* check integrity of edge */
int check_control_flow_transfer(struct cfg_head_info* hdrFrm, struct cfg_head_info *hdrTo, unsigned long lFrm, unsigned long lTo)
{
	struct cfg_dst *tDst;

	if (!cfi_check_source(hdrFrm->cfg_srcbmp, lFrm))
		return false;

	tDst = cfi_check_edge((struct cfg_edge_hashmap*)hdrFrm->cfg_edge_hashmap, hdrFrm->nPrime, lFrm);
	if (tDst == NULL)
		return false;

	if ((hdrFrm != hdrTo) && (tDst->cFlag)) {
		if (hdrTo != NULL)	
			return cfi_check_destination(tDst, lTo);
		else 
			return true;
	}
	else {
		return cfi_check_destination(tDst, lTo);
	}
}


/* We can not do read and write operations without these functions. */
ssize_t shm_read(struct file*filp, char *buf, size_t len, loff_t *off)
{
	unsigned long addr = kernel_memaddr;
	
	if (len < sizeof(unsigned long))
		return 0;
	/* ret contains the amount of chars wasn't successfully written to `buf` */
	copy_to_user(buf, (void*)&addr,  sizeof(unsigned long));
	printk(KERN_INFO "%s, %lx;\n", __FUNCTION__, addr);
	*off = sizeof(unsigned long);
	return 0;
}

void reset_cfg_head_info(struct cfg_head_info*cfg_hdr, struct cfg_file_header *hdr) 
{
	unsigned long lBase = (unsigned long)hdr;

	printk(KERN_INFO "hello %s, %lx\n", hdr->szFlag, lBase);
	cfg_hdr->vaImageBase = 0x8048000;
	cfg_hdr->cfg_srcbmp = lBase + hdr->cfg_srcbmp;
	cfg_hdr->cfg_edge_hashmap = lBase + hdr->cfg_edge_hashmap;
	cfg_hdr->nPrime = hdr->nPrime;
	cfg_hdr->cfg_eptbmp = cfg_hdr->cfg_srcbmp;
}

ssize_t shm_write(struct file*filp, const char*buf, size_t len, loff_t *off)
{	
	static unsigned long mem_ptr = 0, mem_size = 0;
	char szFlag[16];
	int bResetHdr = 0;

	if ((len > 4) && !copy_from_user((void*)szFlag, buf, 4) && (strcmp(szFlag, "cfi") == 0 ))  {
		printk(KERN_INFO "%s\n", szFlag);
		mem_ptr = kernel_memaddr + PAGE_SIZE;
		mem_size = kernel_memsize - PAGE_SIZE;
		bResetHdr = 1;
	}	

	if (len > mem_size)
		len = mem_size;
	if (copy_from_user((void*)mem_ptr, buf, len))
		return -EFAULT;
	if (bResetHdr)
		reset_cfg_head_info( (struct cfg_head_info*)kernel_memaddr, (struct cfg_file_header *) mem_ptr);

	mem_ptr +=  len;
	mem_size -= len;

	return len;
}

static const struct file_operations dbg_fops = {
	.owner = THIS_MODULE,
	.read = shm_read,
	.write = shm_write,
};

void create_shm_proc(void)
{
	/* consistency with the read/write privileges from user application */
	proc_cfg_info = proc_create(PROC_CFG_INFO, 0666, NULL, &dbg_fops);
}

void destroy_shm_proc(void)
{
	remove_proc_entry(PROC_CFG_INFO, NULL);
	//remove_proc_entry(proc_cfi_info, NULL);
}

int create_shm_mem(void)
{
	long tick;

	kernel_memaddr =__get_free_pages(GFP_KERNEL, PAGE_ORDER);
	if(!kernel_memaddr) {
		printk("alloc kernel memory failed!\n");
		return -1;
	}
	/* make sure the page not be swappered out. Invoked for every page */
	for (tick = 0; tick < PAGES_NUMBER; tick++)
		SetPageReserved(virt_to_page(kernel_memaddr + PAGE_SIZE * tick)); 

	kernel_memsize = PAGES_NUMBER * PAGE_SIZE;
	printk("The kernel mem addr=%lx, size=%lx\n",__pa(kernel_memaddr), kernel_memsize);

	return 0;
}

void destroy_shm_mem(void)
{
	long tick;
	
	if (!kernel_memaddr)
		return;

	//printk("The string written by user is: %s\n", (unsigned char *)kernel_memaddr);
	for (tick = 0; tick < PAGES_NUMBER; tick++)
		ClearPageReserved(virt_to_page(kernel_memaddr + PAGE_SIZE * tick));

	free_pages(kernel_memaddr, PAGE_ORDER);
}

void cfi_check_test(void)
{
#define BASE_ADDR  0x8048000
	unsigned long lFrm = 0x8048A5B - BASE_ADDR, lTo = 0x809074E - BASE_ADDR;
	int flag;
	struct cfg_head_info* cfg_hdr = (struct cfg_head_info*) kernel_memaddr;
	
	flag = check_control_flow_transfer(cfg_hdr, cfg_hdr, lFrm, lTo);
	if (flag)
		printk(KERN_INFO "I find it\n");
	else
		printk(KERN_INFO "invalid");
}

//part 3.
//module_init() and module_exit()
static int __init
monitor_init(void)
{
	printk(KERN_INFO "Load cfi_monitor kernel module.\n");
	if (create_shm_mem()) 
		return -1;
		
	create_shm_proc();
	return 0;
}

static void __exit
monitor_cleanup(void)
{
	destroy_shm_proc();
	destroy_shm_mem();
	printk(KERN_INFO "Unload cfi_monitor kernel module.\n");
}

module_init( monitor_init);
module_exit( monitor_cleanup);
MODULE_LICENSE("GPL");
