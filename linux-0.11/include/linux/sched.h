#ifndef _SCHED_H
#define _SCHED_H

#define NR_TASKS 64
#define HZ 100

#define FIRST_TASK task[0]
#define LAST_TASK task[NR_TASKS-1]

#include <linux/head.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <signal.h>

#if (NR_OPEN > 32)
#error "Currently the close-on-exec-flags are in one word, max 32 files/proc"
#endif

#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define TASK_ZOMBIE		3
#define TASK_STOPPED		4

#ifndef NULL
#define NULL ((void *) 0)
#endif

extern int copy_page_tables(unsigned long from, unsigned long to, long size);
extern int free_page_tables(unsigned long from, unsigned long size);

extern void sched_init(void);
extern void schedule(void);
extern void trap_init(void);
extern void panic(const char * str);
extern int tty_write(unsigned minor,char * buf,int count);

typedef int (*fn_ptr)();

struct i387_struct {
	long	cwd;
	long	swd;
	long	twd;
	long	fip;
	long	fcs;
	long	foo;
	long	fos;
	long	st_space[20];	/* 8*10 bytes for each FP-reg = 80 bytes */
};

struct tss_struct {
	long	back_link;	/* 16 high bits zero */
	long	esp0;
	long	ss0;		/* 16 high bits zero */
	long	esp1;
	long	ss1;		/* 16 high bits zero */
	long	esp2;
	long	ss2;		/* 16 high bits zero */
	long	cr3;
	long	eip;
	long	eflags;
	long	eax,ecx,edx,ebx;
	long	esp;
	long	ebp;
	long	esi;
	long	edi;
	long	es;		/* 16 high bits zero */
	long	cs;		/* 16 high bits zero */
	long	ss;		/* 16 high bits zero */
	long	ds;		/* 16 high bits zero */
	long	fs;		/* 16 high bits zero */
	long	gs;		/* 16 high bits zero */
	long	ldt;		/* 16 high bits zero */
	long	trace_bitmap;	/* bits: trace 0, bitmap 16-31 */
	struct i387_struct i387;
};

struct task_struct {
/* these are hardcoded - don't touch */
	long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	long counter;
	long priority;
	long signal;
	struct sigaction sigaction[32];
	long blocked;	/* bitmap of masked signals */
/* various fields */
	int exit_code;
	unsigned long start_code,end_code,end_data,brk,start_stack;
	long pid,father,pgrp,session,leader;
	unsigned short uid,euid,suid;
	unsigned short gid,egid,sgid;
	long alarm;
	long utime,stime,cutime,cstime,start_time;
	unsigned short used_math;
/* file system info */
	int tty;		/* -1 if no tty, so it must be signed */
	unsigned short umask;
	struct m_inode * pwd;
	struct m_inode * root;
	struct m_inode * executable;
	unsigned long close_on_exec;
	struct file * filp[NR_OPEN];
/* ldt for this task 0 - zero 1 - cs 2 - ds&ss */
	struct desc_struct ldt[3];
/* tss for this task */
	struct tss_struct tss;
};

/*
 *  INIT_TASK is used to set up the first task table, touch at
 * your own risk!. Base=0, limit=0x9ffff (=640kB)
 */
#define INIT_TASK \
/* state etc */	{ 0,--state
				 15,--counter
				 15, \--priority
/* signals */	0,--signal
				{{},}, 
		--struct sigaction {
			void (*sa_handler)(int);
			sigset_t sa_mask;
			int sa_flags;
			void (*sa_restorer)(void);
	      };
				0, \--blocked
/* ec,brk... */	0,0,0,0,0,0, \ --int exit_code; unsigned long start_code,end_code,end_data,brk,start_stack; struct m_inode * root; 
/* pid etc.. */	0,-1,0,0,0, \ --long pid,father,pgrp,session,leader;
/* uid etc */	0,0,0,0,0,0, \ --unsigned short uid,euid,suid; unsigned short gid,egid,sgid;
/* alarm */	0,0,0,0,0,0, \ --long alarm; long utime,stime,cutime,cstime,start_time;
/* math */	0, \ --unsigned short used_math;
/* fs info */	-1,0022,NULL,NULL,NULL,0, \ --int tty; unsigned short umask; struct m_inode * pwd; struct m_inode * root; struct m_inode * executable; unsigned long close_on_exec;
/* filp */	{NULL,}, \ struct file * filp[NR_OPEN];
 //struct desc_struct ldt[3];
	{ \
		{0,0}, \
/* ldt */	{0x9f,0xc0fa00}, \
		{0x9f,0xc0f200}, \
	}, \
	//struct tss_struct tss;
/*tss*/	{0,                     --long	back_link;	/* 16 high bits zero */
     PAGE_SIZE+(long)&init_task,--long	esp0;
	 0x10,0,0,0,0,--long	ss0;/* 16 high bits zero */ long	esp1; long	ss1;/* 16 high bits zero */  long	esp2; long	ss2;/* 16 high bits zero */
	 (long)&pg_dir,\--long	cr3;
	 0,0,0,0,0,0,0,0, \--long	eip; long	eflags; long	eax,ecx,edx,ebx; long	esp; long	ebp;
	 0,0,0x17,0x17, --long	esi;long	edi;long	es;		/* 16 high bits zero */ long	cs;		/* 16 high bits zero */
	 0x17,0x17,0x17,0x17, \--long	ss;	/* 16 high bits zero */ long	ds;	/* 16 high bits zero */ long	fs;	/* 16 high bits zero */  long	gs;	/* 16 high bits zero */
	 _LDT(0),0x80000000, \--long	ldt;		/* 16 high bits zero */ --long	trace_bitmap;	/* bits: trace 0, bitmap 16-31 */
		{} \ --struct i387_struct i387;
	}, \
}
	

typedef struct desc_struct {
	unsigned long a,b;
} desc_table[256];

extern struct task_struct *task[NR_TASKS];
extern struct task_struct *last_task_used_math;
extern struct task_struct *current;
extern long volatile jiffies;
extern long startup_time;

#define CURRENT_TIME (startup_time+jiffies/HZ)

extern void add_timer(long jiffies, void (*fn)(void));
extern void sleep_on(struct task_struct ** p);
extern void interruptible_sleep_on(struct task_struct ** p);
extern void wake_up(struct task_struct ** p);

/*
 * Entry into gdt where to find first TSS. 0-nul, 1-cs, 2-ds, 3-syscall
 * 4-TSS0, 5-LDT0, 6-TSS1 etc ...
 */
#define FIRST_TSS_ENTRY 4
#define FIRST_LDT_ENTRY (FIRST_TSS_ENTRY+1)
#define _TSS(n) ((((unsigned long) n)<<4)+(FIRST_TSS_ENTRY<<3))
#define _LDT(n) ((((unsigned long) n)<<4)+(FIRST_LDT_ENTRY<<3))
#define ltr(n) __asm__("ltr %%ax"::"a" (_TSS(n)))
#define lldt(n) __asm__("lldt %%ax"::"a" (_LDT(n)))
#define str(n) \
__asm__("str %%ax\n\t" \
	"subl %2,%%eax\n\t" \
	"shrl $4,%%eax" \
	:"=a" (n) \
	:"a" (0),"i" (FIRST_TSS_ENTRY<<3))
/*
 *	switch_to(n) should switch tasks to task nr n, first
 * checking that n isn't the current task, in which case it does nothing.
 * This also clears the TS-flag if the task we switched to has used
 * tha math co-processor latest.
 */
#define switch_to(n) {\
struct {long a,b;} __tmp; \
__asm__("cmpl %%ecx,_current\n\t" \
	"je 1f\n\t" \
	"movw %%dx,%1\n\t" \
	"xchgl %%ecx,_current\n\t" \
	"ljmp %0\n\t" \
	"cmpl %%ecx,_last_task_used_math\n\t" \
	"jne 1f\n\t" \
	"clts\n" \
	"1:" \
	::"m" (*&__tmp.a),"m" (*&__tmp.b), \
	"d" (_TSS(n)),"c" ((long) task[n])); \
}

#define PAGE_ALIGN(n) (((n)+0xfff)&0xfffff000)
// p->ldt[1],new_code_base {7654,3210}
#define _set_base(addr=p->ldt[1],base=new_code_base=0x4000000) \
__asm__("movw %%dx,%0\n\t" \ // 0x400 0000 的低16位赋值给  (*((addr)+2)) = 00000000 00000000
	"rorl $16,%%edx\n\t" \ edx = 00000000 00000000 00000100 00000000
	"movb %%dl,%1\n\t" \ dl = 00000000 = (*((addr)+4))
	"movb %%dh,%2" \  dh =  00000100 = (*((addr)+7))
	::"m" (*((addr)+2)), \ // 0%
	  "m" (*((addr)+4)), \ // 1%
	  "m" (*((addr)+7)), \ // 2%
	  "d" (base) \ // edx
	:"dx")

#define _set_limit(addr,limit) \
__asm__("movw %%dx,%0\n\t" \
	"rorl $16,%%edx\n\t" \
	"movb %1,%%dh\n\t" \
	"andb $0xf0,%%dh\n\t" \
	"orb %%dh,%%dl\n\t" \
	"movb %%dl,%1" \
	::"m" (*(addr)), \
	  "m" (*((addr)+6)), \
	  "d" (limit) \
	:"dx")

#define set_base(ldt,base) _set_base( ((char *)&(ldt)) , base )
#define set_limit(ldt,limit) _set_limit( ((char *)&(ldt)) , (limit-1)>>12 )

 //struct desc_struct ldt[3];
	{ \
		{0,0}, \
/* ldt */	{0x9f,0xc0fa00}, \｛00000000-4 00000000-5 00000000-6 10011111-7，00000000-0 11000000-1 11111010-2 00000000-3｝
		{0x9f,0xc0f200}, \
	}, \

 ｛ 00000000-0 11000000-1 11111010-2 00000000-3
    00000000-4 00000000-5 00000000-6 10011111-7，｝

#define _get_base(addr=current->ldt[1]-8字节) ({\
unsigned long __base; \
__asm__("movb %3,%%dh\n\t" \ dh= 00000000
	"movb %2,%%dl\n\t" \ dl=00000000
	"shll $16,%%edx\n\t" \ edx = 00000000 00000000 
	"movw %1,%%dx" \ edx = 00000000 00000000 00000000 00000000
	:"=d" (__base) \   // edx  0%
	:"m" (*((addr)+2)), \ // %1
	 "m" (*((addr)+4)), \ // %2
	 "m" (*((addr)+7))); \ // %3
	__base;// %4
})
0000000011000000 0000 1100 0000 0000
#define get_base(ldt) _get_base( ((char *)&(ldt)) )

#define get_limit(segment) ({ \
unsigned long __limit; \
__asm__("lsll %1,%0\n\t //llsl 是Load Segment Limit缩写。从指定段描述符中取出分散的限长比特位
						//，拼成完整的限长值放入制定寄存器中,所得的段限长是实际字节数减1
 ncl %0"  // 限长加1
:"=r" (__limit) 0%
:"r" (segment)); \  1%
__limit; 2%
})

#endif
