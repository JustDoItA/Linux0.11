/*
 *  linux/mm/memory.c
 *
 *  (C) 1991  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

#include <signal.h>

#include <asm/system.h>

#include <linux/sched.h>
#include <linux/head.h>
#include <linux/kernel.h>

volatile void do_exit(long code);

static inline volatile void oom(void)
{
	printk("out of memory\n\r");
	do_exit(SIGSEGV);
}

#define invalidate() \
__asm__("movl %%eax,%%cr3"::"a" (0))

/* these are not to be changed without changing head.s etc */
#define LOW_MEM 0x100000
#define PAGING_MEMORY (15*1024*1024)
#define PAGING_PAGES (PAGING_MEMORY>>12)
#define MAP_NR(addr) (((addr)-LOW_MEM)>>12)
#define USED 100

#define CODE_SPACE(addr) ((((addr)+4095)&~4095) < \
current->start_code + current->end_code)

static long HIGH_MEMORY = 0;

#define copy_page(from,to) \
__asm__("cld ; rep ; movsl"::"S" (from),"D" (to),"c" (1024):"cx","di","si")

static unsigned char mem_map [ PAGING_PAGES ] = {0,};

/*
 * Get physical address of first (actually last :-) free page, and mark it
 * used. If no free pages left, return 0.
 */
unsigned long get_free_page(void)
{
register unsigned long __res asm("ax");

//原文链接：https://blog.csdn.net/linpeng12358/article/details/41017961
__asm__("std ; repne ; scasb\n\t" //循环比较，找出mem_map[i]==0的页; std设置DF=1，所以scasb执行递减操作，
                                  //涉及寄存器al, ecx, es:(e)di三个寄存器，在函数尾部的定义中
								  //  即有
										//al       = 0;    //如果mem_map[i] == 0,表示为空闲页，否则为已分配占用,al保存0值，用于比较
										//ecx    = PAGING_PAGES; //主内存页表个数

										//es:di =  (mem_map+PAGING_PAGES-1);   //内存管理数组最后一项
										//这句指令的意思是从数组mem_map[0..(PAGING_PAGES-1)]的最后一项
										//mem_map[PAGING_PAGES-1]开始，比较mem_map[i]是否等于0(0值保存在al寄存器中);
										//每比较一次,es:di值减1,如果不相等,es:di值减1,即mem_map[i--],继续比较,直到ecx == 0;
										//如果相等，则跳出循环

	"jne 1f\n\t"  // 如果mem_map[0..(PAGING_PAGES-1)]均不等于0,跳转到标签1f处执行,Nf表示向前标签,Nb表示向后标签,N是取值1-10的十进制数字
	"movb $1,1(%%edi)\n\t" 	 // mem_map[i]==0是mem_map[0..(PAGING_PAGES-1)]中逆序第一个找到的等于0的目标，
						    //  将edi的最低位置1，即mem_map[i]=1,标志为该页已被占用，不是空闲位
	"sall $12,%%ecx\n\t"  //  此时ecx保存的是mem_map[i]的下标i,即相对页面数,
							// 举例:
							// 假设mem_map[0..(PAGING_PAGES-1)]最后一个参数
							// mem_map[PAGING_PAGES-1] == 0，即i == (PAGING_PAGES-1),
							// 所以此时*ecx == PAGING_PAGES-1;
							// 此时相对页面地址是4k*(PAGING_PAGES-1),
							// 每一页1024个4字节物理页,左移12位等于4096(2的12次方),
	"addl %2,%%ecx\n\t" // 加上低端内存地址，得到实际物理地址
                       // %2等于LOW_MEM，在如下语句中定义
                       //"0" (0),"i" (LOW_MEM),"c" (PAGING_PAGES),
                       //提问：
                       //为什么4k*(PAGING_PAGES-1)不是实际物理地址呢？
                       //答案是初始化的时候如下:
                       //mem_map[0..(PAGING_PAGES)]是主内存管理数组
                       //管理的只是1-16M的空间，即PAGING_MEMORY = ((16-1)*1024*1024)
                       //不包括0-1M(0-1M,其实是0-640K已经被内核占用)
	"movl %%ecx,%%edx\n\t" //将ecx寄存器的值保存到edx寄存器中，即将实际物理地址保存到edx寄存器中。
	"movl $1024,%%ecx\n\t" // 将1024保存到ecx寄存器中，因为每一页占用4096字节(4K),实际物理内存,每项占用4字节,有1024项。
	"leal 4092(%%edx),%%edi\n\t" // 因为按照4字节对齐，所以每项占用4字节,
                                 // 取当前物理页最后一项4096 = 4096-4 = 1023*4 = (1024-1)*4 。
                                 // 将该物理页面的末端保存在edi寄存器中,
                                 // 即ecx+4092处的地址保存在edi寄存器中。
	"rep ; stosl\n\t" //从ecx+4092处开始，反方向，步进4，重复1024次，
					  // 将该物理页1024项全部填入eax寄存器的值，
					  // 在如下代码定义中，eax初始化为0(al=0,eax =0,ax =0)
					  //  :"0" (0),"i" (LOW_MEM),"c" (PAGING_PAGES),
					  //   所以该物理页1024项全部清零。
	"movl %%edx,%%eax\n" // 将该物理页面起始地址放入eax寄存器中，
					  // Intel的EABI规则中，
					  //  eax寄存器用于保存函数返回值	
	"1:"  //标签1，用于"jne 1f\n\t"语句跳转返回0值，
			//注意：
				//eax寄存器只在"movl %%edx,%%eax\n"中被赋值，
				//eax寄存器初始值是'0'，如果跳转到标签"1:"处，
				//返回值是0，表示没有空闲物理页。
	:"=a" (__res) 0% eax //输出寄存器列表，这里只有一个，其中a表示eax寄存器
	:"0" (0),     1% // "0"表示与上面同个位置的输出相同的寄存器，即"0"等于输出寄存器eax， 即eax既是输出寄存器，同时也是输入寄存器，
					 //   当然，在时间颗粒度最小的情况下，eax不能同时作为输入或者输出寄存器， 只能作为输入或者输出寄存器;
	 "i" (LOW_MEM), 2% //"i" (LOW_MEM)是%2，从输出寄存器到输入寄存器依次编号%0，%1，%2.....%N,
						//其中"i"表示立即数，不是edi的代号，edi的代号是"D";
	 "c" (PAGING_PAGES), 3%  ecx //表示将ecx寄存器存入PAGING_PAGES，ecx寄存器代号"c"。
	 "D" (mem_map+PAGING_PAGES-1) 4% edi // "D"使用edi寄存器，即edi寄存器保存的值是(mem_map+PAGING_PAGES-1)即%%edi = &mem_map[PAGING_PAGES-1]。
	:"di","cx","dx"); // 保留寄存器，告诉编译器"di","cx","dx"三个寄存器已经被分配， 在编译器编译中，不会将这三个寄存器分配为输入或者输出寄存器。
return __res;   //返回__res保存的值，相当于汇编的ret，隐含将eax寄存器返回，C语言中是显式返回。
}


//(1)std:主要将ESI and/or EDI方向设置为递减，对应cld(用于方向设置为递增)DF -> 1;
//(2)repne:
//(3)scasb: GNU汇编
    //在汇编语言中SCASB是一条字符串操作指令，源自“SCAN String Byte”的缩写。
	计算 AL - byte of [ES:EDI] , 设置相应的标志寄存器的值；
    修改寄存器EDI的值：如果标志DF为0，则 inc EDI；如果DF为1，则 dec EDI。
    SCASB指令常与循环指令REPZ/REPNZ合用。例如，REPNZ SCASB 语句表示当 寄存器ECX>0 且 标志寄存器ZF=0，则再执行一次SCASB指令。
    比较寄存器AL的值不相等则重复查找的字
//(4)sall
    如sall $12, %ecx.
    这个指令是算法左移,相当于c语言中的左移操作符<<.
    intel汇编指令中的SAL,(Shit Arithmetic left).
    根据AT&T的语法规则，
    因为是一个长型的操作(ecx),
    所以在intel汇编指令sal上加一个"l",
    即转换成sall。
//(5)stosl
    STOSL指令相当于将EAX中的值保存到ES:EDI指向的地址中，
    若设置了EFLAGS中的方向位置位(即在STOSL指令前使用STD指令)
    则EDI自减4，否则(使用CLD指令)EDI自增4。

/*
 * Free a page of memory at physical address 'addr'. Used by
 * 'free_page_tables()'
 */
void free_page(unsigned long addr)
{
	if (addr < LOW_MEM) return;
	if (addr >= HIGH_MEMORY)
		panic("trying to free nonexistent page");
	addr -= LOW_MEM;
	addr >>= 12;
	if (mem_map[addr]--) return; // 引用数减1
	mem_map[addr]=0;
	panic("trying to free free page");
}

/*
 * This function frees a continuos block of page tables, as needed
 * by 'exit()'. As does copy_page_tables(), this handles only 4Mb blocks.
 */
int free_page_tables(unsigned long from,unsigned long size)
{
	unsigned long *pg_table;
	unsigned long * dir, nr;

	if (from & 0x3fffff)
		panic("free_page_tables called with wrong alignment");
	if (!from)
		panic("Trying to free up swapper memory space");
	size = (size + 0x3fffff) >> 22;
	dir = (unsigned long *) ((from>>20) & 0xffc); /* _pg_dir = 0 */ // 页目录项*4=偏移地址
	for ( ; size-->0 ; dir++) {
		if (!(1 & *dir)) // 1 & *dir 获取*dir的P位,如果为0，表示该页目录项中没有需要释放的内存
			continue;
		pg_table = (unsigned long *) (0xfffff000 & *dir); // 获取页目录项||页表项
		for (nr=0 ; nr<1024 ; nr++) { // 依次循环释放目录项内容
			if (1 & *pg_table) // 1 & *pg_table 获取*pg_table的P位,如果为0，表示该页表项中没有需要释放的内存
				free_page(0xfffff000 & *pg_table); // mem_map[addr]-- mem_map指定的页表页面减1
			*pg_table = 0; // 清理页表项内容
			pg_table++; // 指向下一向
		}
		free_page(0xfffff000 & *dir); // mem_map[addr]-- mem_map指定页目录减1
		*dir = 0; // 清理页目录项内容
	}
	invalidate(); // 刷新页高速缓存
	return 0;
}

/*
 *  Well, here is one of the most complicated functions in mm. It
 * copies a range of linerar addresses by copying only the pages.
 * Let's hope this is bug-free, 'cause this one I don't want to debug :-)
 *
 * Note! We don't copy just any chunks of memory - addresses have to
 * be divisible by 4Mb (one page-directory entry), as this makes the
 * function easier. It's used only by fork anyway.
 *
 * NOTE 2!! When from==0 we are copying kernel space for the first
 * fork(). Then we DONT want to copy a full page-directory entry, as
 * that would lead to some serious memory waste - we just copy the
 * first 160 pages - 640kB. Even that is more than we need, but it
 * doesn't take any more memory - we don't copy-on-write in the low
 * 1 Mb-range, so the pages can be shared with the kernel. Thus the
 * special case for nr=xxxx.
 */
int copy_page_tables(unsigned long from,unsigned long to,long size)
{
	unsigned long * from_page_table;
	unsigned long * to_page_table;
	unsigned long this_page;
	unsigned long * from_dir, * to_dir;
	unsigned long nr;

	if ((from&0x3fffff) || (to&0x3fffff))
		panic("copy_page_tables called with wrong alignment");
	from_dir = (unsigned long *) ((from>>20) & 0xffc); /* _pg_dir = 0 */ // 这里面放着的是源的页目录表项的地址（线性地址）
	to_dir = (unsigned long *) ((to>>20) & 0xffc); //64M>>20 = 64 64先是逻辑地址。当前代码段数据段基地址为0，所以线性地址为64，100 0000代表第0目录项指向的页表的第0页
	size = ((unsigned) (size+0x3fffff)) >> 22;//size 兆单位
	for( ; size-->0 ; from_dir++,to_dir++) {
		if (1 & *to_dir)
			panic("copy_page_tables: already exist");
		if (!(1 & *from_dir))
			continue;
		from_page_table = (unsigned long *) (0xfffff000 & *from_dir); ff ff f0 00 //取源目录项中页表地址
		if (!(to_page_table = (unsigned long *) get_free_page())) // 为了保存目的目录项对应的页表，需要在主内存中申请1页空闲内存页。
																  // 返回新申请的一个页的基址，虽然返回的线性地址，然而这个线性地址刚好也就会等于这个页的物理地址
			return -1;	/* Out of memory, see freeing */
		*to_dir = ((unsigned long) to_page_table) | 7; // 这个过程就是让页目录表项的第16项指向这个新申请的页，把这个新申请的页当作页表来使用，
													   // 同时在这个页目录表里面是这个页表为存在、可读写
		nr = (from==0)?0xA0:1024; //针对当前处理的药物目录项对应的页表，设置需要复制的页面项数。如果是内核空间，则紧需要复制头160页对应的页表项
								  // 否则需要复制一个页表中所有1024页页表项，可映射4MB物理内存
		// 此时对于当前页表，开始循环复制制定的nr个内存页面表项
		for ( ; nr-- > 0 ; from_page_table++,to_page_table++) {
			this_page = *from_page_table; //取出源页表项内容
			if (!(1 & this_page)) // 如果当前源页面没有使用，则不用复制该表项，继续处理下一项
				continue;
			this_page &= ~2; // 复位页表项中R/W标志位（位1置0），即让页表项对应的页面只读。
			*to_page_table = this_page; // 然后将该页表项复制到目的表中
			if (this_page > LOW_MEM) { // 如果该页表项所指物理页面地址在1MB以上，则需要设置内存页面映射数组mem_map[]
				*from_page_table = this_page;  // 另源页表只读
				this_page -= LOW_MEM; // 计算页面号，并以它为索引在页面映射数组相应项中增加引用次数
				this_page >>= 12;
				mem_map[this_page]++;
			}
		}
	}
	invalidate(); // 刷新页变换高速缓存
	return 0;
}

/*
 * This function puts a page in memory at the wanted address.
 * It returns the physical address of the page gotten, 0 if
 * out of memory (either when trying to access page-table or
 * page.)
 */
unsigned long put_page(unsigned long page,unsigned long address)
{
	unsigned long tmp, *page_table;

/* NOTE !!! This uses the fact that _pg_dir=0 */
	// 判断参数给定物理内存页面page的有效性
	if (page < LOW_MEM || page >= HIGH_MEMORY)
		printk("Trying to put page %p at %p\n",page,address);
	if (mem_map[(page-LOW_MEM)>>12] != 1) // 判断该page页面是否是已经申请的页面，即判断mem_map数组中相应字节是否已经置位，没有则发出警告
		printk("mem_map disagrees with %p at %p\n",page,address);
	page_table = (unsigned long *) ((address>>20) & 0xffc); // page_table为address在页目录表中对应的目录项指针
	if ((*page_table)&1) // *page_table 目录项指针（一级页表）内容，即二级页表地址，最后一位P位是否位1
	    // 如果二级页表P位为1，则说明该页已经做好映射关系
		// 则从中取得指定页表地址放到page_table变量中
		page_table = (unsigned long *) (0xfffff000 & *page_table); 
	else {
		if (!(tmp=get_free_page())) // 否则重新申请一个页面
			return 0;
		*page_table = tmp|7; // 并在对应目录项中置相应位，
		page_table = (unsigned long *) tmp; // 然后将改页表地址放到page_table变量中
	}
	page_table[(address>>12) & 0x3ff] = page | 7; // 把物理页面page的地址填入表项同时置位
/* no need for invalidate */
	return page;
}
// 取消写保护页面函数，用于页面异常中断过程中写保护异常的处理
void un_wp_page(unsigned long * table_entry)
{
	unsigned long old_page,new_page;

	old_page = 0xfffff000 & *table_entry; // 取指定页表项中物理页面地址
	
	//-------该内存页面此时只被一个进程使用，并且不是内核中的进程，则直接把属性改为可写即可，不用重新申请一个页面
	
	// 如果原页面地址大于低端LOW_MEM(表示在主内存中)，并且其在页面映射字节图数组中值为1（表示页面仅被引用1次，页面没有被共享）
	if (old_page >= LOW_MEM && mem_map[MAP_NR(old_page)]==1) { 
		*table_entry |= 2; // 则在该页面的页表中置R/W标志（可写）
		invalidate(); // 并刷新页变换高速缓冲，然后返回
		return;
	}
	
	
	//-------否则就需要在主内存内申请一页空闲页面给执行写操作的进程单独使用，取消页面共享
	
	if (!(new_page=get_free_page()))
		oom();
	if (old_page >= LOW_MEM) // 如果原页面大于内存低端，在主内存中，则说名页面是共享的
		mem_map[MAP_NR(old_page)]--; // 将原页面有的页面映射字节数组值减1
	*table_entry = new_page | 7; // 然后将指定页表项内容更新为新页面地址，并置可读写等标志
	invalidate(); // 刷新页变换高速缓冲后，
	copy_page(old_page,new_page); // 将原页面内容复制到新页面上
}	

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * If it's in code space we exit with a segment error.
 */
 // error_code是进程在写保护页面时由CPU自动产生，address是页面线性地址
 // 写共享页面时，需要复制页面（写时复制）
void do_wp_page(unsigned long error_code,unsigned long address)
{
#if 0
/* we cannot do this yet: the estdio library writes to code space */
/* stupid, stupid. I really want the libc.a from GNU */
	if (CODE_SPACE(address))
		do_exit(SIGSEGV);
#endif
	un_wp_page((unsigned long *)
		(((address>>10) & 0xffc) + (0xfffff000 &
		*((unsigned long *) ((address>>20) &0xffc)))));

}
// 写页面验证
// 若页面不可写，则复制页面，address是指定页面线性地址
void write_verify(unsigned long address)
{
	unsigned long page;
	// 取一级目录表指针内容page,查看存在位
	if (!( (page = *((unsigned long *) ((address>>20) & 0xffc)) )&1))
		return; // 如果P=0,则说明改页面不存在，也就么有写时复制可言，
				// 并且若程序对此不存在页面执行写操作时，系统会因缺页异常而去执行do_no_page(),并且为这个地方使用put_page函数映射一个物理页面
	page &= 0xfffff000;
	page += ((address>>10) & 0xffc);
	if ((3 & *(unsigned long *) page) == 1)  /* non-writeable, present */ // 判断该页表项位1（R/W）、位0（P）标志，如果该页面不可写（R/W=0）且存在
		// 那么就执行共享检查和复制页面操作（写时复制）
		un_wp_page((unsigned long *) page);
	return;
}

// 取得一页空闲内存页并映射到指定线性地址处
void get_empty_page(unsigned long address)
{
	unsigned long tmp;
    // get_free_page()仅是申请得到主内存区的一页物理内存 put_page() 将物理页面映射到线性地址处
	if (!(tmp=get_free_page()) || !put_page(tmp,address)) {
		free_page(tmp);		/* 0 is ok - ignored */ //free_page()函数的参数tmp是0也没关系，该函数会忽略并能正常返回
		oom();
	}
}

/*
 * try_to_share() checks the page at address "address" in the task "p",
 * to see if it exists, and if it is clean. If so, share it with the current
 * task.
 *
 * NOTE! This assumes we have checked that p != current, and that they
 * share the same executable.
 */
 // address是进程中的逻辑地址，即是当前进程欲与p进程共享页面的逻辑页面地址
 // 进程p是将被执行共享页面的进程，如果p进程address处的页面存在并且没有被修改过的话，就让当前进程与p进程共享
 // 同时还需要验证指定的地址处是否已经申请了页面，若是则出错，死机。返回1-页面共享处理成功 0-失败
static int try_to_share(unsigned long address, struct task_struct * p)
{
	unsigned long from;
	unsigned long to;
	unsigned long from_page;
	unsigned long to_page;
	unsigned long phys_addr;
	// 求得指定进程p中和当前进程中逻辑地址，addr对应的目录项
	from_page = to_page = ((address>>20) & 0xffc);
	from_page += ((p->start_code>>20) & 0xffc);
	to_page += ((current->start_code>>20) & 0xffc);
/* is there a page-directory at from? */
   // 取得p进程中address对应的物理内存页面地址
	from = *(unsigned long *) from_page;
	if (!(from & 1)) // 如果改物理页面存在并且干净
		return 0;
	from &= 0xfffff000; // 页表指针（地址）
	from_page = from + ((address>>10) & 0xffc); // 页表项指针
	phys_addr = *(unsigned long *) from_page; // 页表项内容
/* is the page clean and present? */
	// 物理页面干净并且存在 0x41对应页表项中的D(Dirty)和P(Present)标识，如果页面不干净或无效则返回
	if ((phys_addr & 0x41) != 0x01)
		return 0;
	phys_addr &= 0xfffff000; //从该表项中取出物理页面地址保存在phys_addr中
	// 检查这个物理页面地址的有效性，即不应该超过机器最大物理地址
	// 也不应该小于内存低端
	if (phys_addr >= HIGH_MEMORY || phys_addr < LOW_MEM) 
		return 0;
	
	// 首先对当前进程的表项进行操作，目标是取得当前进程中address对应的页表项地址
	to = *(unsigned long *) to_page; // 当前进程目录项内容
	if (!(to & 1))// 并且该页表项还没有映射物理页面,即目录项对应的二级页表不存在
		if (to = get_free_page()) // 申请一空闲页面来存放页表
			*(unsigned long *) to_page = to | 7; //更新目录项to_page内容，让其指向内存页面
		else
			oom();
	// 否则取目录项中的页表地址to，
	to &= 0xfffff000;
	to_page = to + ((address>>10) & 0xffc); // 加上页表项索引值<<2，即页表项在表中偏移地址，带到页表项地址to_page
	if (1 & *(unsigned long *) to_page) // 如果对应的物理页面已经存在
							// 则说明原本我们能想共享进程p中对应物理页面，但现在我们自己已经占有了物理页面,于是说明内核出错，死机
		panic("try_to_share: to_page already exists");
/* share them: write-protect */
	// 找到了进程p中的逻辑地址addres处对应的干净且存在的物理页面，而且页确定了当前进程中逻辑地址address所对应的二级表项地址之后
	// 现在对他们进行共享处理
	*(unsigned long *) from_page &= ~2; // 首先对p进程的页表项进行修改，设置其写保护（R/W=0 只读）标志
	*(unsigned long *) to_page = *(unsigned long *) from_page; // 然后让当前进程复制p进程的整个表项，
							// 此时当前进程逻辑地址address处页面即被映射到p进程逻辑地址address处页面映射的物理页面上
	invalidate(); // 刷新页面变换高速缓冲，
	phys_addr -= LOW_MEM;
	phys_addr >>= 12; // 计算所操作物理页面的页面号
	mem_map[phys_addr]++; // 并将对应页面映射字节数组项中引用递增1，最后返回1，表示共享成功
	return 1;
}

/*
 * share_page() tries to find a process that could share a page with
 * the current one. Address is the address of the wanted page relative
 * to the current data space.
 *
 * We first check if it is at all feasible by checking executable->i_count.
 * It should be >1 if there are other tasks sharing this inode.
 */
// 共享页面处理
//  判断系统中是否有另一个进程也在执行同一个执行文件的方法是利用进程任务数据结构中的executable字段，该字段指向进程正在
// 执行长袖在内存中的i节点。根据该i节点引用次数i_count我们可以进行这种判断，若executable->i_count值大于1，则说明系统中可能有两个进程
// 在运行同一个执行文件
static int share_page(unsigned long address)
{
	struct task_struct ** p;
	// 检查当前进程的executable字段是否指向某个执行文件的i节点
	if (!current->executable)
		return 0; // 如果没有，则返回0
	// 如果executable的确指向某个i节点，则检测该i节点引用的计数值，
	// 如果当前进程运行的执行文件的内存i节点引用计数等于1，表示当前系统只有一个进程（即当前进程）在运行该执行文件，因此无共享可言，直接退出函数
	if (current->executable->i_count < 2) 
		return 0;
	// 否则搜索任务数组中所有任务，寻找与当前进程可共享页面的进程，即运行相同执行文件的另一个进程，
	for (p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
		if (!*p)
			continue;
		if (current == *p)
			continue;
		if ((*p)->executable != current->executable) 
			continue;
		// 如果中找到某个进程p，其executable与当前进程相同，则调用try_to_share尝试页面共享，
		if (try_to_share(address,*p))
			return 1;
	}
	return 0;
}

// 执行缺页处理，访问不存在页面处理函数，页面异常中断处理过程中调用的函数，在page.s程序中被调用
// error_code 指出出错类型 address是产生异常页面线性地址
void do_no_page(unsigned long error_code,unsigned long address)
{
	int nr[4];
	unsigned long tmp;
	unsigned long page;
	int block,i;
	// 首先取线性空间中指定地址address处页面地址，
	// 从而可算出制定线性地址在进程空间中相对与进程基址的偏移长度值tmp，即对应的逻辑地址
	address &= 0xfffff000; // address处缺页页面地址
	tmp = address - current->start_code; // 缺页页面对应逻辑地址
	// 若当前进程executable节点指针为空，或者指定地址超出（代码+数据）长度，
	if (!current->executable || tmp >= current->end_data) { // executable是进程正在运行的执行文件的i节点接口
		get_empty_page(address); // 则申请一页物理内存,并映射到指定线性地址处
		return;
	}
	// 否则说明所缺页面在进程执行影像文件范围内，于是就尝试共享页面操作，若成功则退出
	if (share_page(tmp))
		return;
	if (!(page = get_free_page())) // 若不成功就只能申请一页物理内存页面page，然后从设备上读取执行文件中相应页面并映射到进程页面逻辑地址tmp处
		oom();
/* remember that 1 block is used for header */
	// 因为块设备上存放的执行文件映像第一块数据是程序头结构，因此在读取该文件时需要跳过第一块数据
	// 计算缺页所在的数据块号，因为每块数据长度为BLOCK_SIZE=1kb,因此一页内存可存放4个数据块。进程逻辑地址tmp除以数据块大小再加1即可得出
	block = 1 + tmp/BLOCK_SIZE;  // 执行文件中起始数据块号
	for (i=0 ; i<4 ; block++,i++)
		nr[i] = bmap(current->executable,block); // 设备上对应的逻辑块号
	bread_page(page,current->executable->i_dev,nr); // 读设备上4个逻辑块
	// 在读设备逻辑块操作时，可能会出现这样一种情况，即在执行文件中的读取页面位置可能离文件尾不到1个页面的长度
	// 因此就可能读入一些无用的信息，下面的操作就是把这部分超出执行文件end_data以后的部分清零处理
	i = tmp + 4096 - current->end_data; // 超出的字节长度值
	tmp = page + 4096; // tmp指向页面末端
	while (i-- > 0) { // 页面末端i字节清零
		tmp--; 
		*(char *)tmp = 0;
	}
	// 最后把应用引起缺页异常的一页物理页面映射到指定线性地址address处，若操作成功就返回
	if (put_page(page,address))
		return;
	free_page(page); // 否则释放内存页，显示内存不够
	oom();
}
//start_mem 除去虚拟磁盘+物理低4M（内核+BIOS ROM+显存）的内容，占用的内存后剩下的内存起始地址（虚拟磁盘占用896项*1024=）
void mem_init(long start_mem, long end_mem)
{
	int i;

	HIGH_MEMORY = end_mem; //end_mem 内核占用的低1M的内容+从BIOS获取的扩展内存，最大16M
	for (i=0 ; i<PAGING_PAGES ; i++) //扩展内存 PAGING_MEMORY (15*1024*1024)>>12（每页4k大小） = 3840页
		mem_map[i] = USED; // 扩展内存中的15M，mem_map赋初始值USED(100)
	i = MAP_NR(start_mem); // #define MAP_NR(addr) (((addr)-LOW_MEM)>>12) = 896页
	end_mem -= start_mem; //计算主内存区大小
	end_mem >>= 12; //计算主内存区占用物理页
	while (end_mem-->0) // 循环页面数-1次
		mem_map[i++]=0; // mem_map映射赋0，mem_map中每个位置映射为物理的对应页，例如最后一个要素mem_map[3839]，对应3840页
		                // mem_map[3839]值，对应改内存被使用了多少次，在每次分配内存（get_free_page）时，会将改值赋1
}
// 计算内存空闲页面并显示，用于调试时使用
void calc_mem(void)
{
	int i,j,k,free=0;
	long * pg_tbl;
	// 扫描内存页面映射数组mem_map[]，获取空闲页面数并显示，
	for(i=0 ; i<PAGING_PAGES ; i++)
		if (!mem_map[i]) free++;
	printk("%d pages free (of %d)\n\r",free,PAGING_PAGES);
	for(i=2 ; i<1024 ; i++) { // 扫描所有页目录项（除0,1项）
		if (1&pg_dir[i]) { // 如果页目录项有效，则统计对应页表中有效页面数，并显示。
			pg_tbl=(long *) (0xfffff000 & pg_dir[i]);
			for(j=k=0 ; j<1024 ; j++)
				if (pg_tbl[j]&1)
					k++;
			printk("Pg-dir[%d] uses %d pages\n",i,k);
		}
	}
}
