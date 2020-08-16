  
/*****************************************************************
*
* ============== Kernel Dumper for PS4 - WildCard && LM ===============
*
*	Support for 6.00-6.02
*
*	Thanks to:
*	-Qwertyuiop for his kernel exploits
* 	-Specter for his Code Execution method
*	-IDC for helping to understand things
*	-Shadow for the copyout trick ;)
*       -ChendoChap for the 6.20 exploit etc
*
******************************************************************/
#include "ps4.h"
#include "defines.h"


uint64_t uaddr;
void* kbase;
uint64_t kaddr;

int kdump(struct thread *td){

	

	int (*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x00307DF0);
	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kbase + 0x00114800);
	void (*bzero)(void *b, size_t len) = (void *)(kbase + 0x00114640);



	// run copyout into userland memory for the kaddr we specify
	int cpRet = copyout(kaddr, uaddr , PAGE_SIZE);

	// if mapping doesnt exist zero out that mem
	if(cpRet == -1){
		printfkernel("bzero at 0x%016llx\n", kaddr);
		bzero(uaddr, PAGE_SIZE);
		return cpRet;
	}
	
	return cpRet;
}

int kpayload(struct thread *td){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;


	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x1C0];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0x01139458];
	void** got_rootvnode = (void**)&kernel_ptr[0x021BFAC0];

         kbase=kernel_base;

	// resolve kernel functions

	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x00307DF0);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Say hello and put the kernel base in userland to we can use later

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");

	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	printfkernel("uaddr is:0x%016llx\n", uaddr);

	return 0;
}



int _main(struct thread *td){

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, KERN_DUMPSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	

        uaddr = dump;

	syscall(11,&kpayload);


	
	uint64_t pos = 0;


	// loop enough to dump up until gpu used memory
	for(int i = 0; i < KERN_DUMPITER; i++){
	
 		kaddr = kbase + pos;


		uaddr = filedump + pos;


		syscall(11,&kdump);


		pos = pos + PAGE_SIZE;
	}



	// write to file		
	int fd = open("/mnt/usb0/Kernel_Dump_602.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);

	write(fd, filedump, KERN_DUMPSIZE); // Write the userland buffer to USB

        close(fd);

	munmap(dump, PAGE_SIZE);
	munmap(filedump, KERN_DUMPSIZE);

	return 0;
}
