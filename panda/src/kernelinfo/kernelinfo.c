/*!
 * @file kernelinfo.c
 * @brief Retrieves offset information from the running Linux kernel and prints them in the kernel log.
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */

#define _KERNEL_INFO

#include <linux/types.h>
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/version.h>

#include "./buzzer_hypercall.h"
#include "./kernelinfo.h"
/*
 * Include the appropriate mount.h version.
 *
 * Linux commit 7d6fec45a5131 introduces struct mount in fs/mount.h.
 * The new struct contains all the fields that were previously members
 * of struct vfsmount but were touched only by core VFS.
 * It also contains an embedded struct vfsmount which now has been
 * stripped down to include only the fields shared between core VFS
 * and other components.
 *
 * XXX: identify the first kernel version after 7d6fec45a5131 to make
 * the conditionals more accurate.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)		/* 0.0  <= v < 2.6  */
#error Unsupported kernel.
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)	/* 2.6  <= v < 3.0  */
#define current_task per_cpu__current_task
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)	/* 3.0  <= v < 3.3  */
/* nothing */
#else												/* 4.12 <= v < x.xx */
// #include "../../mount.h"
#endif

/*
 * This function is used because to print offsets of members
 * of nested structs. It basically transforms '.' to '_', so
 * that we don't have to replicate all the nesting in the
 * structs used by the introspection program.
 *
 * E.g. for:
 * struct file {
 *	...
 *	struct dentry {
 *		struct *vfsmount;
 *		struct *dentry;
 *	}
 *	...
 * };
 *
 * Caveat: Because a static buffer is returned, the function
 * can only be used once in each invocation of printk.
 */
#define MAX_MEMBER_NAME 31
// static char *cp_memb(const char *s) {
// 	static char memb[MAX_MEMBER_NAME+1];
// 	int i;
// 	for (i = 0; i<MAX_MEMBER_NAME && s[i]!='\0'; i++) {
// 		memb[i] = s[i] == '.' ? '_' : s[i];
// 	}
// 	memb[i] = 0;
// 	return memb;
// }

#define OFFSET(_structp, _memb) \
	((int)((void *)&(_structp->_memb) - (void *)_structp))

#define OFFSET_FROM_MEMBER(_structp, _memb_base, _memb_dest) \
	((int)((void *)&(_structp->_memb_dest) - (void *)&(_structp->_memb_base)))
/*
 * Printf offset of memb from the beginning of structp.
 */
#define PRINT_OFFSET(structp, memb, cfgname)\
	printk(KERN_INFO cfgname ".%s_offset = %d\n",\
		cp_memb(#memb),\
		(int)((void *)&(structp->memb) - (void *)structp))

/*
 * Prints offset between members memb_base and memb_dest.
 * Useful in case where we have a pointer to memb_base, but not to structp.
 * We emit the same name as if we were using PRINT_OFFSET() for memb_dest.
 */
#define PRINT_OFFSET_FROM_MEMBER(structp, memb_base, memb_dest, cfgname)\
	printk(KERN_INFO cfgname ".%s_offset = %d\n",\
		cp_memb(#memb_dest),\
		(int)((void *)&(structp->memb_dest) - (void *)&(structp->memb_base)))


#define SET_SIZE(_ki, _memb, _size, _target) \
	_ki._memb._size = sizeof(_target)

#define SET_OFFSET(_ki, _memb, _structp, _target) \
	_ki._memb._target ## _offset = OFFSET(_structp, _target)

#define SET_OFFSET_FROM_MEMBER(_ki, _memb, _structp, _base, _dest) \
	_ki._memb._dest ## _offset = OFFSET_FROM_MEMBER(_structp, _base, _dest)

/*
 * Prints the size of structv.
 */
#define PRINT_SIZE(structv, cfgmemb, cfgname) printk(KERN_INFO cfgname "." cfgmemb " = %zu\n", sizeof(structv))

static kernelinfo kernel_info;

static int __init get_kernelinfo_init(void)
{
	struct cred cred__s;
	struct vm_area_struct vm_area_struct__s;
	struct dentry dentry__s;
	struct dentry_operations dentry_operations__s;
	struct file file__s;
	struct files_struct files_struct__s;
	struct fdtable fdtable__s;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
	// struct mount mount__s;
#else
	struct vfsmount vfsmount__s;
#endif
	struct qstr qstr__s;

	struct task_struct *task_struct__p;
	struct cred *cred__p;
	struct mm_struct *mm_struct__p;
	struct vm_area_struct *vm_area_struct__p;
	struct dentry *dentry__p;
	struct dentry_operations *dentry_operations__p;
	struct file *file__p;
	struct fdtable *fdtable__p;
	struct files_struct *files_struct__p;
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
// 	struct mount *mount__p;
// #endif
// 	struct vfsmount *vfsmount__p;
 	struct qstr *qstr__p;

	task_struct__p = &init_task;
	cred__p = &cred__s;
	mm_struct__p = init_task.mm;
	vm_area_struct__p = &vm_area_struct__s;
	dentry__p = &dentry__s;
	dentry_operations__p = &dentry_operations__s;
	file__p = &file__s;
	files_struct__p = &files_struct__s;
	fdtable__p = &fdtable__s;
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
// 	mount__p = &mount__s;
// 	vfsmount__p = &mount__s.mnt;
// #else
// 	vfsmount__p = &vfsmount__s;
// #endif
	qstr__p = &qstr__s;


	kernel_info.version.a = (LINUX_VERSION_CODE >> 16),
	kernel_info.version.b = ((LINUX_VERSION_CODE >> 8) & 0xFF),
	kernel_info.version.c = (LINUX_VERSION_CODE & 0xFF),

#if defined __i386__ || defined __x86_64__
	kernel_info.task.per_cpu_offsets_addr = (u64)(uintptr_t)&__per_cpu_offset,
	kernel_info.task.per_cpu_offset_0_addr = (u64)(uintptr_t)__per_cpu_offset[0],
	kernel_info.task.current_task_addr = (u64)(uintptr_t)&pcpu_hot.current_task,
	kernel_info.task.init_addr = (u64)(uintptr_t)(task_struct__p),
#else
	kernel_info.task.per_cpu_offsets_addr = 0,
	kernel_info.task.per_cpu_offset_0_addr = 0,
	kernel_info.task.current_task_addr = (u64)(uintptr_t)(task_struct__p),
	kernel_info.task.init_addr = (u64)(uintptr_t)(task_struct__p),
#endif

	SET_SIZE(kernel_info, task, size, init_task),
	SET_OFFSET(kernel_info, task, task_struct__p, tasks),
	SET_OFFSET(kernel_info, task, task_struct__p, pid),
	SET_OFFSET(kernel_info, task, task_struct__p, tgid),
	SET_OFFSET(kernel_info, task, task_struct__p, group_leader),

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,7,0)
	SET_OFFSET(kernel_info, task, task_struct__p, thread_group),
#endif

	SET_OFFSET(kernel_info, task, task_struct__p, real_parent),
	SET_OFFSET(kernel_info, task, task_struct__p, parent),
	SET_OFFSET(kernel_info, task, task_struct__p, mm),
	SET_OFFSET(kernel_info, task, task_struct__p, stack),
	SET_OFFSET(kernel_info, task, task_struct__p, real_cred),
	SET_OFFSET(kernel_info, task, task_struct__p, cred),
	SET_OFFSET(kernel_info, task, task_struct__p, comm),
	SET_SIZE(kernel_info, task, comm_size, task_struct__p->comm),
	SET_OFFSET(kernel_info, task, task_struct__p, files),
	SET_OFFSET(kernel_info, task, task_struct__p, start_time),

	SET_OFFSET(kernel_info, cred, cred__p, uid),
	SET_OFFSET(kernel_info, cred, cred__p, gid),
	SET_OFFSET(kernel_info, cred, cred__p, euid),
	SET_OFFSET(kernel_info, cred, cred__p, egid),

	SET_SIZE(kernel_info, mm, size, *init_task.mm),

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	SET_OFFSET(kernel_info, mm, mm_struct__p, mmap),
#endif

	SET_OFFSET(kernel_info, mm, mm_struct__p, pgd),
	SET_OFFSET(kernel_info, mm, mm_struct__p, arg_start),
	SET_OFFSET(kernel_info, mm, mm_struct__p, start_brk),
	SET_OFFSET(kernel_info, mm, mm_struct__p, brk),
	SET_OFFSET(kernel_info, mm, mm_struct__p, start_stack),

	SET_SIZE(kernel_info, vma, size, vm_area_struct__s),
	SET_OFFSET(kernel_info, vma, vm_area_struct__p, vm_mm),
	SET_OFFSET(kernel_info, vma, vm_area_struct__p, vm_start),
	SET_OFFSET(kernel_info, vma, vm_area_struct__p, vm_end),

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
		SET_OFFSET(kernel_info, vma, vm_area_struct__p, vm_next),
#endif

	SET_OFFSET(kernel_info, vma, vm_area_struct__p, vm_flags),
	SET_OFFSET(kernel_info, vma, vm_area_struct__p, vm_file),

	/* used in reading file information */
	// SET_OFFSET(fs, file__p,	f_path.dentry),
	// SET_OFFSET(fs, file__p,	f_path.mnt),
	// SET_OFFSET(fs, file__p,	f_pos),
	// SET_OFFSET(fs, files_struct__p,	fdt),
	// SET_OFFSET(fs, files_struct__p,	fdtab),
	// SET_OFFSET(fs, fdtable__p, fd),

	/* used for resolving path names */
	// SET_SIZE(qstr, size, qstr__s),
	// SET_OFFSET(qstr, qstr__p, name),
	// SET_OFFSET(path, dentry__p, d_name),
	// SET_OFFSET(path, dentry__p, d_iname),
	// SET_OFFSET(path, dentry__p, d_parnt),
	// SET_OFFSET(path, dentry__p, d_op),
	// SET_OFFSET(path, dentry_operations__p, d_dname),
	// SET_OFFSET(path, vfsmount__p, mnt_root),

// #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
// 		/* fields in struct mount */
// 		SET_OFFSET_FROM_MEMBER(path, mount__p,	mnt, mnt_parent),
// 		SET_OFFSET_FROM_MEMBER(path, mount__p,	mnt, mnt_mountpoint),
// #else
// 		/* fields in struct vfsmount */
// 		SET_OFFSET(path, vfsmount__p, mnt_parent),
// 		SET_OFFSET(path, vfsmount__p, mnt_mountpoint),
// #endif

	// panic("kernel info");
	bz_kernel_info(&kernel_info);
	return 0;
}

module_init(get_kernelinfo_init);