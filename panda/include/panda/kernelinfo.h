#ifndef _KERNEL_INFO_H
#define _KERNEL_INFO_H

// #include <stdint.h>

#ifndef __packed
#define __packed __attribute__((packed)) 
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif
#define PROFILE_KVER_EQ(ki, _va, _vb, _vc) (KERNEL_VERSION(ki.version.a, ki.version.b, ki.version.c) == KERNEL_VERSION(_va, _vb, _vc))
#define PROFILE_KVER_NE(ki, _va, _vb, _vc) (KERNEL_VERSION(ki.version.a, ki.version.b, ki.version.c) != KERNEL_VERSION(_va, _vb, _vc))
#define PROFILE_KVER_LT(ki, _va, _vb, _vc) (KERNEL_VERSION(ki.version.a, ki.version.b, ki.version.c) < KERNEL_VERSION(_va, _vb, _vc))
#define PROFILE_KVER_GT(ki, _va, _vb, _vc) (KERNEL_VERSION(ki.version.a, ki.version.b, ki.version.c) > KERNEL_VERSION(_va, _vb, _vc))
#define PROFILE_KVER_LE(ki, _va, _vb, _vc) (KERNEL_VERSION(ki.version.a, ki.version.b, ki.version.c) <= KERNEL_VERSION(_va, _vb, _vc))
#define PROFILE_KVER_GE(ki, _va, _vb, _vc) (KERNEL_VERSION(ki.version.a, ki.version.b, ki.version.c) >= KERNEL_VERSION(_va, _vb, _vc))

/**
 * @brief Kernel Version information
 */
typedef struct __packed  {
	int a;
	int b;
	int c;
} kernel_version;

/**
 * @brief Information and offsets related to `struct task_struct`.
 */
typedef struct __packed  {
    uint64_t per_cpu_offsets_addr;
    uint64_t per_cpu_offset_0_addr;
	uint64_t switch_task_hook_addr; /**< Address to hook for task switch notifications. */
    uint64_t current_task_addr;
	uint64_t init_addr;				/**< Address of the `struct task_struct` of the init task. */
	uint64_t size;					/**< Size of `struct task_struct`. */
	union {
		int tasks_offset;			/**< TODO: add documentation for the rest of the struct members */
		int next_task_offset;
	};
	int pid_offset;
	int tgid_offset;
	int group_leader_offset;
	int thread_group_offset;
	union {
		int real_parent_offset;
		int p_opptr_offset;
	};
	union {
		int parent_offset;
		int p_pptr_offset;
	};
	int mm_offset;
	int stack_offset;
	int real_cred_offset;
	int cred_offset;
	int comm_offset;			/**< Offset of the command name in `struct task_struct`. */
	uint64_t comm_size;			/**< Size of the command name. */
	int files_offset;			/**< Offset for open files information. */
    int start_time_offset;                  /** offset of start_time */
} task_info;

/**
 * @brief Information and offsets related to `struct cred`.
 */
typedef struct __packed  {
	int uid_offset;
	int gid_offset;
	int euid_offset;
	int egid_offset;
} cred_info;

/**
 * @brief Information and offsets related to `struct mm_struct`.
 */
typedef struct __packed  {
	uint64_t size;				/**< Size of `struct mm_struct`. */
	int mmap_offset;
	int pgd_offset;
	int arg_start_offset;
	int start_brk_offset;
	int brk_offset;
	int start_stack_offset;
} mm_info;

/**
 * @brief Information and offsets related to `struct vm_area_struct`.
 */
typedef struct __packed  {
	uint64_t size;				/**< Size of `struct vm_area_struct`. */
	int vm_mm_offset;
	int vm_start_offset;
	int vm_end_offset;
	int vm_next_offset;
	int vm_file_offset;
	int vm_flags_offset;
} vma_info;

/**
 * @brief Filesystem information and offsets.
 */
typedef struct __packed  {
	union {
		int f_path_dentry_offset;
		int f_dentry_offset;
	};
	union {
		int f_path_mnt_offset;
		int f_vfsmnt_offset;
	};
	int f_pos_offset;
	int fdt_offset;
	int fdtab_offset;
	int fd_offset;
} fs_info;

/**
 * @brief qstr information and offsets
 */
typedef struct __packed  {
  uint64_t size;
  uint64_t name_offset;
} qstr_info;

/**
 * @brief Path related information and offsets.
 */
typedef struct __packed  {
	int d_name_offset;
	int d_iname_offset;
	int d_parent_offset;
	int d_op_offset;			/**< Offset of the dentry ops table. */
	int d_dname_offset;			/**< Offset of dynamic name function in dentry ops. */
	int mnt_root_offset;
	int mnt_parent_offset;
	int mnt_mountpoint_offset;
} path_info;

/**
 * @brief Wrapper for the structure-specific structs.
 */
typedef struct __packed  {
	char 		*name;
	kernel_version 	version;
	task_info 	task;
	cred_info 	cred;
	mm_info 	mm;
	vma_info 	vma;
	fs_info 	fs;
	qstr_info 	qstr;
	path_info 	path;
} kernelinfo;


#endif // _KERNEL_INFO_H
