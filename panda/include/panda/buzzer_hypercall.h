#ifndef _BUZZER_USER_SPACE_H
#define _BUZZER_USER_SPACE_H

// #include <stdint.h>

// The Bluetooth Host wants to send something
#define BZ_HYPERCALL_SEND 20

// The Bluetooth Host wants to recv something
#define BZ_HYPERCALL_RECV 21

// The Bluetooth Host is waiting for packet
#define BZ_HYPERCALL_WAIT 22

// Print something
#define BZ_HYPERCALL_PRINT 23

// Panic (some annomoly has been detected)
#define BZ_HYPERCALL_PANIC 24

// Guest encounters some error during setup
#define BZ_HYPERCALL_GUEST_ERROR 25

// Guest is requesting harness info for fuzz
#define BZ_HYPERCALL_REQ_HARNESS_INFO 26

// Guest is requesting harness file for fuzz
#define BZ_HYPERCALL_REQ_FILE 27

// Add thread to be monitored for coverage
#define BZ_HYPERCALL_MONITOR_THREAD 28

// Kernel info for OSI
#define BZ_HYPERCALL_KERNEL_INFO 29

// Kernel info (switch task hook addr)
#define BZ_HYPERCALL_KERNEL_SWITCH_TASK_HOOK_ADDR 30

#define BZ_ENV_ASAN_ENABLED "ASAN_ENABLED"

typedef struct {
  uint32_t num;
  uint8_t asan_enabled;
  char argv[256];
  int device_no;
  struct HarnessFile {
    uint32_t size;
    char name[256];
    uint8_t is_target;
    uint8_t is_exec;
  } files[];
} HarnessState;


#if defined(__x86_64__) || defined(TARGET_X86_64)

static inline void bz_hypercall(uintptr_t rax, uintptr_t rbx, uintptr_t rcx,
                                uintptr_t rdx, uintptr_t rdi, uintptr_t rsi) {

  asm __volatile__(
       "push %%rax \t\n\
        push %%rbx \t\n\
        push %%rcx \t\n\
        push %%rdx \t\n\
        push %%rdi \t\n\
        push %%rsi \t\n\
        mov  %0, %%rax \t\n\
        mov  %1, %%rbx \t\n\
        mov  %2, %%rcx \t\n\
        mov  %3, %%rdx \t\n\
        mov  %4, %%rdi \t\n\
        mov  %5, %%rsi \t\n\
        cpuid \t\n\
        pop  %%rsi \t\n\
        pop  %%rdi \t\n\
        pop  %%rdx \t\n\
        pop  %%rcx \t\n\
        pop  %%rbx \t\n\
        pop  %%rax \t\n\
       "
                   : /* no output registers */
                   : "r"(rax), "r"(rbx), "r"(rcx), "r"(rdx), "r"(rdi),
                     "r"(rsi) /* input operands */
                   : "rax", "rbx", "rcx", "rdx", "rdi",
                     "rsi" /* clobbered registers */
  );
  return;
}

#else

static inline void bz_hypercall(uintptr_t eax, uintptr_t ebx, uintptr_t ecx,
                                uintptr_t edx, uintptr_t edi, uintptr_t esi) {

  asm __volatile__("push %%eax \t\n\
        push %%ebx \t\n\
        push %%ecx \t\n\
        push %%edx \t\n\
        push %%edi \t\n\
        push %%esi \t\n\
        mov  %0, %%eax \t\n\
        mov  %1, %%ebx \t\n\
        mov  %2, %%ecx \t\n\
        mov  %3, %%edx \t\n\
        mov  %4, %%edi \t\n\
        mov  %5, %%esi \t\n\
        cpuid \t\n\
        pop  %%esi \t\n\
        pop  %%edi \t\n\
        pop  %%edx \t\n\
        pop  %%ecx \t\n\
        pop  %%ebx \t\n\
        pop  %%eax \t\n\
       "
                   : /* no output registers */
                   : "r"(eax), "r"(ebx), "r"(ecx), "r"(edx), "r"(edi),
                     "r"(esi) /* input operands */
                   : "eax", "ebx", "ecx", "edx", "edi",
                     "esi" /* clobbered registers */
  );
  return;
}
#endif // __WORDSIZE == 64

#define alloc_printf(_str...)                                                  \
  ({                                                                           \
    char *_tmp;                                                                \
    int _len = snprintf(NULL, 0, _str);                                        \
    _tmp = (char *)calloc(_len + 1, 1);                                        \
    snprintf(_tmp, _len + 1, _str);                                            \
    _tmp;                                                                      \
  })

#define bz_hypercall_0(_cmd)                                                   \
  bz_hypercall(BZ_HYPERCALL_##_cmd, 0, 0, 0, 0, 0)

#define bz_hypercall_1(_cmd, _arg0)                                            \
  bz_hypercall(BZ_HYPERCALL_##_cmd, (uintptr_t)_arg0, 0, 0, 0, 0)

#define bz_hypercall_2(_cmd, _arg0, _arg1)                                     \
  bz_hypercall(BZ_HYPERCALL_##_cmd, (uintptr_t)_arg0, (uintptr_t)_arg1, 0, 0, 0)

#define bz_hypercall_3(_cmd, _arg0, _arg1, _arg2)                              \
  bz_hypercall(BZ_HYPERCALL_##_cmd, (uintptr_t)_arg0, (uintptr_t)_arg1, (uintptr_t)_arg2, 0, 0)

#define bz_hypercall_4(_cmd, _arg0, _arg1, _arg2, _arg3)                       \
  bz_hypercall(BZ_HYPERCALL_##_cmd, (uintptr_t)_arg0, (uintptr_t)_arg1, (uintptr_t)_arg2, (uintptr_t)_arg4, 0)

#define bz_hypercall_5(_cmd, _arg0, _arg1, _arg2, _arg3, _arg4)                \
  bz_hypercall(BZ_HYPERCALL_##_cmd, (uintptr_t)_arg0, (uintptr_t)_arg1, (uintptr_t)_arg2, (uintptr_t)_arg3, (uintptr_t)_arg4)


#define bz_kernel_info(_kernelinfo)                                            \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_1(KERNEL_INFO, _kernelinfo);                                  \
    _ret;                                                                      \
  })

#define bz_kernel_switch_task_hook_addr(_addr)                                 \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_1(KERNEL_SWITCH_TASK_HOOK_ADDR, _addr);                       \
    _ret;                                                                      \
  })

#define bz_monitor_thread(_tid)                                                \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_1(MONITOR_THREAD, _tid);                                      \
    _ret;                                                                      \
  })

#define bz_print(_fmt...)                                                      \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    char *_str = alloc_printf(_fmt);                                           \
    bz_hypercall_2(PRINT, _str, strlen(_str));                                 \
    free(_str);                                                                \
    _ret;                                                                      \
  })

#define bz_send(_data, _len)                                                   \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_3(SEND, _data, _len, &_ret);                                  \
    _ret;                                                                      \
  })

#define bz_recv(_data, _len)                                                   \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_3(RECV, _data, _len, &_ret);                                  \
    _ret;                                                                      \
  })

#define bz_wait()                                                              \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_0(WAIT);                                                      \
    _ret;                                                                      \
  })

#define bz_panic(_fmt...)                                                      \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    char *_str = alloc_printf(_fmt);                                           \
    bz_hypercall_2(PANIC, _str, strlen(_str));                                 \
    _ret;                                                                      \
  })

#define bz_guest_error(_fmt...)                                                \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    char *_str = alloc_printf(_fmt);                                           \
    bz_hypercall_2(GUEST_ERROR, _str, strlen(_str));                           \
    free(_str);                                                                \
    _ret;                                                                      \
  })

#define bz_req_harness_info(_info)                                             \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_1(REQ_HARNESS_INFO, _info);                                   \
    _ret;                                                                      \
  })

#define bz_req_file(_buffer)                                                   \
  ({                                                                           \
    uintptr_t _ret = 0;                                                        \
    bz_hypercall_1(REQ_FILE, _buffer);                                         \
    _ret;                                                                      \
  })


#endif