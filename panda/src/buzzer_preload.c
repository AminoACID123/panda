#define _GNU_SOURCE

#include "panda/buzzer_userspace.h"
#include <dlfcn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ucontext.h>
#include <sys/un.h>
#include <sys/mman.h>

#define HCI_FD_DUMMY (123)

static bool asan_enabled;

/* Crash Handling*/

char* get_asan_log(void){

    if (!getenv("ASAN_OPTIONS"))
        return "\0";

    char* asan_log_file = alloc_printf("/tmp/data.log.%d", getpid());
    FILE* f = fopen(asan_log_file, "r");
    char* asan_log = malloc(0x1000);
    memset(asan_log, 0x00, 0x1000);

    if(f){
        fread(asan_log, 0x1000-1, 1, f);
        fclose(f);
    }
    
    free(asan_log_file);
    return asan_log;
}

static void set_handler(void (*handler)(int,siginfo_t *,void *)){
    //hprintf("%s\n", __func__);
    struct sigaction action;
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler;

    int (*new_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);
    new_sigaction = dlsym(RTLD_NEXT, "sigaction");
        
    if(asan_enabled){
        if (new_sigaction(SIGSEGV, &action, NULL) == -1) {
            bz_guest_error("sigsegv: sigaction");
            _exit(1);
        }
        if (new_sigaction(SIGFPE, &action, NULL) == -1) {
            bz_guest_error("sigfpe: sigaction");
            _exit(1);
        }
        if (new_sigaction(SIGBUS, &action, NULL) == -1) {
            bz_guest_error("sigbus: sigaction");
            _exit(1);
        }
    }
    
    if (new_sigaction(SIGILL, &action, NULL) == -1) {
        bz_guest_error("sigill: sigaction");
        _exit(1);
    }
    
    if (new_sigaction(SIGABRT, &action, NULL) == -1) {
        bz_guest_error("sigabrt: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGIOT, &action, NULL) == -1) {
        bz_guest_error("sigiot: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGTRAP, &action, NULL) == -1) {
        bz_guest_error("sigiot: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGSYS, &action, NULL) == -1) {
        bz_guest_error("sigsys: sigaction");
        _exit(1);
    }
    bz_print("[!] all signal handlers are hooked!\n");
}


static void fault_handler(int signo, siginfo_t *info, void *extra){
    ucontext_t *context = (ucontext_t *)extra;
    char* context_str;

#if defined(__i386__)
    context_str = alloc_printf("PC: 0x%lX\tSignal: %s\n", context->uc_mcontext.gregs[REG_EIP], strsignal(info->si_signo));
#else
    context_str = alloc_printf("PC: 0x%llX\tSignal: %s\n", context->uc_mcontext.gregs[REG_RIP], strsignal(info->si_signo));
#endif
    bz_panic("Context: %s", context_str);
}

static void fault_handler_asan(int signo, siginfo_t *info, void *extra){
    char* asan_log = get_asan_log();
    ucontext_t *context = (ucontext_t *)extra;
    char* context_str;

#if defined(__i386__)
    context_str = alloc_printf("PC: 0x%lX\tSignal: %s\n", context->uc_mcontext.gregs[REG_EIP], strsignal(info->si_signo));
#else
    context_str = alloc_printf("PC: 0x%llX\tSignal: %s\n", context->uc_mcontext.gregs[REG_RIP], strsignal(info->si_signo));
#endif

    bz_panic("%s\n%s", context_str, asan_log);
}

void config_handler(void){
    if(!asan_enabled) {
        set_handler(fault_handler);
    } 
    else {
        set_handler(fault_handler_asan);
    }
}

void init_crash_handling(void){
    config_handler();
}

void _abort(void){
    char* asan_log = get_asan_log();
    bz_panic("Guest _abort: %p\n%s", __builtin_return_address(0), asan_log);
    while(1){}
}

void abort(void){
    char* asan_log = get_asan_log();
    bz_panic("Guest abort: %p\n%s", __builtin_return_address(0), asan_log);
    while(1){}
}

void __abort(void){
    char* asan_log = get_asan_log();
    bz_panic("Guest __abort: %p\n%s", __builtin_return_address(0), asan_log);
    while(1){}
}

void __assert_fail (const char *__assertion, const char *__file, unsigned int __line, const char *__function){
    bz_panic("Guest __assert_fail: %s %s %d: %s\n", __function, __file, __line, __assertion);
}

void __assert_perror_fail (int __errnum, const char *__file, unsigned int __line, const char *__function){
    bz_panic("Guest __assert_perror_fail: %s %s %d: %d\n", __function, __file, __line, __errnum);
}



/* HCI Interaction */
int socket(int domain, int type, int protocol)
{
    int (*original_socket)(int ,int, int);
    original_socket = dlsym(RTLD_NEXT, "socket");

    if (domain == PF_BLUETOOTH)
    {
        bz_print("Open HCI socket");
        // return HCI_FD_DUMMY;
    }
    // else
    // {
        return (*original_socket)(domain, type, protocol);
    // }
}

// int ioctl(int fd, unsigned long request, ...)
// {
//     return 0;
// }

// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
// {
//     return 0;
// }

void force_map(void) {
    char line[1024];
    FILE *in_file = fopen("/proc/self/maps", "r");

    while (fgets(line, sizeof(line), in_file)) {
        char* addr_range = strtok(line, " ");
        char* perms = strtok(NULL, " ");
        if (perms[2] == 'x') {
            uintptr_t start = 0, end = 0;
            sscanf(addr_range, "%lx-%lx", &start, &end);
            mlock((void*)start, end - start);
        }
    }

    fclose(in_file);
}

/* Main Entrance */
int __libc_start_main(int (*main) (int,char **,char **),
              int argc,char **ubp_av,
              void (*init) (void),
              void (*fini)(void),
              void (*rtld_fini)(void),
              void (*stack_end)) {

    int (*original__libc_start_main)(int (*main) (int,char **,char **),
        int argc,char **ubp_av,
        void (*init) (void),
        void (*fini)(void),
        void (*rtld_fini)(void),
        void (*stack_end));


    original__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");
    asan_enabled = (getenv(BZ_ENV_ASAN_ENABLED) != NULL);

    bz_print("Installing crash handlers");
    init_crash_handling();
    bz_print("Crash handlers handled");

    return original__libc_start_main(main,argc,ubp_av, init,fini,rtld_fini,stack_end);
}
