
#include "qemu/osdep.h"
#include "qemu/typedefs.h"

#include "afl/afl-fuzz.h"
#include "afl/debug.h"
#include "cpu.h"
#include "panda/debug.h"

#include "panda/buzzer_hypercall.h"
#include "qom/cpu.h"

#include <stdint.h>
#include <dirent.h>

#include "panda/buzzer.h"
#include "panda/plugin.h"
#include "panda/common.h"

static HarnessState* harness_state = NULL;
static uint32_t harness_state_size = 0;
static uint32_t harness_state_i = 0;
static char* bz_buffer = NULL;

#if defined(TARGET_I386) || defined(TARGET_X86_64)
#define reg_cmd(cpu)    (((CPUArchState*)cpu->env_ptr)->regs[R_EAX])
#define reg_arg0(cpu)   (((CPUArchState*)cpu->env_ptr)->regs[R_EBX])
#define reg_arg1(cpu)   (((CPUArchState*)cpu->env_ptr)->regs[R_ECX])
#define reg_arg2(cpu)   (((CPUArchState*)cpu->env_ptr)->regs[R_EDX])
#define reg_arg3(cpu)   (((CPUArchState*)cpu->env_ptr)->regs[R_EDI])
#define reg_arg4(cpu)   (((CPUArchState*)cpu->env_ptr)->regs[R_ESI])
#else
    #error "Arch not supported yet"
#endif

static void buzzer_handle_hypercall_send(CPUState* cpu) {
    target_ulong addr = reg_arg0(cpu);
    target_ulong len = reg_arg1(cpu);
    printf("Rcvd from Bluetooth host " TARGET_FMT_ld  " bytes:\n", len);
    bz_buffer = (char*)realloc(bz_buffer, len);
    bz_virtual_memory_read(cpu, addr, bz_buffer, len);
    qemu_hexdump(bz_buffer, stdout, "", len);
}

static void buzzer_handle_hypercall_recv(CPUState* cpu) {
    printf("Bluetooth host is wants to receive data\n");
}

static void buzzer_handle_hypercall_wait(CPUState* cpu) {
    printf("Bluetooth host is waiting for data\n");
}

static void buzzer_handle_hypercall_print(CPUState *cpu) {
    target_ulong str_addr = reg_arg0(cpu);
    target_ulong len = reg_arg1(cpu);
    bz_buffer = (char*)realloc(bz_buffer, len + 1);
    bz_buffer[len] = '\0'; 
    bz_virtual_memory_read(cpu, str_addr, bz_buffer, len);
    printf("[Guest: ] %s\n", bz_buffer);
}

static void buzzer_handle_hypercall_panic(CPUState* cpu) {
    target_ulong str_addr = reg_arg0(cpu);
    target_ulong len = reg_arg1(cpu);
    message_t* message = (message_t*)buzzer->shmem_message;
    message->size = len + 1;
    message->data[len] = '\0';
    
    bz_virtual_memory_read(cpu, str_addr, message->data, len);
    send_stat(STAT_RUN_CRASH);
    exit(0);
}

static void buzzer_handle_hypercall_guest_error(CPUState* cpu) {
    target_ulong str_addr = reg_arg0(cpu);
    target_ulong len = reg_arg1(cpu);
    message_t* message = (message_t*)buzzer->shmem_message;
    message->size = len + 1;
    message->data[len] = '\0';

    bz_virtual_memory_read(cpu, str_addr, message->data, len);
    send_stat(STAT_RUN_ERROR);
    exit(-1);
}

static void buzzer_handle_hypercall_req_harness_info(CPUState* cpu) {
    struct dirent **nl;
    int nl_cnt = scandir(buzzer->target_dir, &nl, NULL, alphasort);
    if (nl_cnt <= 0) {
        perror("Failed to open target directory");
    }

    harness_state_size = sizeof(HarnessState) + nl_cnt * sizeof(harness_state->files[0]);
    harness_state = (HarnessState*)calloc(harness_state_size, 1);
    harness_state->asan_enabled = buzzer->enable_asan;
    harness_state->device_no =  buzzer->device_no;

    if (buzzer->args)
        strcpy(harness_state->argv, buzzer->args);

    bool target_found = false;
    bool preload_found = false;
    for (int i = 0; i < nl_cnt; ++i) {
        struct stat st;
        char* fn = alloc_printf("%s/%s", buzzer->target_dir, nl[i]->d_name);
        lstat(fn, &st);

        if (!S_ISREG(st.st_mode))
            continue;

        int n = harness_state->num++;
        strcpy(harness_state->files[n].name, nl[i]->d_name);
        harness_state->files[n].size = st.st_size;
        if (!strcmp(buzzer->target_file, harness_state->files[n].name)) {
            harness_state->files[n].is_exec = true;
            harness_state->files[n].is_target = true;
            target_found = true;
        } else if (!strcmp("buzzer_preload.so", harness_state->files[n].name)) {
            harness_state->files[n].is_exec = true;
            harness_state->files[n].is_target = false;
            preload_found = true;
        }
        free(fn); 
        
    }

    if (!target_found) {
        FATAL("Target %s not found in target dir %s", buzzer->target_file, buzzer->target_dir);
        exit(-1);
    }

    if (!preload_found) {
        printf("buzzer_preload.so not found in target dir %s", buzzer->target_dir);
        exit(-1);
    }

    target_ulong addr = reg_arg0(cpu);
    bz_virtual_memory_write(cpu, addr, (uint8_t*)harness_state, harness_state_size);
}

static void buzzer_handle_hypercall_req_file(CPUState* cpu) {
    char* fn = alloc_printf("%s/%s", 
        buzzer->target_dir, harness_state->files[harness_state_i].name);
    uint32_t size = harness_state->files[harness_state_i].size;
    FILE* f = fopen(fn, "r");
    bz_buffer = (char*)realloc(bz_buffer, size);

    ACTF("Sending file %s to guest\n", fn);

    if (fread(bz_buffer, 1, size, f) != size) {
        FATAL("Failed to read file %s\n", fn);
    }

    target_ulong addr = reg_arg0(cpu);
    if (bz_virtual_memory_write(cpu, addr, (uint8_t*)bz_buffer, size) != MEMTX_OK) {
        FATAL("Failed to write to guest virtual memory\n");
    }
    fclose(f);
    free(fn);

    harness_state_i++;
}

static void buzzer_handle_hypercall_kernel_info(CPUState* cpu) {
    target_ulong addr = reg_arg0(cpu);
    if (panda_virtual_memory_read(cpu, addr, 
        (uint8_t*)&buzzer->kernel_info, sizeof(kernelinfo)) != MEMTX_OK) {
        FATAL("Failed to read kernel info\n");
    }
    OKF("Read kernel info complete: %p", 
        buzzer->kernel_info.task.per_cpu_offset_0_addr);
}

static void buzzer_handle_hypercall_kernel_switch_task_hook_addr(CPUState* cpu) {
    buzzer->kernel_info.task.switch_task_hook_addr = reg_arg0(cpu);
    OKF("Read switch task hook addr: " TARGET_PTR_FMT, 
        buzzer->kernel_info.task.switch_task_hook_addr);
}

static void buzzer_handle_hypercall_monitor_thread(CPUState* cpu) {
    buzzer->target_pid = reg_arg0(cpu);
    OKF("Read target pid: %u", buzzer->target_pid);
}

bool buzzer_callback_hypercall(void* cpu) {
    switch (reg_cmd(((CPUState*)cpu)))
    {
    case BZ_HYPERCALL_SEND:
        buzzer_handle_hypercall_send(cpu);
        return true;

    case BZ_HYPERCALL_RECV:
        buzzer_handle_hypercall_recv(cpu);
        return true;

    case BZ_HYPERCALL_WAIT:
        buzzer_handle_hypercall_wait(cpu);
        return true;

    case BZ_HYPERCALL_PRINT:
        buzzer_handle_hypercall_print(cpu);
        return true;

    case BZ_HYPERCALL_PANIC:
        buzzer_handle_hypercall_panic(cpu);
        return true;

    case BZ_HYPERCALL_GUEST_ERROR:
        buzzer_handle_hypercall_guest_error(cpu);
        return true;

    case BZ_HYPERCALL_REQ_HARNESS_INFO:
        buzzer_handle_hypercall_req_harness_info(cpu);
        return true;

    case BZ_HYPERCALL_REQ_FILE:
        buzzer_handle_hypercall_req_file(cpu);
        return true;
    
    case BZ_HYPERCALL_KERNEL_INFO:
        buzzer_handle_hypercall_kernel_info(cpu);
        return true;
    
    case BZ_HYPERCALL_KERNEL_SWITCH_TASK_HOOK_ADDR:
        buzzer_handle_hypercall_kernel_switch_task_hook_addr(cpu);
        return true;
    
    case BZ_HYPERCALL_MONITOR_THREAD:
        buzzer_handle_hypercall_monitor_thread(cpu);
        return true;

    default:
        return false;
    }
}
