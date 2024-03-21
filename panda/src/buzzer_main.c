#include "qemu/osdep.h"

#include <fcntl.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <gmodule.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "afl/afl-fuzz.h"
#include "bluetooth/bluetooth.h"
#include "migration/qemu-file.h"
#include "panda/buzzer.h"
#include "panda/debug.h"
#include "panda/rr/rr_log.h"
#include "panda/rr/rr_api.h"
#include "panda/rr/rr_log_all.h"
#include "panda/tcg-utils.h"
#include "qemu-common.h"

#include "qemu/typedefs.h"
#include "qemu/main-loop.h"
#include "sysemu/sysemu.h"
#include "vl.h"
#include "panda/kernelinfo.h"

buzzer_state_t* buzzer;
static QEMUTimer* recv_timeout_timer;
static QEMUTimer* recv_complete_timer;
static bool first_message = true;
static uint64_t recv_time;

static void on_timeout(void* opaque) {
    message_t* message;
    message = (message_t*)buzzer->shmem_message;
    message->size = 0;
    message->type = FUZZ_RECV_TMOUT;
    message->time = BZ_TMOUT_MS * 1000;
    timer_del(recv_timeout_timer);
    send_stat(STAT_RUN_TMOUT);
}

void buzzer_on_serial_recv(uint8_t* buf, uint32_t size) {
    message_t* message;
    message = (message_t*)buzzer->shmem_message;
    if (likely(first_message)) {
        message->size = size;
        message->type = FUZZ_RECV_OK;
        message->time = qemu_clock_get_us(QEMU_CLOCK_VIRTUAL) - recv_time;
        memcpy(message->data, buf, size);
        first_message = false;

    } else {
        memcpy(&message->data[message->size], buf, size);
        message->size += size;
    }
        
    timer_del(recv_timeout_timer);
    timer_mod(recv_complete_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 
        buzzer->char_transmit_time * BZ_RECV_TMOUT_SCALE * 2);
}

void buzzer_on_recv_complete(void* opaque) {
    timer_del(recv_complete_timer);
    send_stat(STAT_RUN_OK);
}

static void on_ctrl_recv(void* opaque) {
    int cmd = recv_ctrl();
    if (cmd == CTRL_CREATE_FSRV) {
        buzzer->stop_cpu = true;

    } else if (likely(cmd == CTRL_STEP_ONE)) {
        message_t* header = (message_t*)buzzer->shmem_message;
        first_message = true;
        recv_time = qemu_clock_get_us(QEMU_CLOCK_VIRTUAL);
        char_buzzer_send_packet(header->data, header->size);
        send_stat(STAT_STEP_ONE);
        timer_mod(recv_timeout_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + BZ_TMOUT_MS);

    } else if (cmd == CTRL_EXIT) {
        if (unlikely(rr_in_record())) {
            buzzer_on_record_end();
        }
        exit(0);
    }
}

void buzzer_on_record_end(void) {
    rr_record_end_of_log();
    rr_finalize_write_log();   
}

void buzzer_on_replay_end(void) {
    exit(0);
}


void buzzer_callback_after_machine_init(void) {
    qemu_set_fd_handler(CTRL_READ_FD, on_ctrl_recv, NULL, NULL);
    recv_timeout_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, on_timeout, NULL);
    recv_complete_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, buzzer_on_recv_complete, NULL);
}

void buzzer_reset(void) {
    timer_del(recv_timeout_timer);
    timer_del(recv_complete_timer);
    char_buzzer_reset();
}

void buzzer_replay_pklg(char* path) {
    uint32_t message_cnt = 0;
    message_t* message = realloc(NULL, sizeof(message_t));
    FILE* f = fopen(path, "rb");

    fread(&message_cnt, sizeof(uint32_t), 1, f);

    for (uint32_t i = 0; i < message_cnt; ++i) {
        fread(message, sizeof(*message), 1, f);

        message = realloc(message, message->size + sizeof(message_t));

        fread(message->data, 1, message->size, f);

        if (message->type != FUZZ_SEND)
            continue;

        memcpy(buzzer->shmem_message, message, message->size + sizeof(message_t));

        send_ctrl_step_one();
        recv_stat();
    }
}

static void launch_children(void) {

    int ctrl_pipe[2], stat_pipe[2];

    pipe(ctrl_pipe);
    pipe(stat_pipe);

    
    // launch qemu executor
    pid_t pid = fork();
    
    if (!pid) {
        dup2(stat_pipe[1], STAT_WRITE_FD);
        dup2(ctrl_pipe[0], CTRL_READ_FD);
        close(ctrl_pipe[0]);
        close(ctrl_pipe[1]);
        close(stat_pipe[0]);
        close(stat_pipe[1]);

        buzzer->root_fsrv = getpid();
        buzzer->bb_map = shm_hash_map_new(MAP_SIZE << 2);
        return;
    }

    dup2(stat_pipe[0], STAT_READ_FD);
    dup2(ctrl_pipe[1], CTRL_WRITE_FD);
    close(ctrl_pipe[0]);
    close(ctrl_pipe[1]);
    close(stat_pipe[0]);
    close(stat_pipe[1]);

    // buzzer_fuzz_loop(pid);
    
    // Wait for initial packet
    ACTF("wait init packet");
    ck_recv_stat(STAT_RUN_OK);
    OKF("Buzzer up. Recvd initial packet:");
    message_t* initial_message = (message_t*)buzzer->shmem_message;
    qemu_hexdump(initial_message->data, stdout, "recv", initial_message->size);

    if (buzzer->replay_path[0] != '\0') {
        buzzer_replay_pklg(buzzer->replay_path);
        kill(pid, SIGKILL);
        exit(0);
    }

    // Create forkserver
    send_ctrl_create_fsrv();

    afl_run(pid);
}

int buzzer_main(int argc, char **argv, char **envp) {

    if (!strcmp(basename(argv[0]), "buzzer-fuzz")) {
        buzzer = mmap(NULL, sizeof(buzzer_state_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        buzzer->shmem_message = mmap(NULL, MAX_FILE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        buzzer->shmem_trace_child = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        buzzer->shmem_trace_mother = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        buzzer->shmem_trace_root = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        buzzer->shmem_trace = buzzer->shmem_trace_root;
        buzzer->in_buzzer_mode = true;
        launch_children();
    } 
    return main_aux(argc, argv, envp, PANDA_NORMAL);
}
