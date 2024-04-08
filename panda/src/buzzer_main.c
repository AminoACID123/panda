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
static bool fuzz_rcvd = false;
static uint64_t recv_time;

// static void on_timeout(void* opaque) {
//     message_t* message = mbuf_fuzz_recv();
//     message->size = 0;
//     message->type = FUZZ_RECV_TMOUT;
//     message->time = BZ_TMOUT_MS * 1000;
//     timer_del(recv_timeout_timer);
//     send_stat(STAT_RUN_TMOUT);
// }

// void buzzer_on_serial_recv(uint8_t* buf, uint32_t size) {
//     message_t* message = mbuf_fuzz_recv();
//     if (likely(first_message)) {
//         message->size = size;
//         message->type = FUZZ_RECV_OK;
//         message->time = qemu_clock_get_us(QEMU_CLOCK_VIRTUAL) - recv_time;
//         memcpy(message->data, buf, size);
//         first_message = false;

//     } else {
//         memcpy(&message->data[message->size], buf, size);
//         message->size += size;
//     }
        
//     timer_del(recv_timeout_timer);
//     timer_mod(recv_complete_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 
//         buzzer->char_transmit_time * BZ_RECV_TMOUT_SCALE * 2);
// }

// void buzzer_on_recv_complete(void* opaque) {
//     timer_del(recv_complete_timer);
//     send_stat(STAT_RUN_OK);
// }

static void on_ctrl_recv(void* opaque) {
    int cmd = recv_ctrl();
    if (cmd == CTRL_CREATE_FSRV) {
        buzzer->stop_cpu = true;
    } 
    // else if (likely(cmd == CTRL_STEP_ONE)) {
    //     message_t* header = mbuf_fuzz_send();
    //     first_message = true;
    //     recv_time = qemu_clock_get_us(QEMU_CLOCK_VIRTUAL);
    //     char_buzzer_send_packet(header->data, header->size);
    //     send_stat(STAT_STEP_ONE);
    //     timer_mod(recv_timeout_timer,
    //         qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + BZ_TMOUT_MS);
    // }
    else if (cmd == CTRL_EXIT) {
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
    // recv_timeout_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, on_timeout, NULL);
    // recv_complete_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, buzzer_on_recv_complete, NULL);
}

void __hot controller_send(uint8_t* buf, int len)
{
    int send_len;
    do {
        send_len = write(buzzer->sock_controller, buf, len);
        if (send_len < 0) {
            FATAL("Controller send failed");
        }
        len -= send_len;
    } while(len > 0);
}

void __hot controller_send_iov(struct iovec* iov, int cnt)
{
    writev(buzzer->sock_controller, iov, cnt);
}

int __hot controller_recv(uint8_t* buf, int tmout_ms)
{
    int sret, fd;
    fd_set fdset;
    struct timeval timeout;

    fd = buzzer->sock_controller;
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);

    timeout.tv_sec = (tmout_ms / 1000);
    timeout.tv_usec = (tmout_ms % 1000) * 1000;

    do {
        sret = select(fd + 1, &fdset, NULL, NULL, &timeout);
    } while (sret < 0 && errno == EINTR);

    if (sret == 0) {
        return -2;
    }

    return read(buzzer->sock_controller, buf, BZ_BUF_MAX);
}

void buzzer_reset(void) {
    timer_del(recv_timeout_timer);
    timer_del(recv_complete_timer);
    char_buzzer_reset();
}

void buzzer_reset_timers(void) {
    timer_del(recv_timeout_timer);
    timer_del(recv_complete_timer);
}

static void buzzer_replay_pklg(char* path) {
    int stat;
    uint32_t message_cnt = 0;
    message_t* message = realloc(NULL, sizeof(message_t));
    FILE* f = fopen(path, "rb");

    fread(&message_cnt, sizeof(uint32_t), 1, f);

    for (uint32_t i = 0; i < message_cnt; ++i) {
        fread(message, sizeof(*message), 1, f);

        message = realloc(message, message->size + sizeof(message_t));

        fread(message->data, 1, message->size, f);

        if (message->type != FUZZ_SEND) {
            continue;
        }

        // memcpy(buzzer->shmem_message_fuzz_send, message, message->size + sizeof(message_t));
        controller_send(message->data, message->size);
        controller_recv(buzzer->mbuf, BZ_TMOUT_MS);

        // send_ctrl_step_one();

        // stat = recv_stat();

    }
}

static void launch_children(void)
{
    struct sockaddr_un addr;
    int len, sk, on = 1, ctrl_pipe[2], stat_pipe[2];

    pipe(ctrl_pipe);
    pipe(stat_pipe);

    sk = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = PF_UNIX;
    strcpy(addr.sun_path, BZ_SOCKET);
    remove(BZ_SOCKET);
    // ioctl(sk, FIONBIO, (char*)&on);
    bind(sk, (struct sockaddr*)&addr, sizeof(addr));
    listen(sk, 3);
    
    // launch qemu executor
    pid_t pid = fork();
    
    if (!pid) {
        dup2(stat_pipe[1], STAT_WRITE_FD);
        dup2(ctrl_pipe[0], CTRL_READ_FD);
        close(ctrl_pipe[0]);
        close(ctrl_pipe[1]);
        close(stat_pipe[0]);
        close(stat_pipe[1]);
        close(sk);

        buzzer->root_fsrv = getpid();
        buzzer->bb_map = shm_hash_map_new(MAP_SIZE << 2);

        sk = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        connect(sk, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
        buzzer->sock_host = sk;

        return;
    }

    dup2(stat_pipe[0], STAT_READ_FD);
    dup2(ctrl_pipe[1], CTRL_WRITE_FD);
    close(ctrl_pipe[0]);
    close(ctrl_pipe[1]);
    close(stat_pipe[0]);
    close(stat_pipe[1]);

    // buzzer_fuzz_loop(pid);
    buzzer->sock_controller = accept(sk, 0, 0);
    OKF("Socket connected: %d", buzzer->sock_controller);

    buzzer->mbuf_len = controller_recv(buzzer->mbuf, BZ_TMOUT_MS * 200);
    if (buzzer->mbuf_len < 0) {
        FATAL("Failed to recv initial message: %d", len);
    }

    OKF("Buzzer up. Recvd initial packet:");
    qemu_hexdump(buzzer->mbuf, stdout, "recv", buzzer->mbuf_len);

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
        // We do all the mmap here
        uint32_t* ptr;
        int prot = PROT_READ | PROT_WRITE;
        int flags = MAP_SHARED | MAP_ANONYMOUS;

        // Allocate for buzzer_state_t core data structure
        buzzer = mmap(NULL, sizeof(buzzer_state_t), prot, flags, -1, 0);

        buzzer->tmout.tv_sec = BZ_TMOUT_MS / 1000;
        buzzer->tmout.tv_usec = (BZ_TMOUT_MS % 1000) * 1000;

        buzzer->exec_fail_sig = EXEC_FAIL_SIG;

        // Allocate buffer to send fuzz input
        buzzer->mbuf = malloc(BZ_BUF_MAX);

        // Trace bits of machine startup
        ptr = mmap(NULL, MAP_SIZE + 4, prot, flags, -1, 0);
        buzzer->shmem_trace_root = (uint8_t*)&ptr[1];

        // Trace bits of prefix message
        ptr = mmap(NULL, MAP_SIZE + 4, prot, flags, -1, 0);
        buzzer->shmem_trace_mother = (uint8_t*)&ptr[1];

        // Trace bits of a forked child
        ptr = mmap(NULL, MAP_SIZE + 4, prot, flags, -1, 0);
        buzzer->shmem_trace_child = (uint8_t*)&ptr[1];

        buzzer->shmem_trace = buzzer->shmem_trace_root;

        buzzer->in_buzzer_mode = true;

        launch_children();

    } 
    return main_aux(argc, argv, envp, PANDA_NORMAL);
}
