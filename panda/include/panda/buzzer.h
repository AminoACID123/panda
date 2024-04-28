#ifndef _BUZZER_H
#define _BUZZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "afl/debug.h"
#include "panda/compiler.h"
#include "panda/kernelinfo.h"
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define BZ_TMOUT_MS 100
#define BZ_RECV_TMOUT_SCALE 4
#define BZ_MSG_SIZE (1 << 16)
#define BZ_TRACE_SIZE (1 << 20)
#define BZ_REPLAY_LOG "/tmp/buzzer-log"
#define BZ_SOCKET "/tmp/buzzer.sock"

#define BZ_ACL_MTU      1024
#define BZ_SCO_MTU      255
#define BZ_ACL_MAX_PKT  5
#define BZ_SCO_MAX_PKT  5

// Control commands
enum {
  CTRL_STOP_CPU = 1, // Stop virtual cpu but do not exit process
  CTRL_EXIT,         // Exit the current session (used in record mode)
  CTRL_EXIT_COV,     // Exit the current session and report coverage
  CTRL_STEP_ONE,     // Process a single message
  CTRL_CFM_RUN,
  CTRL_CREATE_FSRV,       // Create forkserver
  CTRL_EXIT_FSRV,         // Exit forkserver
  CTRL_START_NORMAL,      // Start a normal fuzz session
  CTRL_START_RECORD,      // Start a record fuzz session
  CTRL_EXTRACT_EVENTS,    // Extract event types of IUT
  CTRL_EXTRACT_LE_EVENTS, // Extract le event types of IUT
};

enum {
  STAT_FSRV_UP = 0, // Forkserver is up
  // STAT_CHILD_EXIT,  // A session completed (child exited)
  // STAT_STEP_ONE,    // A single message has been received and processed
  // STAT_RUN_ERROR,   // Something is wrong with fuzz execution
  // STAT_RUN_CRASH,   // The input message results in a crash
  // STAT_RUN_TMOUT,   // The input message results in a timeout
  // STAT_RUN_OK       // A reply message has been received
};

enum {
  LINUX_USER = 0,
  LINUX_KERNEL,
};

enum { TASK_FUZZ = 0, TASK_EXTRACT_EVENTS, TASK_EXTRACT_LE_EVENTS, PKT_DEP };

enum { EXEC_OK = 0, EXEC_TMOUT, EXEC_CRASH, EXEC_ASAN };

enum { EXEC_COV_NONE, EXEC_COV_NEW, EXEC_COV_NEW_COUNT };

struct QEMUFile;

typedef struct __packed {
  uint16_t size;
  uint16_t type;
  uint16_t time;
  uint8_t data[];
} MessageHeader;

typedef struct __packed {
  uint32_t exec_ms;
  uint8_t exec_result;
  uint8_t exec_cov;
} ExecStatus;

typedef struct __packed {
  bool terminate;
  uint32_t count;
  uint32_t data[];
} AnalyzeResult;

#define BZ_BUF_MAX 65536
typedef struct buzzer_state {
  /* Fuzzer setup*/
  bool disable_le, disable_bredr;
  bool kernel_mode;
  char args[PATH_MAX];
  char out_dir[PATH_MAX];
  char target_dir[PATH_MAX];
  char target_file[PATH_MAX];
  char replay_path[PATH_MAX];
  char crash_message[PATH_MAX];
  bool enable_guest_print;
  bool enable_asan;
  bool no_ui, no_ack;
  int device_no;

  /* Runtime */
  int stat_pipe[2];
  int ctrl_pipe[2];
  int c2h_data_pipe[2];
  int h2c_data_pipe[2];

  // int sock_host;
  // int sock_controller;
  uint32_t exec_fail_sig;
  struct timeval tmout;
  bool stop_cpu;
  bool in_buzzer_mode;
  bool update_bb_map;
  bool update_parent_bb_map;
  kernelinfo kernel_info;
  pid_t root_fsrv;
  uint32_t char_transmit_time;
  uint8_t current_task;
  uint8_t target_type;
  uint8_t *mbuf;
  int mbuf_len;
  uint8_t *shmem_trace;
  uint8_t *shmem_trace_child;
  uint8_t *shmem_trace_mother;
  uint8_t *shmem_trace_root;

  uint16_t acl_mtu;
  uint16_t acl_max_pkt;

  bool exec_speed_abnormal;

  void* bb_map;
  
} buzzer_state_t;

extern buzzer_state_t *buzzer;

void buzzer_load_plugins(void);
void buzzer_init_plugins(void);
void buzzer_on_record_end(void);
void buzzer_on_replay_end(void);
void buzzer_on_serial_recv(uint8_t *buf, uint32_t size);
void char_buzzer_send_packet(uint8_t *data, int len);
void char_buzzer_send_packet_v(const struct iovec *iov, int iovcnt);
void buzzer_callback_after_machine_init(void);

void buzzer_reset(void);

void controller_send(uint8_t* buf, int len);
int controller_recv(uint8_t* buf, int tmout_ms);
int controller_recv_ack(int tmout_ms);
int controller_recv_nowait(uint8_t *buf);
void controller_recv_drain(uint8_t *buf);
void host_send(uint8_t* buf, int len);
int host_recv(uint8_t* buf, int tmout_ms);
void host_recv_drain(uint8_t *buf);

void *shm_hash_map_new(size_t n);
void shm_hash_map_reserve(void *opaque, size_t n);
uint32_t shm_hash_map_insert(void *opaque, uint64_t key);
uint32_t shm_hash_map_lookup(void *opaque, uint64_t key);
uint64_t shm_hash_map_lookup_value(void* opaque, uint32_t value);

#define send_ctrl(_ctrl)                                                       \
  do {                                                                         \
    int __ctrl = _ctrl;                                                        \
    write(buzzer->ctrl_pipe[1], &__ctrl, sizeof(__ctrl));                      \
  } while (0);

#define recv_ctrl()                                                            \
  ({                                                                           \
    int _ctrl;                                                                 \
    read(buzzer->ctrl_pipe[0], &_ctrl, sizeof(_ctrl));                         \
    _ctrl;                                                                     \
  })

#define send_stat(_stat)                                                       \
  do {                                                                         \
    int __stat = _stat;                                                        \
    write(buzzer->stat_pipe[1], &__stat, sizeof(__stat));                      \
  } while (0);

#define recv_stat()                                                            \
  ({                                                                           \
    int _stat;                                                                 \
    read(buzzer->stat_pipe[0], &_stat, sizeof(_stat));                         \
    _stat;                                                                     \
  })

#define ck_recv_stat(_stat)                                                    \
  do {                                                                         \
    int __stat = recv_stat();                                                  \
    if (unlikely(__stat != _stat))                                             \
      FATAL("Wrong status: %d, expected %d", __stat, _stat);                   \
  } while (0);

#define ck_recv_stat2(_stat1, _stat2)                                          \
  do {                                                                         \
    int __stat = recv_stat();                                                  \
    if (unlikely(__stat != _stat1 && __stat != _stat2))                        \
      FATAL("Wrong status: %d, expected %d or %d", __stat, _stat1, _stat2);    \
  } while (0);

#define send_ctrl_step_one()                                                   \
  do {                                                                         \
    send_ctrl(CTRL_STEP_ONE);                                                  \
    ck_recv_stat(STAT_STEP_ONE);                                               \
  } while (0);

#define send_ctrl_create_fsrv()                                                \
  do {                                                                         \
    send_ctrl(CTRL_CREATE_FSRV);                                               \
    ck_recv_stat(STAT_FSRV_UP);                                                \
  } while (0);

#define send_ctrl_exit_fsrv()                                                  \
  ({                                                                           \
    int _tmp;                                                                  \
    send_ctrl(CTRL_EXIT_FSRV);                                                 \
    _tmp = recv_stat();                                                        \
    _tmp;                                                                      \
  })

#define send_ctrl_start_normal()                                               \
  ({                                                                           \
    int _tmp;                                                                  \
    send_ctrl(CTRL_START_NORMAL);                                              \
    _tmp = recv_stat();                                                        \
    _tmp;                                                                      \
  })

#define send_ctrl_exit()                                                       \
  ({                                                                           \
    int _tmp;                                                                  \
    send_ctrl(CTRL_EXIT);                                                      \
    _tmp = recv_stat();                                                        \
    _tmp;                                                                      \
  })

#ifdef __cplusplus
}
#endif

#endif // _BUZZER_FUZZ_H