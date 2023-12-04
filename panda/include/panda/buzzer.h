#ifndef _BUZZER_H
#define _BUZZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "afl/debug.h"
#include "panda/compiler.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define BZ_TMOUT_MS 100
#define BZ_MSG_SIZE (1 << 16)
#define BZ_TRACE_SIZE (1 << 20)
#define BZ_REPLAY_LOG "/tmp/buzzer-log"

#define CTRL_WRITE_FD 190
#define CTRL_READ_FD 191
#define STAT_WRITE_FD 192
#define STAT_READ_FD 193

// Control commands
typedef enum {
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
} BuzzerControl;

typedef enum {
  STAT_FSRV_UP = 0, // Forkserver is up
  STAT_CHILD_EXIT,  // A session completed (child exited)
  STAT_STEP_ONE,    // A single message has been received and processed
  STAT_RUN_ERROR,   // Something is wrong with fuzz execution
  STAT_RUN_CRASH,   // The input message results in a crash
  STAT_RUN_TMOUT,   // The input message results in a timeout
  STAT_RUN_OK       // A reply message has been received
} BuzzerStatus;

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

#define BZ_PATH_MAX 512
typedef struct buzzer_state {
  /* Fuzzer setup*/
  bool disable_le, disable_bredr;
  char args[BZ_PATH_MAX];
  char out_dir[BZ_PATH_MAX];
  char target_dir[BZ_PATH_MAX];
  char target_file[BZ_PATH_MAX];
  bool enable_asan;
  int device_no;

  /* Runtime */
  bool stop_cpu;
  bool in_buzzer_mode;
  uint8_t current_task;
  uint8_t *shmem_message;
  uint8_t *shmem_trace;
  uint8_t *shmem_trace_child;
  uint8_t *shmem_trace_mother;
} buzzer_state_t;

extern buzzer_state_t *buzzer;

void buzzer_load_plugins(void);
void buzzer_init_plugins(void);
void buzzer_fuzz_loop(pid_t pid);
void buzzer_on_record_end(void);
void buzzer_on_replay_end(void);
void buzzer_on_cpu_stop(void *opaque);
void buzzer_on_serial_recv(uint8_t *buf, uint32_t size);
void buzzer_fuzz_start(void *);
uint32_t buzzer_fuzz_step_one(uint8_t *buf, uint32_t size);
void char_buzzer_send_packet(uint8_t *data, int len);
void char_buzzer_send_packet_v(const struct iovec *iov, int iovcnt);
void buzzer_after_machine_init(void);

#define send_ctrl(_ctrl)                                                       \
  do {                                                                         \
    int __ctrl = _ctrl;                                                        \
    write(CTRL_WRITE_FD, &__ctrl, sizeof(__ctrl));                             \
  } while (0);

#define recv_ctrl()                                                            \
  ({                                                                           \
    int _ctrl;                                                                 \
    read(CTRL_READ_FD, &_ctrl, sizeof(_ctrl));                                 \
    _ctrl;                                                                     \
  })

#define send_stat(_stat)                                                       \
  do {                                                                         \
    int __stat = _stat;                                                        \
    write(STAT_WRITE_FD, &__stat, sizeof(__stat));                             \
  } while (0);

#define recv_stat()                                                            \
  ({                                                                           \
    int _stat;                                                                 \
    read(STAT_READ_FD, &_stat, sizeof(_stat));                                 \
    _stat;                                                                     \
  })

#define ck_recv_stat(_stat)                                                    \
  do {                                                                         \
    int __stat = recv_stat();                                                  \
    if (__stat != _stat)                                                       \
      FATAL("Wrong status: %d, expected %d", __stat, _stat);                   \
  } while (0);

#define send_ctrl_step_one()                                                   \
  do {                                                                         \
    send_ctrl(CTRL_STEP_ONE);                                                  \
    recv_stat();                                                               \
  } while (0);

#define send_ctrl_create_fsrv()                                                \
  ({                                                                           \
    int _tmp;                                                                  \
    send_ctrl(CTRL_CREATE_FSRV);                                               \
    _tmp = recv_stat();                                                        \
    _tmp;                                                                      \
  })

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