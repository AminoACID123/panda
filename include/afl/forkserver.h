/*
   american fuzzy lop++ - forkserver header
   ----------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#ifndef __AFL_FORKSERVER_H
#define __AFL_FORKSERVER_H

#include <stdio.h>
#include <stdbool.h>

#include "afl/types.h"

typedef struct afl_forkserver {

  /* a program that includes afl-forkserver needs to define these */

  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */
  u8* trace_bits_child;
  u8* trace_bits_mother;

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      child_status,                     /* waitpid result for the child     */
      out_dir_fd;                       /* FD of the lock file              */

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */
      dev_urandom_fd,                   /* Persistent fd for /dev/urandom   */

      dev_null_fd,                      /* Persistent fd for /dev/null      */
      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 init_tmout;                       /* Configurable init timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */
  u32 real_map_size;                    /* real map size, unaligned         */
  u32 snapshot;                         /* is snapshot feature used         */
  u64 mem_limit;                        /* Memory cap for child (MB)        */

  u64 total_execs;                      /* How often run_target was called  */

  char *out_file,                         /* File to fuzz, if any             */
      *target_path;                     /* Path of the target               */

  FILE *plot_file;                      /* Gnuplot output file              */

  /* Note: last_run_timed_out is u32 to send it to the child as 4 byte array */
  u32 last_run_timed_out;               /* Traced process timed out?        */

  u8 last_kill_signal;                  /* Signal that killed the child     */

  bool use_shmem_fuzz;                  /* use shared mem for test cases    */

  bool support_shmem_fuzz;              /* set by afl-fuzz                  */

  bool use_fauxsrv;                     /* Fauxsrv for non-forking targets? */

  bool qemu_mode;                       /* if running in qemu mode or not   */

  bool frida_mode;                     /* if running in frida mode or not   */

  bool frida_asan;                    /* if running with asan in frida mode */

  bool cs_mode;                      /* if running in CoreSight mode or not */

  bool use_stdin;                       /* use stdin for sending data       */

  bool no_unlink;                       /* do not unlink cur_input          */

  bool uses_asan;                       /* Target uses ASAN?                */

  bool debug;                           /* debug mode?                      */

  bool uses_crash_exitcode;             /* Custom crash exitcode specified? */
  u8   crash_exitcode;                  /* The crash exitcode specified     */

  u32 *shmem_fuzz_len;                  /* length of the fuzzing test case  */

  u8 *shmem_fuzz;                       /* allocated memory for fuzzing     */

  char *cmplog_binary;                  /* the name of the cmplog binary    */

  /* persistent mode replay functionality */
  u32 persistent_record;                /* persistent replay setting        */
#ifdef AFL_PERSISTENT_RECORD
  u32  persistent_record_idx;           /* persistent replay cache ptr      */
  u32  persistent_record_cnt;           /* persistent replay counter        */
  u8  *persistent_record_dir;
  u8 **persistent_record_data;
  u32 *persistent_record_len;
  s32  persistent_record_pid;
#endif

  /* Function to kick off the forkserver child */
  void (*init_child_func)(struct afl_forkserver *fsrv, char **argv);

  u8 *afl_ptr;                          /* for autodictionary: afl ptr      */

  u8 child_kill_signal;
  u8 fsrv_kill_signal;

  u8 persistent_mode;

  pid_t children[MAX_CHILDREN];
  int child_cur;

  u8 incremental_trace_bits;

} afl_forkserver_t;

typedef enum fsrv_run_result {

  /* 00 */ FSRV_RUN_OK = 0,
  /* 01 */ FSRV_RUN_TMOUT,
  /* 02 */ FSRV_RUN_CRASH,
  /* 03 */ FSRV_RUN_ERROR

} fsrv_run_result_t;

void afl_fsrv_init(afl_forkserver_t *fsrv);
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from);
void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output);
u32  afl_fsrv_get_mapsize(afl_forkserver_t *fsrv, char **argv,
                          volatile u8 *stop_soon_p, u8 debug_child_output);
void afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len);
fsrv_run_result_t afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
                                      volatile u8 *stop_soon_p);
pid_t afl_fsrv_push_child(afl_forkserver_t* fsrv, pid_t pid);
pid_t afl_fsrv_pop_child(afl_forkserver_t* fsrv, pid_t pid);
void              afl_fsrv_killall(void);
void              afl_fsrv_deinit(afl_forkserver_t *fsrv);
void              afl_fsrv_kill(afl_forkserver_t *fsrv);

#endif
