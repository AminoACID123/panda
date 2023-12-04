/*
   american fuzzy lop++ - forkserver code
   --------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>


   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#include "afl/config.h"
#include "afl/types.h"
#include "afl/debug.h"
#include "afl/common.h"
#include "afl/list.h"
#include "afl/forkserver.h"
#include "afl/hash.h"
#include "panda/buzzer.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>



/**
 * The correct fds for reading and writing pipes
 */

/* Describe integer as memory size. */

static list_t fsrv_list = {.element_prealloc_count = 0};

static void fsrv_exec_child(afl_forkserver_t *fsrv, char **argv) {

  if (fsrv->qemu_mode || fsrv->cs_mode) {

    setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0);

  }

  execv(fsrv->target_path, argv);

  WARNF("Execv failed in forkserver.");

}

/* Initializes the struct */

void afl_fsrv_init(afl_forkserver_t *fsrv) {

  fsrv->child_cur = -1;

  // this structure needs default so we initialize it if this was not done
  // already
  fsrv->out_fd = -1;
  fsrv->out_dir_fd = -1;
  fsrv->dev_null_fd = -1;
  fsrv->dev_urandom_fd = -1;

  /* Settings */
  fsrv->use_stdin = true;
  fsrv->no_unlink = false;
  fsrv->exec_tmout = EXEC_TIMEOUT;
  fsrv->init_tmout = EXEC_TIMEOUT * FORK_WAIT_MULT;
  fsrv->mem_limit = MEM_LIMIT;
  fsrv->out_file = NULL;
  fsrv->child_kill_signal = SIGKILL;

  /* exec related stuff */
  fsrv->child_pid = -1;
  fsrv->map_size = MAP_SIZE;
  fsrv->real_map_size = fsrv->map_size;
  fsrv->use_fauxsrv = false;
  fsrv->last_run_timed_out = false;
  fsrv->debug = false;
  fsrv->uses_crash_exitcode = false;
  fsrv->uses_asan = false;

  fsrv->trace_bits_child = buzzer->shmem_trace_child;
  fsrv->trace_bits_mother = buzzer->shmem_trace_mother;

  fsrv->shmem_fuzz = buzzer->shmem_message;

  fsrv->init_child_func = fsrv_exec_child;
  list_append(&fsrv_list, fsrv);

}

/* Initialize a new forkserver instance, duplicating "global" settings */
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from) {

  fsrv_to->use_stdin = from->use_stdin;
  fsrv_to->dev_null_fd = from->dev_null_fd;
  fsrv_to->exec_tmout = from->exec_tmout;
  fsrv_to->init_tmout = from->init_tmout;
  fsrv_to->mem_limit = from->mem_limit;
  fsrv_to->map_size = from->map_size;
  fsrv_to->real_map_size = from->real_map_size;
  fsrv_to->support_shmem_fuzz = from->support_shmem_fuzz;
  fsrv_to->out_file = from->out_file;
  fsrv_to->dev_urandom_fd = from->dev_urandom_fd;
  fsrv_to->out_fd = from->out_fd;  // not sure this is a good idea
  fsrv_to->no_unlink = from->no_unlink;
  fsrv_to->uses_crash_exitcode = from->uses_crash_exitcode;
  fsrv_to->crash_exitcode = from->crash_exitcode;
  fsrv_to->child_kill_signal = from->child_kill_signal;
  fsrv_to->fsrv_kill_signal = from->fsrv_kill_signal;
  fsrv_to->debug = from->debug;

  // These are forkserver specific.
  fsrv_to->out_dir_fd = -1;
  fsrv_to->child_pid = -1;
  fsrv_to->use_fauxsrv = 0;
  fsrv_to->last_run_timed_out = 0;

  fsrv_to->init_child_func = from->init_child_func;

  list_append(&fsrv_list, fsrv_to);

}

/* Wrapper for select() and read(), reading a 32 bit var.
  Returns the time passed to read.
  If the wait times out, returns timeout_ms + 1;
  Returns 0 if an error occurred (fd closed, signal, ...); */
static u32 __attribute__((hot))
read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms, volatile u8 *stop_soon_p) {

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  struct timeval timeout;
  int            sret;
  ssize_t        len_read;

  timeout.tv_sec = (timeout_ms / 1000);
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
#if !defined(__linux__)
  u32 read_start = get_cur_time_us();
#endif

  /* set exceptfds as well to return when a child exited/closed the pipe. */
restart_select:
  sret = select(fd + 1, &readfds, NULL, NULL, &timeout);

  if (likely(sret > 0)) {

  restart_read:
    if (*stop_soon_p) {

      // Early return - the user wants to quit.
      return 0;

    }

    len_read = read(fd, (u8 *)buf, 4);

    if (likely(len_read == 4)) {  // for speed we put this first

#if defined(__linux__)
      u32 exec_ms = MIN(
          timeout_ms,
          ((u64)timeout_ms - (timeout.tv_sec * 1000 + timeout.tv_usec / 1000)));
#else
      u32 exec_ms = MIN(timeout_ms, (get_cur_time_us() - read_start) / 1000);
#endif

      // ensure to report 1 ms has passed (0 is an error)
      return exec_ms > 0 ? exec_ms : 1;

    } else if (unlikely(len_read == -1 && errno == EINTR)) {

      goto restart_read;

    } else if (unlikely(len_read < 4)) {

      return 0;

    }

  } else if (unlikely(!sret)) {

    *buf = -1;
    return timeout_ms + 1;

  } else if (unlikely(sret < 0)) {

    if (likely(errno == EINTR)) goto restart_select;

    *buf = -1;
    return 0;

  }

  return 0;  // not reached

}

/* Internal forkserver for non_instrumented_mode=1 and non-forkserver mode runs.
  It execvs for each fork, forwarding exit codes and child pids to afl. */

static void afl_fauxsrv_execv(afl_forkserver_t *fsrv, char **argv) {

  unsigned char tmp[4] = {0, 0, 0, 0};
  pid_t         child_pid;

  if (!be_quiet) { ACTF("Using Fauxserver:"); }

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {

    abort();  // TODO: Abort?

  }

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  while (1) {

    uint32_t was_killed;
    int      status;

    /* Wait for parent by reading from the pipe. Exit if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) { exit(0); }

    /* Create a clone of our process. */

    child_pid = fork();

    if (child_pid < 0) { PFATAL("Fork failed"); }

    /* In child process: close fds, resume execution. */

    if (!child_pid) {  // New child

      close(fsrv->out_dir_fd);
      close(fsrv->dev_null_fd);
      close(fsrv->dev_urandom_fd);

      if (fsrv->plot_file != NULL) {

        fclose(fsrv->plot_file);
        fsrv->plot_file = NULL;

      }

      // enable terminating on sigpipe in the childs
      struct sigaction sa;
      memset((char *)&sa, 0, sizeof(sa));
      sa.sa_handler = SIG_DFL;
      sigaction(SIGPIPE, &sa, NULL);

      signal(SIGCHLD, old_sigchld_handler);

      // FORKSRV_FD is for communication with AFL, we don't need it in the
      // child
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      // finally: exec...
      execv(fsrv->target_path, argv);

      /* Use a distinctive bitmap signature to tell the parent about execv()
        falling through. */

      *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;

      WARNF("Execv failed in fauxserver.");
      break;

    }

    /* In parent process: write PID to AFL. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) { exit(0); }

    /* after child exited, get and relay exit status to parent through waitpid.
     */

    if (waitpid(child_pid, &status, 0) < 0) {

      // Zombie Child could not be collected. Scary!
      WARNF("Fauxserver could not determine child's exit code. ");

    }

    /* Relay wait status to AFL pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) { exit(1); }

  }

}

/* Report on the error received via the forkserver controller and exit */
static void report_error_and_exit(int error) {

  switch (error) {

    case FS_ERROR_MAP_SIZE:
      FATAL(
          "AFL_MAP_SIZE is not set and fuzzing target reports that the "
          "required size is very large. Solution: Run the fuzzing target "
          "stand-alone with the environment variable AFL_DEBUG=1 set and set "
          "the value for __afl_final_loc in the AFL_MAP_SIZE environment "
          "variable for afl-fuzz.");
      break;
    case FS_ERROR_MAP_ADDR:
      FATAL(
          "the fuzzing target reports that hardcoded map address might be the "
          "reason the mmap of the shared memory failed. Solution: recompile "
          "the target with either afl-clang-lto and do not set "
          "AFL_LLVM_MAP_ADDR or recompile with afl-clang-fast.");
      break;
    case FS_ERROR_SHM_OPEN:
      FATAL("the fuzzing target reports that the shm_open() call failed.");
      break;
    case FS_ERROR_SHMAT:
      FATAL("the fuzzing target reports that the shmat() call failed.");
      break;
    case FS_ERROR_MMAP:
      FATAL(
          "the fuzzing target reports that the mmap() call to the shared "
          "memory failed.");
      break;
    case FS_ERROR_OLD_CMPLOG:
      FATAL(
          "the -c cmplog target was instrumented with an too old AFL++ "
          "version, you need to recompile it.");
      break;
    case FS_ERROR_OLD_CMPLOG_QEMU:
      FATAL(
          "The AFL++ QEMU/FRIDA loaders are from an older version, for -c you "
          "need to recompile it.\n");
      break;
    default:
      FATAL("unknown error code %d from fuzzing target!", error);

  }

}

/* Delete the current testcase and write the buf to the testcase file */

void __attribute__((hot))
afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len) {

}

pid_t afl_fsrv_push_child(afl_forkserver_t* fsrv, pid_t pid) {
  fsrv->children[++fsrv->child_cur] = pid;
  return pid;
}

pid_t afl_fsrv_pop_child(afl_forkserver_t* fsrv, pid_t child) {
  pid_t expected_pid = fsrv->children[fsrv->child_cur--];
  if (unlikely(expected_pid != child))
    FATAL("Wrong child pid: recv %d, expect %d", child, expected_pid);
  return child;
}

void afl_fsrv_killall(void) {

  LIST_FOREACH(&fsrv_list, afl_forkserver_t, {

    afl_fsrv_kill(el);

  });

}

void afl_fsrv_deinit(afl_forkserver_t *fsrv) {

  afl_fsrv_kill(fsrv);
  list_remove(&fsrv_list, fsrv);

}

void afl_fsrv_kill(afl_forkserver_t *fsrv) {

  if (fsrv->child_pid > 0) { kill(fsrv->child_pid, fsrv->child_kill_signal); }
  if (fsrv->fsrv_pid > 0) {

    kill(fsrv->fsrv_pid, fsrv->fsrv_kill_signal);
    waitpid(fsrv->fsrv_pid, NULL, 0);

  }

  close(fsrv->fsrv_ctl_fd);
  close(fsrv->fsrv_st_fd);
  fsrv->fsrv_pid = -1;
  fsrv->child_pid = -1;

}

