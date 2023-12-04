/*
   american fuzzy lop++ - common routines
   --------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Gather some functions common to multiple executables

   - detect_file_args

 */

#include <stdlib.h>
#include <stdio.h>
#include "afl/forkserver.h"
#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif
#ifndef __USE_GNU
  #define __USE_GNU
#endif
#include <string.h>
#include <strings.h>
#include <math.h>
#include <sys/mman.h>

#include "afl/debug.h"
#include "afl/alloc-inl.h"
#include "afl/common.h"

/* Detect @@ in args. */
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

u8  be_quiet = 0;
u8 *doc_path = "";
u8  last_intr = 0;

#ifndef AFL_PATH
  #define AFL_PATH "/usr/local/lib/afl/"
#endif

void *afl_memmem(const void *haystack, size_t haystacklen, const void *needle,
                 size_t needlelen) {

  if (unlikely(needlelen > haystacklen)) { return NULL; }

  for (u32 i = 0; i <= haystacklen - needlelen; ++i) {

    if (unlikely(memcmp(haystack + i, needle, needlelen) == 0)) {

      return (void *)(haystack + i);

    }

  }

  return (void *)NULL;

}

void set_sanitizer_defaults() {

  /* Set sane defaults for ASAN if nothing else is specified. */
  char *have_asan_options = getenv("ASAN_OPTIONS");
  char *have_ubsan_options = getenv("UBSAN_OPTIONS");
  char *have_msan_options = getenv("MSAN_OPTIONS");
  char *have_lsan_options = getenv("LSAN_OPTIONS");
  u8  have_san_options = 0;
  char  default_options[1024] =
      "detect_odr_violation=0:abort_on_error=1:symbolize=0:allocator_may_"
      "return_null=1:handle_segv=0:handle_sigbus=0:handle_abort=0:handle_"
      "sigfpe=0:handle_sigill=0:";

  if (have_asan_options || have_ubsan_options || have_msan_options ||
      have_lsan_options) {

    have_san_options = 1;

  }

  /* LSAN does not support abort_on_error=1. (is this still true??) */
  u8 should_detect_leaks = 0;

  if (!have_lsan_options) {

    u8 buf[2048] = "";
    if (!have_san_options) { strcpy(buf, default_options); }
    if (have_asan_options) {

      if (NULL != strstr(have_asan_options, "detect_leaks=0")) {

        strcat(buf, "exitcode=" STRINGIFY(LSAN_ERROR) ":fast_unwind_on_malloc=0:print_suppressions=0:detect_leaks=0:malloc_context_size=0:");

      } else {

        should_detect_leaks = 1;
        strcat(buf, "exitcode=" STRINGIFY(LSAN_ERROR) ":fast_unwind_on_malloc=0:print_suppressions=0:detect_leaks=1:malloc_context_size=30:");

      }

    }

    setenv("LSAN_OPTIONS", buf, 1);

  }

  /* for everything not LSAN we disable detect_leaks */

  if (!have_lsan_options) {

    if (should_detect_leaks) {

      strcat(default_options, "detect_leaks=1:malloc_context_size=30:");

    } else {

      strcat(default_options, "detect_leaks=0:malloc_context_size=0:");

    }

  }

  /* Set sane defaults for ASAN if nothing else is specified. */

  if (!have_san_options) { setenv("ASAN_OPTIONS", default_options, 1); }

  /* Set sane defaults for UBSAN if nothing else is specified. */

  if (!have_san_options) { setenv("UBSAN_OPTIONS", default_options, 1); }

  /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
     point. So, we do this in a very hacky way. */

  if (!have_msan_options) {

    u8 buf[2048] = "";
    if (!have_san_options) { strcpy(buf, default_options); }
    strcat(buf, "exit_code=" STRINGIFY(MSAN_ERROR) ":msan_track_origins=0:");
    setenv("MSAN_OPTIONS", buf, 1);

  }

  /* Envs for QASan */
  setenv("QASAN_MAX_CALL_STACK", "0", 0);
  setenv("QASAN_SYMBOLIZE", "0", 0);

}

u32 check_binary_signatures(u8 *fn) {

  int ret = 0, fd = open(fn, O_RDONLY);
  if (fd < 0) { PFATAL("Unable to open '%s'", fn); }
  struct stat st;
  if (fstat(fd, &st) < 0) { PFATAL("Unable to fstat '%s'", fn); }
  u32 f_len = st.st_size;
  u8 *f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (f_data == MAP_FAILED) { PFATAL("Unable to mmap file '%s'", fn); }
  close(fd);

  if (afl_memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1)) {

    if (!be_quiet) { OKF(cPIN "Persistent mode binary detected."); }
    setenv(PERSIST_ENV_VAR, "1", 1);
    ret = 1;

  } else if (getenv("AFL_PERSISTENT")) {

    if (!be_quiet) { OKF(cPIN "Persistent mode enforced."); }
    setenv(PERSIST_ENV_VAR, "1", 1);
    ret = 1;

  } else if (getenv("AFL_FRIDA_PERSISTENT_ADDR")) {

    if (!be_quiet) {

      OKF("FRIDA Persistent mode configuration options detected.");

    }

    setenv(PERSIST_ENV_VAR, "1", 1);
    ret = 1;

  }

  if (afl_memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1)) {

    if (!be_quiet) { OKF(cPIN "Deferred forkserver binary detected."); }
    setenv(DEFER_ENV_VAR, "1", 1);
    ret += 2;

  } else if (getenv("AFL_DEFER_FORKSRV")) {

    if (!be_quiet) { OKF(cPIN "Deferred forkserver enforced."); }
    setenv(DEFER_ENV_VAR, "1", 1);
    ret += 2;

  }

  if (munmap(f_data, f_len)) { PFATAL("unmap() failed"); }

  return ret;

}

void detect_file_args(char **argv, u8 *prog_in, bool *use_stdin) {

  u32 i = 0;
  u8  cwd[PATH_MAX];
  if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }

  /* we are working with libc-heap-allocated argvs. So do not mix them with
   * other allocation APIs like ck_alloc. That would disturb the free() calls.
   */
  while (argv[i]) {

    char *aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      if (!prog_in) { FATAL("@@ syntax is not supported by this tool."); }

      *use_stdin = false;

      /* Be sure that we're always using fully-qualified paths. */

      *aa_loc = 0;

      /* Construct a replacement argv value. */
      u8 *n_arg;

      if (prog_in[0] == '/') {

        n_arg = alloc_printf("%s%s%s", argv[i], prog_in, aa_loc + 2);

      } else {

        n_arg = alloc_printf("%s%s/%s%s", argv[i], cwd, prog_in, aa_loc + 2);

      }

      ck_free(argv[i]);
      argv[i] = n_arg;

    }

    i++;

  }

  /* argvs are automatically freed at exit. */

}

/* duplicate the system argv so that
  we can edit (and free!) it later */

char **argv_cpy_dup(int argc, char **argv) {

  int i = 0;

  char **ret = ck_alloc((argc + 1) * sizeof(char *));
  if (unlikely(!ret)) { FATAL("Amount of arguments specified is too high"); }

  for (i = 0; i < argc; i++) {

    ret[i] = ck_strdup(argv[i]);

  }

  ret[i] = NULL;

  return ret;

}

/* frees all args in the given argv,
   previously created by argv_cpy_dup */

void argv_cpy_free(char **argv) {

  u32 i = 0;
  while (argv[i]) {

    ck_free(argv[i]);
    argv[i] = NULL;
    i++;

  }

  ck_free(argv);

}


/* Find binary, used by analyze, showmap, tmin
   @returns the path, allocating the string */

u8 *find_binary(u8 *fname) {

  // TODO: Merge this function with check_binary of afl-fuzz-init.c

  u8 *env_path = NULL;
  u8 *target_path = NULL;

  struct stat st;

  if (unlikely(!fname)) { FATAL("No binary supplied"); }

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);

    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4) {

      ck_free(target_path);
      FATAL("Program '%s' not found or not executable", fname);

    }

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        if (unlikely(!cur_elem)) {

          FATAL(
              "Unexpected overflow when processing ENV. This should never "
              "had happened.");

        }

        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else {

        cur_elem = ck_strdup(env_path);

      }

      env_path = delim;

      if (cur_elem[0]) {

        target_path = alloc_printf("%s/%s", cur_elem, fname);

      } else {

        target_path = ck_strdup(fname);

      }

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4) {

        break;

      }

      ck_free(target_path);
      target_path = NULL;

    }

    if (!target_path) {

      FATAL("Program '%s' not found or not executable", fname);

    }

  }

  return target_path;

}


int parse_afl_kill_signal(char *numeric_signal_as_str, int default_signal) {

  if (numeric_signal_as_str && numeric_signal_as_str[0]) {

    char *endptr;
    u8    signal_code;
    signal_code = (u8)strtoul(numeric_signal_as_str, &endptr, 10);
    /* Did we manage to parse the full string? */
    if (*endptr != '\0' || endptr == (char *)numeric_signal_as_str) {

      FATAL("Invalid signal name: %s", numeric_signal_as_str);

    } else {

      return signal_code;

    }

  }

  return default_signal;

}

void configure_afl_kill_signals(afl_forkserver_t *fsrv,
                                char             *afl_kill_signal_env,
                                char             *afl_fsrv_kill_signal_env,
                                int               default_server_kill_signal) {

  afl_kill_signal_env =
      afl_kill_signal_env ? afl_kill_signal_env : getenv("AFL_KILL_SIGNAL");
  afl_fsrv_kill_signal_env = afl_fsrv_kill_signal_env
                                 ? afl_fsrv_kill_signal_env
                                 : getenv("AFL_FORK_SERVER_KILL_SIGNAL");

  fsrv->child_kill_signal = parse_afl_kill_signal(afl_kill_signal_env, SIGKILL);

  if (afl_kill_signal_env && !afl_fsrv_kill_signal_env) {

    /*
    Set AFL_FORK_SERVER_KILL_SIGNAL to the value of AFL_KILL_SIGNAL for
    backwards compatibility. However, if AFL_FORK_SERVER_KILL_SIGNAL is set, is
    takes precedence.
    */
    afl_fsrv_kill_signal_env = afl_kill_signal_env;

  }

  fsrv->fsrv_kill_signal = parse_afl_kill_signal(afl_fsrv_kill_signal_env,
                                                 default_server_kill_signal);

}

static inline unsigned int helper_min3(unsigned int a, unsigned int b,
                                       unsigned int c) {

  return a < b ? (a < c ? a : c) : (b < c ? b : c);

}

// from
// https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Levenshtein_distance#C
static int string_distance_levenshtein(char *s1, char *s2) {

  unsigned int s1len, s2len, x, y, lastdiag, olddiag;
  s1len = strlen(s1);
  s2len = strlen(s2);
  unsigned int column[s1len + 1];
  column[s1len] = 1;

  for (y = 1; y <= s1len; y++)
    column[y] = y;
  for (x = 1; x <= s2len; x++) {

    column[0] = x;
    for (y = 1, lastdiag = x - 1; y <= s1len; y++) {

      olddiag = column[y];
      column[y] = helper_min3(column[y] + 1, column[y - 1] + 1,
                              lastdiag + (s1[y - 1] == s2[x - 1] ? 0 : 1));
      lastdiag = olddiag;

    }

  }

  return column[s1len];

}

#define ENV_SIMILARITY_TRESHOLD 3


/* Read mask bitmap from file. This is for the -B option. */

void read_bitmap(u8 *fname, u8 *map, size_t len) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_read(fd, map, len, fname);

  close(fd);

}

/* Get unix time in milliseconds */

inline u64 get_cur_time(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Get unix time in microseconds */

u64 get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

/* Describe integer. The buf should be
   at least 6 bytes to fit all ints we randomly see.
   Will return buf for convenience. */

char *stringify_int(char *buf, size_t len, u64 val) {
\
#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast)     \
  do {                                                     \
                                                           \
    if (val < (_divisor) * (_limit_mult)) {                \
                                                           \
      snprintf(buf, len, _fmt, ((_cast)val) / (_divisor)); \
      return buf;                                          \
                                                           \
    }                                                      \
                                                           \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strncpy(buf, "infty", len);
  buf[len - 1] = '\0';

  return buf;

}

/* Describe float. Similar as int. */

char *stringify_float(char *buf, size_t len, double val) {

  if (val < 99.995) {

    snprintf(buf, len, "%0.02f", val);

  } else if (val < 999.95) {

    snprintf(buf, len, "%0.01f", val);

  } else if (unlikely(isnan(val) || isinf(val))) {

    strcpy(buf, "inf");

  } else {

    stringify_int(buf, len, (u64)val);

  }

  return buf;

}

/* Describe integer as memory size. */

char *stringify_mem_size(char *buf, size_t len, u64 val) {

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strncpy(buf, "infty", len - 1);
  buf[len - 1] = '\0';

  return buf;

}

/* Describe time delta as string.
   Returns a pointer to buf for convenience. */

char *stringify_time_diff(char *buf, size_t len, u64 cur_ms, u64 event_ms) {

  if (!event_ms) {

    snprintf(buf, len, "none seen yet");

  } else {

    u64 delta;
    s32 t_d, t_h, t_m, t_s;
    u8  val_buf[STRINGIFY_VAL_SIZE_MAX];

    delta = cur_ms - event_ms;

    t_d = delta / 1000 / 60 / 60 / 24;
    t_h = (delta / 1000 / 60 / 60) % 24;
    t_m = (delta / 1000 / 60) % 60;
    t_s = (delta / 1000) % 60;

    stringify_int(val_buf, sizeof(val_buf), t_d);
    snprintf(buf, len, "%s days, %d hrs, %d min, %d sec", val_buf, t_h, t_m,
             t_s);

  }

  return buf;

}

/* Unsafe Describe integer. The buf sizes are not checked.
   This is unsafe but fast.
   Will return buf for convenience. */

char *u_stringify_int(char *buf, u64 val) {
\
#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) \
  do {                                                 \
                                                       \
    if (val < (_divisor) * (_limit_mult)) {            \
                                                       \
      sprintf(buf, _fmt, ((_cast)val) / (_divisor));   \
      return buf;                                      \
                                                       \
    }                                                  \
                                                       \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(buf, "infty");

  return buf;

}

/* Unsafe describe float. Similar as unsafe int. */

char *u_stringify_float(char *buf, double val) {

  if (val < 99.995) {

    sprintf(buf, "%0.02f", val);

  } else if (val < 999.95) {

    sprintf(buf, "%0.01f", val);

  } else if (unlikely(isnan(val) || isinf(val))) {

    strcpy(buf, "infinite");

  } else {

    return u_stringify_int(buf, (u64)val);

  }

  return buf;

}

/* Unsafe describe integer as memory size. */

char *u_stringify_mem_size(char *buf, u64 val) {

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(buf, "infty");

  return buf;

}

/* Unsafe describe time delta as string.
   Returns a pointer to buf for convenience. */

char *u_stringify_time_diff(char *buf, u64 cur_ms, u64 event_ms) {

  if (!event_ms) {

    sprintf(buf, "none seen yet");

  } else {

    u64 delta;
    s32 t_d, t_h, t_m, t_s;
    u8  val_buf[STRINGIFY_VAL_SIZE_MAX];

    delta = cur_ms - event_ms;

    t_d = delta / 1000 / 60 / 60 / 24;
    t_h = (delta / 1000 / 60 / 60) % 24;
    t_m = (delta / 1000 / 60) % 60;
    t_s = (delta / 1000) % 60;

    u_stringify_int(val_buf, t_d);
    sprintf(buf, "%s days, %d hrs, %d min, %d sec", val_buf, t_h, t_m, t_s);

  }

  return buf;

}

/* Unsafe describe time delta as simple string.
   Returns a pointer to buf for convenience. */

u8 *u_simplestring_time_diff(char *buf, u64 cur_ms, u64 event_ms) {

  if (!event_ms) {

    sprintf(buf, "00:00:00");

  } else {

    u64 delta;
    s32 t_d, t_h, t_m, t_s;

    delta = cur_ms - event_ms;

    t_d = delta / 1000 / 60 / 60 / 24;
    t_h = (delta / 1000 / 60 / 60) % 24;
    t_m = (delta / 1000 / 60) % 60;
    t_s = (delta / 1000) % 60;

    sprintf(buf, "%d:%02d:%02d:%02d", t_d, t_h, t_m, t_s);

  }

  return buf;

}

/* Reads the map size from ENV */
u32 get_map_size(void) {

  uint32_t map_size = DEFAULT_SHMEM_SIZE;
  char    *ptr;

  if ((ptr = getenv("AFL_MAP_SIZE")) || (ptr = getenv("AFL_MAPSIZE"))) {

    map_size = atoi(ptr);
    if (!map_size || map_size > (1 << 29)) {

      FATAL("illegal AFL_MAP_SIZE %u, must be between %u and %u", map_size, 64U,
            1U << 29);

    }

    if (map_size % 64) { map_size = (((map_size >> 6) + 1) << 6); }

  } else if (getenv("AFL_SKIP_BIN_CHECK")) {

    map_size = MAP_SIZE;

  }

  return map_size;

}

/* Create a stream file */

FILE *create_ffile(char *fn) {

  s32   fd;
  FILE *f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }

  f = fdopen(fd, "w");

  if (!f) { PFATAL("fdopen() failed"); }

  return f;

}

/* Create a file */

s32 create_file(char *fn) {

  s32 fd;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }

  return fd;

}
