/*
   american fuzzy lop++ - common routines header
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Gather some functions common to multiple executables

   - detect_file_args

 */

#ifndef __AFLCOMMON_H
#define __AFLCOMMON_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>
#include "forkserver.h"
#include "types.h"

/* STRINGIFY_VAL_SIZE_MAX will fit all stringify_ strings. */

#define STRINGIFY_VAL_SIZE_MAX (16)

u32  check_binary_signatures(u8 *fn);
void detect_file_args(char **argv, u8 *prog_in, bool *use_stdin);
void print_suggested_envs(char *mispelled_env);
void check_environment_vars(char **env);
void set_sanitizer_defaults(void);

char **argv_cpy_dup(int argc, char **argv);
void   argv_cpy_free(char **argv);


/* Extract env vars from input string and set them using setenv()
   For use with AFL_TARGET_ENV, ... */
bool extract_and_set_env(u8 *env_str);

extern u8  be_quiet;
extern u8 *doc_path;                    /* path to documentation dir        */

/* Find binary, used by analyze, showmap, tmin
   @returns the path, allocating the string */

u8 *find_binary(u8 *fname);

/* Parses the (numeric) kill signal environment variable passed
   via `numeric_signal_as_str`.
   If NULL is passed, the `default_signal` value is returned.
   FATALs if `numeric_signal_as_str` is not a valid integer .*/
int parse_afl_kill_signal(char *numeric_signal_as_str, int default_signal);

/* Configure the signals that are used to kill the forkserver
   and the forked childs. If `afl_kill_signal_env` or `afl_fsrv_kill_signal_env`
   is NULL, the appropiate values are read from the environment. */
void configure_afl_kill_signals(afl_forkserver_t *fsrv,
                                char             *afl_kill_signal_env,
                                char             *afl_fsrv_kill_signal_env,
                                int               default_server_kill_signal);

/* Read a bitmap from file fname to memory
   This is for the -B option again. */

void read_bitmap(u8 *fname, u8 *map, size_t len);

/* Get unix time in milliseconds */

u64 get_cur_time(void);

/* Get unix time in microseconds */

u64 get_cur_time_us(void);

/* Describe integer. The buf should be
   at least 6 bytes to fit all ints we randomly see.
   Will return buf for convenience. */

char *stringify_int(char *buf, size_t len, u64 val);

/* Describe float. Similar as int. */

char *stringify_float(char *buf, size_t len, double val);

/* Describe integer as memory size. */

char *stringify_mem_size(char *buf, size_t len, u64 val);

/* Describe time delta as string.
   Returns a pointer to buf for convenience. */

char *stringify_time_diff(char *buf, size_t len, u64 cur_ms, u64 event_ms);

/* Unsafe describe time delta as simple string.
   Returns a pointer to buf for convenience. */

u8 *u_simplestring_time_diff(char *buf, u64 cur_ms, u64 event_ms);

/* Unsafe Describe integer. The buf sizes are not checked.
   This is unsafe but fast.
   Will return buf for convenience. */

char *u_stringify_int(char *buf, u64 val);

/* Unsafe describe float. Similar as unsafe int. */

char *u_stringify_float(char *buf, double val);

/* Unsafe describe integer as memory size. */

char *u_stringify_mem_size(char *buf, u64 val);

/* Unsafe describe time delta as string.
   Returns a pointer to buf for convenience. */

char *u_stringify_time_diff(char *buf, u64 cur_ms, u64 event_ms);

/* Reads the map size from ENV */
u32 get_map_size(void);

/* create a stream file */
FILE *create_ffile(char *fn);

/* create a file */
s32 create_file(char *fn);

/* memmem implementation as not all platforms support this */
void *afl_memmem(const void *haystack, size_t haystacklen, const void *needle,
                 size_t needlelen);


#endif

