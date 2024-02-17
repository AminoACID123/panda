/*
   american fuzzy lop++ - fuzzer code
   --------------------------------

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

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl/afl-fuzz.h"
#include <limits.h>
#include <stdlib.h>
#include "afl/common.h"
#include "panda/buzzer.h"
#ifndef USEMMAP
  #include <fcntl.h>
  #include <sys/ipc.h>
  #include <sys/mman.h>
  #include <sys/shm.h>
  #include <sys/stat.h>
#endif

#ifdef __APPLE__
  #include <pthread/qos.h>
  #include <sys/qos.h>
#endif

#ifdef PROFILING
extern u64 time_spent_working;
#endif

static void at_exit(void) {
  // afl_states_stop();
}

#ifndef AFL_LIB

/* Main entry point */
void afl_run(pid_t pid) {
  u32 map_size = MAP_SIZE;
  u8  debug = 0;

  struct timeval  tv;
  struct timezone tz;

  ACTF("afl_run");

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  if (!afl) { FATAL("Could not create afl state"); }

  bt_state_init(&afl->bt_state);

  setup_signal_handlers();

  afl_state_init(afl, map_size);
  afl->out_dir = buzzer->out_dir;

  afl_fsrv_init(&afl->fsrv);
  if (debug) { afl->fsrv.debug = true; }
  afl_fsrv_push_child(&afl->fsrv, pid);

  SAYF(cCYA "afl-fuzz" VERSION cRST
            " based on afl by Michal Zalewski and a large online community\n");

  gettimeofday(&tv, &tz);
  rand_set_seed(afl, tv.tv_sec ^ tv.tv_usec ^ getpid());

  afl->shmem_testcase_mode = 1;  // we always try to perform shmem fuzzing

  afl->power_name = power_names[afl->schedule];

  /* Dynamically allocate memory for AFLFast schedules */
  if (afl->schedule >= FAST && afl->schedule <= RARE) {
    afl->n_fuzz = ck_alloc(N_FUZZ_SIZE * sizeof(u32));
  }

  afl->q_testcase_max_cache_size = TESTCASE_MAX_CACHE_SIZE * 1048576;

  afl->q_testcase_max_cache_entries = TESTCASE_MAX_CACHE_ENTRIES;

  afl_realloc(AFL_BUF_PARAM(in_scratch), MIN_ALLOC);
  afl_realloc(AFL_BUF_PARAM(in), MIN_ALLOC);
  afl_realloc(AFL_BUF_PARAM(out_scratch), MIN_ALLOC);
  afl_realloc(AFL_BUF_PARAM(out), MIN_ALLOC);
  afl_realloc(AFL_BUF_PARAM(eff), MIN_ALLOC);
  afl_realloc(AFL_BUF_PARAM(ex), MIN_ALLOC);

  for (int i = 0; i < MESSAGE_LIST_SCRATCH_LEN; ++i) {
    afl_realloc((void **)&afl->message_list_scratch[i],
                MIN_ALLOC + sizeof(message_t));
  }

  get_core_count(afl);

  atexit(at_exit);

  setup_dirs_fds(afl);

  #ifdef HAVE_AFFINITY
  bind_to_free_cpu(afl);
  #endif /* HAVE_AFFINITY */

  init_count_class16();

  afl->tmp_dir = afl->out_dir;

  afl->use_banner = buzzer->target_file;

  memset(afl->virgin_bits, 255, map_size);
  memset(afl->virgin_tmout, 255, map_size);
  memset(afl->virgin_crash, 255, map_size);

  afl->q_testcase_cache =
      ck_alloc(afl->q_testcase_max_cache_entries * sizeof(size_t));
  if (!afl->q_testcase_cache) { PFATAL("malloc failed for cache entries"); }

  afl->start_time = get_cur_time();
  afl->stage_name = "IutReset";
  afl->stage_short = "IutReset";
  afl->fsrv.trace_bits = afl->fsrv.trace_bits_mother;
  queue_entry_append_message_recv(afl, afl->queue_tmp);
  common_fuzz_stuff(afl, afl->queue_tmp, FSRV_RUN_OK);
  memset(afl->virgin_bits, 255, afl->fsrv.map_size);

  // handle_iut_initialization(afl);

  cull_queue(afl);

  afl->queue_cur = NULL;

  afl->start_time = get_cur_time();

  write_stats_file(afl, 0, 0, 0, 0);
  maybe_update_plot_file(afl, 0, 0, 0);

  afl->start_time = get_cur_time();

  u64 prev_queued = 0;
  u32 prev_queued_items = 0, runs_in_current_cycle = (u32)-1;
  u8  skipped_fuzz;

  while (likely(!afl->stop_soon)) {
    cull_queue(afl);

    if (unlikely((!afl->old_seed_selection &&
                  runs_in_current_cycle > afl->queued_items) ||
                 (afl->old_seed_selection && !afl->queue_cur))) {
      ++afl->queue_cycle;
      runs_in_current_cycle = (u32)-1;
      afl->cur_skipped_items = 0;

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (unlikely(afl->queued_items == prev_queued
                   /* FIXME TODO BUG: && (get_cur_time() - afl->start_time) >=
                      3600 */
                   )) {
        if (afl->use_splicing) {
          ++afl->cycles_wo_finds;

          switch (afl->expand_havoc) {
            case 0:
              // this adds extra splicing mutation options to havoc mode
              afl->expand_havoc = 1;
              break;
            case 1:
              afl->expand_havoc = 2;
              if (afl->cmplog_lvl && afl->cmplog_lvl < 2) afl->cmplog_lvl = 2;
              break;
            case 2:
              // increase havoc mutations per fuzz attempt
              afl->havoc_stack_pow2++;
              afl->expand_havoc = 3;
              break;
            case 3:
              // further increase havoc mutations per fuzz attempt
              afl->havoc_stack_pow2++;
              afl->expand_havoc = 4;
              break;
            case 4:
              afl->expand_havoc = 5;
              break;
            case 5:
              // nothing else currently
              break;
          }

        } else {
  #ifndef NO_SPLICING
          afl->use_splicing = 1;
  #else
          afl->use_splicing = 0;
  #endif
        }

      } else {
        afl->cycles_wo_finds = 0;
      }

      if (afl->cycle_schedules) {
        /* we cannot mix non-AFLfast schedules with others */

        switch (afl->schedule) {
          case EXPLORE:
            afl->schedule = EXPLOIT;
            break;
          case EXPLOIT:
            afl->schedule = MMOPT;
            break;
          case MMOPT:
            afl->schedule = SEEK;
            break;
          case SEEK:
            afl->schedule = EXPLORE;
            break;
          case FAST:
            afl->schedule = COE;
            break;
          case COE:
            afl->schedule = LIN;
            break;
          case LIN:
            afl->schedule = QUAD;
            break;
          case QUAD:
            afl->schedule = RARE;
            break;
          case RARE:
            afl->schedule = FAST;
            break;
        }

        // we must recalculate the scores of all queue entries
        for (u32 i = 0; i < afl->queued_items; i++) {
          if (likely(!afl->queue_buf[i]->disabled)) {
            update_bitmap_score(afl, afl->queue_buf[i]);
          }
        }
      }

      prev_queued = afl->queued_items;
    }

    ++runs_in_current_cycle;

    do {
      if (likely(!afl->old_seed_selection)) {
        if (likely(afl->pending_favored && afl->smallest_favored >= 0)) {
          afl->current_entry = afl->smallest_favored;

          afl->queue_cur = afl->queue_buf[afl->current_entry];

        } else {
          if (unlikely(prev_queued_items < afl->queued_items ||
                       afl->reinit_table)) {
            // we have new queue entries since the last run, recreate alias
            // table
            prev_queued_items = afl->queued_items;
            create_alias_table(afl);
          }

          do {
            afl->current_entry = select_next_queue_entry(afl);

          } while (unlikely((afl->current_entry >= afl->queued_items) || (afl->passed_iut_init && afl->current_entry == 0)));

          afl->queue_cur = afl->queue_buf[afl->current_entry];
        }
      }

      skipped_fuzz = fuzz_one(afl);

    } while (skipped_fuzz && afl->queue_cur && !afl->stop_soon);

    u64 cur_time = get_cur_time();

    if (likely(afl->switch_fuzz_mode && afl->fuzz_mode == 0 &&
               !afl->non_instrumented_mode) &&
        unlikely(cur_time > (likely(afl->last_find_time) ? afl->last_find_time
                                                         : afl->start_time) +
                                afl->switch_fuzz_mode)) {
      afl->fuzz_mode = 1;
    }
  }

  afl_states_stop();
}

#endif /* !AFL_LIB */
