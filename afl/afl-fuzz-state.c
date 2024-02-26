/*
   american fuzzy lop++ - globals declarations
   -------------------------------------------

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

#include <limits.h>
#include <signal.h>
#include "afl/afl-fuzz.h"

s8  interesting_8[] = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

char *power_names[POWER_SCHEDULES_NUM] = {"explore", "mmopt", "exploit",
                                          "fast",    "coe",   "lin",
                                          "quad",    "rare",  "seek"};

/* Initialize MOpt "globals" for this afl state */

static void init_mopt_globals(afl_state_t *afl) {
  MOpt_globals_t *core = &afl->mopt_globals_core;
  core->finds = afl->core_operator_finds_puppet;
  core->finds_v2 = afl->core_operator_finds_puppet_v2;
  core->cycles = afl->core_operator_cycles_puppet;
  core->cycles_v2 = afl->core_operator_cycles_puppet_v2;
  core->cycles_v3 = afl->core_operator_cycles_puppet_v3;
  core->is_pilot_mode = 0;
  core->pTime = &afl->tmp_core_time;
  core->period = period_core;
  core->havoc_stagename = "MOpt-core-havoc";
  core->splice_stageformat = "MOpt-core-splice %u";
  core->havoc_stagenameshort = "MOpt_core_havoc";
  core->splice_stagenameshort = "MOpt_core_splice";

  MOpt_globals_t *pilot = &afl->mopt_globals_pilot;
  pilot->finds = afl->stage_finds_puppet[0];
  pilot->finds_v2 = afl->stage_finds_puppet_v2[0];
  pilot->cycles = afl->stage_cycles_puppet[0];
  pilot->cycles_v2 = afl->stage_cycles_puppet_v2[0];
  pilot->cycles_v3 = afl->stage_cycles_puppet_v3[0];
  pilot->is_pilot_mode = 1;
  pilot->pTime = &afl->tmp_pilot_time;
  pilot->period = period_pilot;
  pilot->havoc_stagename = "MOpt-havoc";
  pilot->splice_stageformat = "MOpt-splice %u";
  pilot->havoc_stagenameshort = "MOpt_havoc";
  pilot->splice_stagenameshort = "MOpt_splice";
}

/* A global pointer to all instances is needed (for now) for signals to arrive
 */

static list_t afl_states = {.element_prealloc_count = 0};

/* Initializes an afl_state_t. */

void afl_state_init(afl_state_t *afl, uint32_t map_size) {
  /* thanks to this memset, growing vars like out_buf
  and out_size are NULL/0 by default. */
  memset(afl, 0, sizeof(afl_state_t));

  afl->shm.map_size = map_size ? map_size : MAP_SIZE;

  afl->w_init = 0.9;
  afl->w_end = 0.3;
  afl->g_max = 5000;
  afl->period_pilot_tmp = 5000.0;
  afl->schedule = EXPLORE; /* Power schedule (default: EXPLORE)*/
  afl->havoc_max_mult = HAVOC_MAX_MULT;
  afl->clear_screen = 1;    /* Window resized?                  */
  afl->havoc_div = 1;       /* Cycle count divisor for havoc    */
  afl->stage_name = "init"; /* Name of the current fuzz stage   */
  afl->splicing_with = -1;  /* Splicing with which test case?   */
  afl->cpu_to_bind = -1;
  afl->havoc_stack_pow2 = HAVOC_STACK_POW2;
  afl->hang_tmout = EXEC_TIMEOUT;
  afl->exit_on_time = 0;
  afl->stats_update_freq = 1;
  afl->stats_file_update_freq_msecs = STATS_UPDATE_SEC * 1000;
  afl->stats_avg_exec = 0;
  afl->skip_deterministic = 1;
  afl->sync_time = SYNC_TIME;
  afl->cmplog_lvl = 2;
  afl->min_length = 1;
  afl->max_length = MAX_FILE;
  afl->switch_fuzz_mode = STRATEGY_SWITCH_TIME * 1000;
#ifndef NO_SPLICING
  afl->use_splicing = 1;
#endif
  afl->q_testcase_max_cache_size = TESTCASE_CACHE_SIZE * 1048576UL;
  afl->q_testcase_max_cache_entries = 64 * 1024;

#ifdef HAVE_AFFINITY
  afl->cpu_aff = -1; /* Selected CPU core                */
#endif               /* HAVE_AFFINITY */

  afl->virgin_bits = ck_alloc(map_size);
  afl->virgin_tmout = ck_alloc(map_size);
  afl->virgin_crash = ck_alloc(map_size);
  afl->var_bytes = ck_alloc(map_size);
  afl->top_rated = ck_alloc(map_size * sizeof(void *));
  afl->clean_trace = ck_alloc(map_size);
  afl->clean_trace_custom = ck_alloc(map_size);
  afl->first_trace = ck_alloc(map_size);
  afl->map_tmp_buf = ck_alloc(map_size);

  afl->fsrv.use_stdin = 1;
  afl->fsrv.map_size = map_size;
  // afl_state_t is not available in forkserver.c
  afl->fsrv.afl_ptr = (void *)afl;
  afl->fsrv.exec_tmout = EXEC_TIMEOUT;
  afl->fsrv.mem_limit = MEM_LIMIT;
  afl->fsrv.dev_urandom_fd = -1;
  afl->fsrv.dev_null_fd = -1;
  afl->fsrv.child_pid = -1;
  afl->fsrv.out_dir_fd = -1;

  afl->queue_tmp = calloc(1, sizeof(struct queue_entry));

  afl->new_bits_only = 1;

  bt_state_init(&afl->bt_state);

  init_mopt_globals(afl);

  list_append(&afl_states, afl);
}

/* Removes this afl_state instance and frees it. */

void afl_state_deinit(afl_state_t *afl) {
  if (afl->in_place_resume) { ck_free(afl->in_dir); }
  if (afl->pass_stats) { ck_free(afl->pass_stats); }
  if (afl->orig_cmp_map) { ck_free(afl->orig_cmp_map); }
  if (afl->cmplog_binary) { ck_free(afl->cmplog_binary); }

  afl_free(afl->queue_buf);
  afl_free(afl->out_buf);
  afl_free(afl->out_scratch_buf);
  afl_free(afl->eff_buf);
  afl_free(afl->in_buf);
  afl_free(afl->in_scratch_buf);
  afl_free(afl->ex_buf);

  ck_free(afl->virgin_bits);
  ck_free(afl->virgin_tmout);
  ck_free(afl->virgin_crash);
  ck_free(afl->var_bytes);
  ck_free(afl->top_rated);
  ck_free(afl->clean_trace);
  ck_free(afl->clean_trace_custom);
  ck_free(afl->first_trace);
  ck_free(afl->map_tmp_buf);

  list_remove(&afl_states, afl);
}

void afl_states_stop(void) {
  /* We may be inside a signal handler.
   Set flags first, send kill signals to child proceses later. */
  LIST_FOREACH(&afl_states, afl_state_t, {
    el->stop_soon = 1;
    el->force_ui_update = 1;  // ensure the screen is reprinted
    el->stop_soon = 1;        // ensure everything is written
  //   show_stats(el);           // print the screen one last time
    write_bitmap(el);
    save_pklg(el);

    SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
         el->stop_soon == 2 ? "programmatically" : "by user");

    if (el->most_time_key == 2) {
      SAYF(cYEL "[!] " cRST "Time limit was reached\n");
    }

    if (el->most_execs_key == 2) {
      SAYF(cYEL "[!] " cRST "Execution limit was reached\n");
    }

    /* Running for more than 30 minutes but still doing first cycle? */

    if (el->queue_cycle == 1 &&
        get_cur_time() - el->start_time > 30 * 60 * 1000) {
      SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming, see %s/README.md)\n",
           doc_path);
    }

    fclose(el->fsrv.plot_file);
    destroy_queue(el);

    afl_fsrv_deinit(&el->fsrv);

    /* remove tmpfile */
    if (el->tmp_dir != NULL && !el->in_place_resume && el->fsrv.out_file) {
      (void)unlink(el->fsrv.out_file);
    }

    ck_free(el->fsrv.target_path);
    ck_free(el->fsrv.out_file);
    if (el->q_testcase_cache) { ck_free(el->q_testcase_cache); }
    afl_state_deinit(el);
    free(el); /* not tracked */

    alloc_report();

    OKF("We're done here. Have a nice day!\n");

    exit(0);
  });
}

void afl_states_clear_screen(void) {
  LIST_FOREACH(&afl_states, afl_state_t, { el->clear_screen = 1; });
}

void afl_states_request_skip(void) {
  LIST_FOREACH(&afl_states, afl_state_t, { el->skip_requested = 1; });
}
