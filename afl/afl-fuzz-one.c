/*
   american fuzzy lop++ - fuzze_one routines in different flavours
   ---------------------------------------------------------------

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
#include <string.h>
#include "afl/afl-fuzz.h"
#include "panda/buzzer.h"

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset.
   We use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last) {
  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; ++pos) {
    if (*(ptr1++) != *(ptr2++)) {
      if (f_loc == -1) { f_loc = pos; }
      l_loc = pos;
    }
  }

  *first = f_loc;
  *last = l_loc;

  return;
}

#endif /* !IGNORE_FINDS */

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

u8 fuzz_one_original(afl_state_t *afl) {
  u32 len;
  u32 j;
  u32 i;
  u8 *in_buf, *out_buf, *ex_tmp, *eff_map = 0;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0, prev_cksum, _prev_cksum;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, eff_cnt = 1;

  u8  fault, fsrv_created = 0, timed_out = 0;
  s32 status;
  u32 use_stacking, stack_max;

  u8 ret_val = 1, tmp;

  message_t *message;

  struct queue_entry *q = afl->queue_tmp;

  if (likely(afl->pending_favored)) {
    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((afl->queue_cur->fuzz_level || !afl->queue_cur->favored) &&
        likely(rand_below(afl, 100) < SKIP_TO_NEW_PROB)) {
      return 1;
    }

  } else if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

             afl->queued_items > 10) {
    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 && !afl->queue_cur->fuzz_level) {
      if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

    } else {
      if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }
    }
  }

  orig_perf = perf_score = afl->queue_cur->perf_score;

  if (unlikely(perf_score <= 0 && afl->active_items > 1)) {
    goto abandon_entry;
  }

  queue_entry_clear_messages(q);
  queue_testcase_get(afl, afl->queue_cur);
  q->mother = afl->queue_cur;

  fsrv_created = perform_dry_run(afl, afl->queue_cur);

  if (unlikely(!fsrv_created)) goto abandon_entry;

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

iut_init_stage:

  if (likely(afl->passed_iut_init)) goto evt_enum_stage;

  afl->stage_name = "IutInit";
  afl->stage_short = "IutInit";
  afl->stage_max = 5;

  // Handle IUT init stage.
  // In IUT init stage, the host will perform mutual configuration with
  // the controller.

  // An ideal way of handling IUT init is to explore IUT configuration
  // space as much as possible.
  // However, for now we just config IUT with a virtual controller with
  // all possible features enabled.

  memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother, afl->fsrv.map_size);

  queue_entry_clear_messages(q);

  message = q->mother->messages[0];

  fault = FSRV_RUN_OK;

  afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

  handle_message(afl, q, message->data, message->size);

  while (1) {
    if (unlikely(has_exec_fail_sig(afl->fsrv.trace_bits))) {
      FATAL("IUT crashes during init");
    }

    timed_out = recv_message(afl, q);

    if (timed_out) { break; }
  }

  afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

  if (common_fuzz_stuff(afl, q, fault)) goto abandon_entry;

  afl->passed_iut_init = 1;

  ret_val = 1;

  goto abandon_entry;

evt_enum_stage:

  if (likely(afl->passed_evt_enum)) goto havoc_stage;

  afl->stage_name = "EvtEnum";
  afl->stage_short = "EvtEnum";
  afl->stage_max = hci_evt_cnt() + hci_le_evt_cnt();

  {
    queue_entry_clear_messages(q);
    memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother,
           afl->fsrv.map_size);
    queue_entry_append_event(q, 0xEF, u8, 255);
    afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());
    emit_message(afl, q, 0);
    recv_message(afl, q);
    afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());
    classify_counts(&afl->fsrv);
    has_new_bits(afl, afl->virgin_bits);
  }

  {
    queue_entry_clear_messages(q);
    memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother,
           afl->fsrv.map_size);
    queue_entry_append_event(q, 0xEF, u8, 10);
    afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());
    emit_message(afl, q, 0);
    recv_message(afl, q);
    afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());
    classify_counts(&afl->fsrv);
    has_new_bits(afl, afl->virgin_bits);
  }

  {
    queue_entry_clear_messages(q);
    memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother,
           afl->fsrv.map_size);
    queue_entry_append_le_event(q, 0xEF, u8, 10);
    afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());
    emit_message(afl, q, 0);
    recv_message(afl, q);
    afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());
    classify_counts(&afl->fsrv);
    has_new_bits(afl, afl->virgin_bits);
  }

  for (int i = 0, n = hci_evt_cnt(); i < n; ++i) {
    hci_evt_format_t *fmt = get_hci_evt_by_index(i);

    memcpy(buzzer->shmem_trace_child, buzzer->shmem_trace_mother,
           afl->fsrv.map_size);

    queue_entry_clear_messages(q);
    // fmt->opcode = 0x0F;
    queue_entry_append_event(q, fmt->opcode, u8, fmt->size);

    afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

    emit_message(afl, q, 0);

    recv_message(afl, q);

    afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

    ACTF("0x%02x", fmt->opcode);

    classify_counts(&afl->fsrv);

    if (2 == has_new_bits(afl, afl->virgin_bits)) {
      OKF("0x%02x", fmt->opcode);
      add_hci_iut_evt(fmt->opcode);
    }
  }

  for (int i = 0, n = hci_le_evt_cnt(); i < n; ++i) {
    hci_evt_format_t *fmt = get_hci_le_evt_by_index(i);

    memcpy(buzzer->shmem_trace_child, buzzer->shmem_trace_mother,
           afl->fsrv.map_size);

    queue_entry_clear_messages(q);

    queue_entry_append_le_event(q, fmt->opcode, u8, fmt->size - 1);

    afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

    emit_message(afl, q, 0);

    recv_message(afl, q);

    afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

    ACTF("0x%02x", fmt->opcode);

    classify_counts(&afl->fsrv);

    if (2 == has_new_bits(afl, afl->virgin_bits)) {
      OKF("0x%02x", fmt->opcode);
      add_hci_iut_le_evt(fmt->opcode);
    }
  }

  afl->hci_evt_cnt = hci_evt_cnt();
  afl->hci_le_evt_cnt = hci_le_evt_cnt();
  afl->iut_evt_cnt = hci_iut_evt_cnt();
  afl->iut_le_evt_cnt = hci_iut_le_evt_cnt();

  afl->passed_evt_enum = 1;

  ret_val = 1;

  goto abandon_entry;

havoc_stage:

  afl->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {
    afl->stage_name = "havoc";
    afl->stage_short = "havoc";
    afl->stage_max = (HAVOC_CYCLES * perf_score / afl->havoc_div) >> 8;

  } else {
    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "splice %u", splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = "splice";
    afl->stage_max = (SPLICE_HAVOC * perf_score / afl->havoc_div) >> 8;
  }

  if (unlikely(afl->stage_max < HAVOC_MIN)) { afl->stage_max = HAVOC_MIN; }

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  havoc_queued = afl->queued_items;

  stack_max = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

  // + (afl->extras_cnt ? 2 : 0) + (afl->a_extras_cnt ? 2 : 0);

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
    memcpy(afl->fsrv.trace_bits, afl->fsrv.trace_bits_mother,
           afl->fsrv.map_size);

    queue_entry_clear_messages(q);

    message = queue_entry_message_tail(afl->queue_cur);

    afl_fsrv_push_child(&afl->fsrv, send_ctrl_start_normal());

    use_stacking = 1 + rand_below(afl, stack_max);

    afl->stage_cur_val = use_stacking;

    q->subseq_tmouts = 0;

    for (int i = 0; i < use_stacking; ++i) {
      fault = recv_message(afl, q);

      if (fault == FSRV_RUN_TMOUT) {
        emit_message_random(afl, q);
        q->subseq_tmouts++;
        if (q->subseq_tmouts + q->mother->subseq_tmouts >= TMOUT_LIMIT) {
          fault = FSRV_RUN_TMOUT;
          break;
        }
      }
      else if (unlikely(fault == FSRV_RUN_CRASH)) {
        break;
      }
      else {
        q->subseq_tmouts = 0;
      }
    }

    afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit());

    if (common_fuzz_stuff(afl, q, fault)) goto abandon_entry;

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (afl->queued_items != havoc_queued) {
      if (perf_score <= afl->havoc_max_mult * 100) {
        afl->stage_max *= 2;
        perf_score *= 2;
      }

      havoc_queued = afl->queued_items;
    }
  }

  // ACTF("Exit fsrv");

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  if (!splice_cycle) {
    afl->stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_HAVOC] += afl->stage_max;

  } else {
    afl->stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_SPLICE] += afl->stage_max;
  }

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  // if (afl->use_splicing && splice_cycle++ < SPLICE_CYCLES &&
  //     afl->ready_for_splicing_count > 1 && afl->queue_cur->len >= 4) {

  //   struct queue_entry *target;
  //   u32                 tid, split_at;
  //   u8                 *new_buf;
  //   s32                 f_diff, l_diff;

  //   /* First of all, if we've modified in_buf for havoc, let's clean that
  //      up... */

  //   if (in_buf != orig_in) {

  //     in_buf = orig_in;
  //     len = afl->queue_cur->len;

  //   }

  //   /* Pick a random queue entry and seek to it. Don't splice with yourself.
  //   */

  //   do {

  //     tid = rand_below(afl, afl->queued_items);

  //   } while (

  //       unlikely(tid == afl->current_entry || afl->queue_buf[tid]->len < 4));

  //   /* Get the testcase */
  //   afl->splicing_with = tid;
  //   target = afl->queue_buf[tid];
  //   queue_testcase_get(afl, target);

  //   /* Find a suitable splicing location, somewhere between the first and
  //      the last differing byte. Bail out if the difference is just a single
  //      byte or so. */

  //   locate_diffs(in_buf, new_buf, MIN(len, (s64)target->len), &f_diff,
  //   &l_diff);

  //   if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) { goto retry_splicing;
  //   }

  //   /* Split somewhere between the first and last differing byte. */

  //   split_at = f_diff + rand_below(afl, l_diff - f_diff);

  //   /* Do the thing. */

  //   len = target->len;
  //   afl->in_scratch_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), len);
  //   memcpy(afl->in_scratch_buf, in_buf, split_at);
  //   memcpy(afl->in_scratch_buf + split_at, new_buf, len - split_at);
  //   in_buf = afl->in_scratch_buf;
  //   afl_swap_bufs(AFL_BUF_PARAM(in), AFL_BUF_PARAM(in_scratch));

  //   out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  //   if (unlikely(!out_buf)) { PFATAL("alloc"); }
  //   memcpy(out_buf, in_buf, len);

  //   goto havoc_stage;

  // }

  ret_val = 0;

/* we are through with this queue entry - for this iteration */
abandon_entry:
  if (likely(fsrv_created))
    afl_fsrv_pop_child(&afl->fsrv, send_ctrl_exit_fsrv());

  afl->splicing_with = -1;

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      !afl->queue_cur->was_fuzzed && !afl->queue_cur->disabled) {
    --afl->pending_not_fuzzed;
    afl->queue_cur->was_fuzzed = 1;
    afl->reinit_table = 1;
    if (afl->queue_cur->favored) {
      --afl->pending_favored;
      afl->smallest_favored = -1;
    }
  }

  ++afl->queue_cur->fuzz_level;
  return ret_val;
}

/* The entry point for the mutator, choosing the default mutator, and/or MOpt
   depending on the configuration. */
u8 fuzz_one(afl_state_t *afl) {
  return fuzz_one_original(afl);
}
