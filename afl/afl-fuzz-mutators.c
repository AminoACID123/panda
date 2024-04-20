/*
   american fuzzy lop++ - custom mutators related routines
   -------------------------------------------------------

   Originally written by Shengtuo Hu

   Now maintained by  Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>
                        Dominik Maier <mail@dmnk.co>

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

struct custom_mutator *load_custom_mutator(afl_state_t *, const char *);
#ifdef USE_PYTHON
struct custom_mutator *load_custom_mutator_py(afl_state_t *, char *);
#endif

void run_afl_custom_queue_new_entry(afl_state_t *afl, struct queue_entry *q,
                                    u8 *fname, u8 *mother_fname) {

  if (afl->custom_mutators_count) {

    u8 updated = 0;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_queue_new_entry) {

        if (el->afl_custom_queue_new_entry(el->data, fname, mother_fname)) {

          updated = 1;

        }

      }

    });

    if (updated) {

      struct stat st;
      if (stat(fname, &st)) { PFATAL("File %s is gone!", fname); }
      if (!st.st_size) {

        FATAL("File %s became empty in custom mutator!", fname);

      }

      q->len = st.st_size;

    }

  }

}

void setup_custom_mutators(afl_state_t *afl) {

  /* Try mutator library first */
  struct custom_mutator *mutator;
  u8                    *fn = afl->afl_env.afl_custom_mutator_library;
  u32                    prev_mutator_count = 0;

  if (fn) {

    if (afl->limit_time_sig && afl->limit_time_sig != -1)
      FATAL(
          "MOpt and custom mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/redqueen/...).");

    u8 *fn_token = (u8 *)strsep((char **)&fn, ";:,");

    if (likely(!fn_token)) {

      mutator = load_custom_mutator(afl, fn);
      list_append(&afl->custom_mutator_list, mutator);
      afl->custom_mutators_count++;

    } else {

      while (fn_token) {

        if (*fn_token) {  // strsep can be empty if ";;"

          if (afl->not_on_tty && afl->debug)
            SAYF("[Custom] Processing: %s\n", fn_token);
          prev_mutator_count = afl->custom_mutators_count;
          mutator = load_custom_mutator(afl, fn_token);
          list_append(&afl->custom_mutator_list, mutator);
          afl->custom_mutators_count++;
          if (prev_mutator_count > afl->custom_mutators_count)
            FATAL("Maximum Custom Mutator count reached.");
          fn_token = (u8 *)strsep((char **)&fn, ";:,");

        }

      }

    }

  }

  /* Try Python module */
#ifdef USE_PYTHON
  u8 *module_name = afl->afl_env.afl_python_module;

  if (module_name) {

    if (afl->limit_time_sig) {

      FATAL(
          "MOpt and Python mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/redqueen/...).");

    }

    struct custom_mutator *m = load_custom_mutator_py(afl, module_name);
    afl->custom_mutators_count++;
    list_append(&afl->custom_mutator_list, m);

  }

#else
  if (afl->afl_env.afl_python_module) {

    FATAL("Your AFL binary was built without Python support");

  }

#endif

}

void destroy_custom_mutators(afl_state_t *afl) {

  if (afl->custom_mutators_count) {

    LIST_FOREACH_CLEAR(&afl->custom_mutator_list, struct custom_mutator, {

      if (!el->data) { FATAL("Deintializing NULL mutator"); }
      if (el->afl_custom_deinit) el->afl_custom_deinit(el->data);
      if (el->dh) dlclose(el->dh);

      if (el->post_process_buf) {

        afl_free(el->post_process_buf);
        el->post_process_buf = NULL;

      }

      ck_free(el);

    });

  }

}

struct custom_mutator *load_custom_mutator(afl_state_t *afl, const char *fn) {

  void                  *dh;
  struct custom_mutator *mutator = ck_alloc(sizeof(struct custom_mutator));

  if (memchr(fn, '/', strlen(fn))) {

    mutator->name_short = strdup(strrchr(fn, '/') + 1);

  } else {

    mutator->name_short = strdup(fn);

  }

  if (strlen(mutator->name_short) > 22) { mutator->name_short[21] = 0; }

  mutator->name = fn;
  ACTF("Loading custom mutator library from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());
  mutator->dh = dh;

  /* Mutator */
  /* "afl_custom_init", optional for backward compatibility */
  mutator->afl_custom_init = dlsym(dh, "afl_custom_init");
  if (!mutator->afl_custom_init) {

    FATAL("Symbol 'afl_custom_init' not found.");

  }

  /* "afl_custom_fuzz" or "afl_custom_mutator", required */
  mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_fuzz");
  if (!mutator->afl_custom_fuzz) {

    /* Try "afl_custom_mutator" for backward compatibility */
    WARNF("Symbol 'afl_custom_fuzz' not found. Try 'afl_custom_mutator'.");

    mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_mutator");
    if (!mutator->afl_custom_fuzz) {

      WARNF("Symbol 'afl_custom_mutator' not found.");

    } else {

      OKF("Found 'afl_custom_mutator'.");

    }

  } else {

    OKF("Found 'afl_custom_mutator'.");

  }


  /* "afl_custom_fuzz_count", optional */
  mutator->afl_custom_fuzz_count = dlsym(dh, "afl_custom_fuzz_count");
  if (!mutator->afl_custom_fuzz_count) {

    ACTF("optional symbol 'afl_custom_fuzz_count' not found.");

  } else {

    OKF("Found 'afl_custom_fuzz_count'.");

  }

  /* "afl_custom_deinit", optional for backward compatibility */
  mutator->afl_custom_deinit = dlsym(dh, "afl_custom_deinit");
  if (!mutator->afl_custom_deinit) {

    FATAL("Symbol 'afl_custom_deinit' not found.");

  }

  /* "afl_custom_post_process", optional */
  mutator->afl_custom_post_process = dlsym(dh, "afl_custom_post_process");
  if (!mutator->afl_custom_post_process) {

    ACTF("optional symbol 'afl_custom_post_process' not found.");

  } else {

    OKF("Found 'afl_custom_post_process'.");

  }

  u8 notrim = 0;
  /* "afl_custom_init_trim", optional */
  mutator->afl_custom_init_trim = dlsym(dh, "afl_custom_init_trim");
  if (!mutator->afl_custom_init_trim) {

    notrim = 1;
    ACTF("optional symbol 'afl_custom_init_trim' not found.");

  } else {

    OKF("Found 'afl_custom_init_trim'.");

  }

  /* "afl_custom_trim", optional */
  mutator->afl_custom_trim = dlsym(dh, "afl_custom_trim");
  if (!mutator->afl_custom_trim) {

    notrim = 1;
    ACTF("optional symbol 'afl_custom_trim' not found.");

  } else {

    OKF("Found 'afl_custom_trim'.");

  }

  /* "afl_custom_post_trim", optional */
  mutator->afl_custom_post_trim = dlsym(dh, "afl_custom_post_trim");
  if (!mutator->afl_custom_post_trim) {

    notrim = 1;
    ACTF("optional symbol 'afl_custom_post_trim' not found.");

  } else {

    OKF("Found 'afl_custom_post_trim'.");

  }

  if (notrim) {

    if (mutator->afl_custom_init_trim || mutator->afl_custom_trim ||
        mutator->afl_custom_post_trim) {

      WARNF(
          "Custom mutator does not implement all three trim APIs, standard "
          "trimming will be used.");

    }

    mutator->afl_custom_init_trim = NULL;
    mutator->afl_custom_trim = NULL;
    mutator->afl_custom_post_trim = NULL;

  }

  /* "afl_custom_havoc_mutation", optional */
  mutator->afl_custom_havoc_mutation = dlsym(dh, "afl_custom_havoc_mutation");
  if (!mutator->afl_custom_havoc_mutation) {

    ACTF("optional symbol 'afl_custom_havoc_mutation' not found.");

  } else {

    OKF("Found 'afl_custom_havoc_mutation'.");

  }

  /* "afl_custom_havoc_mutation", optional */
  mutator->afl_custom_havoc_mutation_probability =
      dlsym(dh, "afl_custom_havoc_mutation_probability");
  if (!mutator->afl_custom_havoc_mutation_probability) {

    ACTF("optional symbol 'afl_custom_havoc_mutation_probability' not found.");

  } else {

    OKF("Found 'afl_custom_havoc_mutation_probability'.");

  }

  /* "afl_custom_queue_get", optional */
  mutator->afl_custom_queue_get = dlsym(dh, "afl_custom_queue_get");
  if (!mutator->afl_custom_queue_get) {

    ACTF("optional symbol 'afl_custom_queue_get' not found.");

  } else {

    OKF("Found 'afl_custom_queue_get'.");

  }

  /* "afl_custom_splice_optout", optional, never called */
  mutator->afl_custom_splice_optout = dlsym(dh, "afl_custom_splice_optout");
  if (!mutator->afl_custom_splice_optout) {

    ACTF("optional symbol 'afl_custom_splice_optout' not found.");

  } else {

    OKF("Found 'afl_custom_splice_optout'.");
    afl->custom_splice_optout = 1;

  }

  /* "afl_custom_fuzz_send", optional */
  mutator->afl_custom_fuzz_send = dlsym(dh, "afl_custom_fuzz_send");
  if (!mutator->afl_custom_fuzz_send) {

    ACTF("optional symbol 'afl_custom_fuzz_send' not found.");

  } else {

    OKF("Found 'afl_custom_fuzz_send'.");

  }

  /* "afl_custom_post_run", optional */
  mutator->afl_custom_post_run = dlsym(dh, "afl_custom_post_run");
  if (!mutator->afl_custom_post_run) {

    ACTF("optional symbol 'afl_custom_post_run' not found.");

  } else {

    OKF("Found 'afl_custom_post_run'.");

  }

  /* "afl_custom_queue_new_entry", optional */
  mutator->afl_custom_queue_new_entry = dlsym(dh, "afl_custom_queue_new_entry");
  if (!mutator->afl_custom_queue_new_entry) {

    ACTF("optional symbol 'afl_custom_queue_new_entry' not found");

  } else {

    OKF("Found 'afl_custom_queue_new_entry'.");

  }

  /* "afl_custom_describe", optional */
  mutator->afl_custom_describe = dlsym(dh, "afl_custom_describe");
  if (!mutator->afl_custom_describe) {

    ACTF("optional symbol 'afl_custom_describe' not found.");

  } else {

    OKF("Found 'afl_custom_describe'.");

  }

  OKF("Custom mutator '%s' installed successfully.", fn);

  /* Initialize the custom mutator */
  if (mutator->afl_custom_init) {

    mutator->data = mutator->afl_custom_init(afl, rand_below(afl, 0xFFFFFFFF));

  }

  mutator->stacked_custom = (mutator && mutator->afl_custom_havoc_mutation);
  mutator->stacked_custom_prob =
      6;  // like one of the default mutations in havoc

  return mutator;

}


