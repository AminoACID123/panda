/*
   american fuzzy lop++ - initialization related routines
   ------------------------------------------------------

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
#include "afl/common.h"
#include <limits.h>
#include <string.h>


#ifdef HAVE_AFFINITY

/* bind process to a specific cpu. Returns 0 on failure. */

static u8 bind_cpu(afl_state_t *afl, s32 cpuid) {

  #if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)
  cpu_set_t c;
  #elif defined(__NetBSD__)
  cpuset_t *c;
  #elif defined(__sun)
  psetid_t c;
  #endif

  afl->cpu_aff = cpuid;

  #if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)

  CPU_ZERO(&c);
  CPU_SET(cpuid, &c);

  #elif defined(__NetBSD__)

  c = cpuset_create();
  if (c == NULL) { PFATAL("cpuset_create failed"); }
  cpuset_set(cpuid, c);

  #elif defined(__sun)

  pset_create(&c);
  if (pset_assign(c, cpuid, NULL)) { PFATAL("pset_assign failed"); }

  #endif

  #if defined(__linux__)

  return (sched_setaffinity(0, sizeof(c), &c) == 0);

  #elif defined(__FreeBSD__) || defined(__DragonFly__)

  return (pthread_setaffinity_np(pthread_self(), sizeof(c), &c) == 0);

  #elif defined(__NetBSD__)

  if (pthread_setaffinity_np(pthread_self(), cpuset_size(c), c)) {

    cpuset_destroy(c);
    return 0;

  }

  cpuset_destroy(c);
  return 1;

  #elif defined(__sun)

  if (pset_bind(c, P_PID, getpid(), NULL)) {

    pset_destroy(c);
    return 0;

  }

  pset_destroy(c);
  return 1;

  #else

  // this will need something for other platforms
  // TODO: Solaris/Illumos has processor_bind ... might worth a try
  WARNF("Cannot bind to CPU yet on this platform.");
  return 1;

  #endif

}

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

void bind_to_free_cpu(afl_state_t *afl) {

  u8  cpu_used[4096] = {0};
  u8  lockfile[PATH_MAX] = "";
  s32 i;

  if (afl->afl_env.afl_no_affinity && !afl->afl_env.afl_try_affinity) {

    if (afl->cpu_to_bind != -1) {

      FATAL("-b and AFL_NO_AFFINITY are mututally exclusive.");

    }

    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;

  }

  if (afl->cpu_to_bind != -1) {

    if (!bind_cpu(afl, afl->cpu_to_bind)) {

      if (afl->afl_env.afl_try_affinity) {

        WARNF(
            "Could not bind to requested CPU %d! Make sure you passed a valid "
            "-b.",
            afl->cpu_to_bind);

      } else {

        FATAL(
            "Could not bind to requested CPU %d! Make sure you passed a valid "
            "-b.",
            afl->cpu_to_bind);

      }

    } else {

      OKF("CPU binding request using -b %d successful.", afl->cpu_to_bind);

    }

    return;

  }

  if (afl->cpu_core_count < 2) { return; }

  #if defined(__linux__)

  DIR           *d;
  struct dirent *de;
  d = opendir("/proc");

  if (!d) {

    if (lockfile[0]) unlink(lockfile);
    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }

  ACTF("Checking CPU core loadout...");

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    u8    fn[PATH_MAX];
    FILE *f;
    u8    tmp[MAX_LINE];
    u8    has_vmsize = 0;

    if (!isdigit(de->d_name[0])) { continue; }

    snprintf(fn, PATH_MAX, "/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) { continue; }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) { has_vmsize = 1; }

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) && !strchr(tmp, '-') &&
          !strchr(tmp, ',') && sscanf(tmp + 19, "%u", &hval) == 1 &&
          hval < sizeof(cpu_used) && has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    fclose(f);

  }

  closedir(d);

  #elif defined(__FreeBSD__) || defined(__DragonFly__)

  struct kinfo_proc *procs;
  size_t             nprocs;
  size_t             proccount;
  int                s_name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
  size_t             s_name_l = sizeof(s_name) / sizeof(s_name[0]);

  if (sysctl(s_name, s_name_l, NULL, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    return;

  }

  proccount = nprocs / sizeof(*procs);
  nprocs = nprocs * 4 / 3;

  procs = ck_alloc(nprocs);
  if (sysctl(s_name, s_name_l, procs, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    ck_free(procs);
    return;

  }

  for (i = 0; i < (s32)proccount; i++) {

    #if defined(__FreeBSD__)

    if (!strcmp(procs[i].ki_comm, "idle")) continue;

    // fix when ki_oncpu = -1
    s32 oncpu;
    oncpu = procs[i].ki_oncpu;
    if (oncpu == -1) oncpu = procs[i].ki_lastcpu;

    if (oncpu != -1 && oncpu < (s32)sizeof(cpu_used) && procs[i].ki_pctcpu > 60)
      cpu_used[oncpu] = 1;

    #elif defined(__DragonFly__)

    if (procs[i].kp_lwp.kl_cpuid < (s32)sizeof(cpu_used) &&
        procs[i].kp_lwp.kl_pctcpu > 10)
      cpu_used[procs[i].kp_lwp.kl_cpuid] = 1;

    #endif

  }

  ck_free(procs);

  #elif defined(__NetBSD__)

  struct kinfo_proc2 *procs;
  size_t              nprocs;
  size_t              proccount;
  int                 s_name[] = {

      CTL_KERN, KERN_PROC2, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), 0};
  size_t s_name_l = sizeof(s_name) / sizeof(s_name[0]);

  if (sysctl(s_name, s_name_l, NULL, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    return;

  }

  proccount = nprocs / sizeof(struct kinfo_proc2);
  procs = ck_alloc(nprocs * sizeof(struct kinfo_proc2));
  s_name[5] = proccount;

  if (sysctl(s_name, s_name_l, procs, &nprocs, NULL, 0) != 0) {

    if (lockfile[0]) unlink(lockfile);
    ck_free(procs);
    return;

  }

  for (i = 0; i < (s32)proccount; i++) {

    if (procs[i].p_cpuid < sizeof(cpu_used) && procs[i].p_pctcpu > 0)
      cpu_used[procs[i].p_cpuid] = 1;

  }

  ck_free(procs);

  #elif defined(__sun)

  kstat_named_t *n;
  kstat_ctl_t   *m;
  kstat_t       *k;
  cpu_stat_t     cs;
  u32            ncpus;

  m = kstat_open();

  if (!m) FATAL("kstat_open failed");

  k = kstat_lookup(m, "unix", 0, "system_misc");

  if (!k) {

    if (lockfile[0]) unlink(lockfile);
    kstat_close(m);
    return;

  }

  if (kstat_read(m, k, NULL)) {

    if (lockfile[0]) unlink(lockfile);
    kstat_close(m);
    return;

  }

  n = kstat_data_lookup(k, "ncpus");
  ncpus = n->value.i32;

  if (ncpus > sizeof(cpu_used)) ncpus = sizeof(cpu_used);

  for (i = 0; i < (s32)ncpus; i++) {

    k = kstat_lookup(m, "cpu_stat", i, NULL);
    if (kstat_read(m, k, &cs)) {

      if (lockfile[0]) unlink(lockfile);
      kstat_close(m);
      return;

    }

    if (cs.cpu_sysinfo.cpu[CPU_IDLE] > 0) continue;

    if (cs.cpu_sysinfo.cpu[CPU_USER] > 0 || cs.cpu_sysinfo.cpu[CPU_KERNEL] > 0)
      cpu_used[i] = 1;

  }

  kstat_close(m);

  #else
    #warning \
        "For this platform we do not have free CPU binding code yet. If possible, please supply a PR to https://github.com/AFLplusplus/AFLplusplus"
  #endif

  #if !defined(__aarch64__) && !defined(__arm__) && !defined(__arm64__)

  for (i = 0; i < afl->cpu_core_count; i++) {

  #else

  /* many ARM devices have performance and efficiency cores, the slower
     efficiency cores seem to always come first */

  for (i = afl->cpu_core_count - 1; i > -1; i--) {

  #endif

    if (cpu_used[i]) { continue; }

    OKF("Found a free CPU core, try binding to #%u.", i);

    if (bind_cpu(afl, i)) {

      /* Success :) */
      break;

    }

    WARNF("setaffinity failed to CPU %d, trying next CPU", i);

  }

  if (lockfile[0]) unlink(lockfile);

  if (i == afl->cpu_core_count || i == -1) {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %d CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). "
         "Starting\n"
         "    another fuzzer on this machine is probably a bad plan.\n"
         "%s",
         afl->cpu_core_count,
         afl->afl_env.afl_try_affinity ? ""
                                       : "    If you are sure, you can set "
                                         "AFL_NO_AFFINITY and try again.\n");

    if (!afl->afl_env.afl_try_affinity) { FATAL("No more free CPU cores"); }

  }

}

#endif                                                     /* HAVE_AFFINITY */

/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(afl_state_t *afl, void **ptrs, u32 cnt) {

  u32 i;

  for (i = 0; i < cnt - 2; ++i) {

    u32   j = i + rand_below(afl, cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;

  }

}


/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

void read_testcases(afl_state_t *afl, u8 *directory) {

  struct dirent **nl;
  s32             nl_cnt, subdirs = 1;
  u32             i;
  u8             *fn1, *dir = directory;
  u8              val_buf[2][STRINGIFY_VAL_SIZE_MAX];

  /* Auto-detect non-in-place resumption attempts. */

  if (dir == NULL) {

    fn1 = alloc_printf("%s/queue", afl->in_dir);
    if (!access(fn1, F_OK)) {

      afl->in_dir = fn1;
      subdirs = 0;

    } else {

      ck_free(fn1);

    }

    dir = afl->in_dir;

  }

  ACTF("Scanning '%s'...", dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(dir, &nl, NULL, alphasort);

  if (nl_cnt < 0 && directory == NULL) {

    if (errno == ENOENT || errno == ENOTDIR) {

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The "
           "fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file "
           "under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in "
           "the input\n"
           "    directory.\n");

    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (unlikely(afl->old_seed_selection && afl->shuffle_queue && nl_cnt > 1)) {

    ACTF("Shuffling queue...");
    shuffle_ptrs(afl, (void **)nl, nl_cnt);

  }

  // if (getenv("MYTEST")) afl->in_place_resume = 1;

  if (nl_cnt) {

    u32 done = 0;

    if (unlikely(afl->in_place_resume)) {

      i = nl_cnt;

    } else {

      i = 0;

    }

    do {

      if (unlikely(afl->in_place_resume)) { --i; }

      struct stat st;
      u8          dfn[PATH_MAX];
      snprintf(dfn, PATH_MAX, "%s/.state/deterministic_done/%s", afl->in_dir,
               nl[i]->d_name);
      u8 *fn2 = alloc_printf("%s/%s", dir, nl[i]->d_name);

      u8 passed_det = 0;

      if (lstat(fn2, &st) || access(fn2, R_OK)) {

        PFATAL("Unable to access '%s'", fn2);

      }

      /* obviously we want to skip "descending" into . and .. directories,
         however it is a good idea to skip also directories that start with
         a dot */
      if (subdirs && S_ISDIR(st.st_mode) && nl[i]->d_name[0] != '.') {

        free(nl[i]);                                         /* not tracked */
        read_testcases(afl, fn2);
        ck_free(fn2);
        goto next_entry;

      }

      free(nl[i]);

      if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn2, "/README.txt")) {

        ck_free(fn2);
        goto next_entry;

      }

      if (st.st_size > MAX_FILE) {

        WARNF("Test case '%s' is too big (%s, limit is %s), partial reading",
              fn2,
              stringify_mem_size(val_buf[0], sizeof(val_buf[0]), st.st_size),
              stringify_mem_size(val_buf[1], sizeof(val_buf[1]), MAX_FILE));

      }

      /* Check for metadata that indicates that deterministic fuzzing
         is complete for this entry. We don't want to repeat deterministic
         fuzzing when resuming aborted scans, because it would be pointless
         and probably very time-consuming. */

      if (!access(dfn, F_OK)) { passed_det = 1; }

      add_to_queue(afl, fn2, st.st_size >= MAX_FILE ? MAX_FILE : st.st_size,
                   passed_det);

      if (unlikely(afl->shm.cmplog_mode)) {

        if (afl->cmplog_lvl == 1) {

          if (!afl->cmplog_max_filesize ||
              afl->cmplog_max_filesize < st.st_size) {

            afl->cmplog_max_filesize = st.st_size;

          }

        } else if (afl->cmplog_lvl == 2) {

          if (!afl->cmplog_max_filesize ||
              afl->cmplog_max_filesize > st.st_size) {

            afl->cmplog_max_filesize = st.st_size;

          }

        }

      }

    next_entry:
      if (unlikely(afl->in_place_resume)) {

        if (unlikely(i == 0)) { done = 1; }

      } else {

        if (unlikely(++i >= (u32)nl_cnt)) { done = 1; }

      }

    } while (!done);

  }

  // if (getenv("MYTEST")) afl->in_place_resume = 0;

  free(nl);                                                  /* not tracked */

  if (!afl->queued_items && directory == NULL) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The "
         "fuzzer\n"
         "    needs one or more test case to start with - ideally, a small "
         "file under\n"
         "    1 kB or so. The cases must be stored as regular files directly "
         "in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", afl->in_dir);

  }

  if (unlikely(afl->shm.cmplog_mode)) {

    if (afl->cmplog_max_filesize < 1024) {

      afl->cmplog_max_filesize = 1024;

    } else {

      afl->cmplog_max_filesize = (((afl->cmplog_max_filesize >> 10) + 1) << 10);

    }

  }

  afl->last_find_time = 0;
  afl->queued_at_start = afl->queued_items;

}

/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8 *old_path, u8 *new_path) {

  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8 *tmp;

  if (!i) { return; }

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0) { PFATAL("Unable to open '%s'", old_path); }

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (dfd < 0) { PFATAL("Unable to create '%s'", new_path); }

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) {

    ck_write(dfd, tmp, i, new_path);

  }

  if (i < 0) { PFATAL("read() failed"); }

  ck_free(tmp);
  close(sfd);
  close(dfd);

}

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

void pivot_inputs(afl_state_t *afl) {

  struct queue_entry *q;
  u32                 id = 0, i;

  ACTF("Creating hard links for all input files...");

  for (i = 0; i < afl->queued_items && likely(afl->queue_buf[i]); i++) {

    q = afl->queue_buf[i];

    if (unlikely(q->disabled)) { continue; }

    char *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) {

      rsl = q->fname;

    } else {

      ++rsl;

    }

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {

      u8 *src_str;
      u32 src_id;

      afl->resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", afl->out_dir, rsl);

      /* Since we're at it, let's also get the parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {

        if (src_id < afl->queued_items) {

          struct queue_entry *s = afl->queue_buf[src_id];

          if (s) { q->depth = s->depth + 1; }

        }

        if (afl->max_depth < q->depth) { afl->max_depth = q->depth; }

      }

    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

      u8 *use_name = strstr(rsl, ",orig:");

      if (use_name) {

        use_name += 6;

      } else {

        use_name = rsl;

      }

      nfn = alloc_printf("%s/queue/id:%06u,time:0,execs:%llu,orig:%s",
                         afl->out_dir, id, afl->fsrv.total_execs, use_name);


    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) { mark_as_det_done(afl, q); }

    if (afl->custom_mutators_count) {

      run_afl_custom_queue_new_entry(afl, q, q->fname, NULL);

    }

    ++id;

  }

  if (afl->in_place_resume) { nuke_resume_dir(afl); }

}

/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

u32 find_start_position(afl_state_t *afl) {

  u8 tmp[4096] = {0};                    /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!afl->resuming_fuzz) { return 0; }

  if (afl->in_place_resume) {

    fn = alloc_printf("%s/fuzzer_stats", afl->out_dir);

  } else {

    fn = alloc_printf("%s/../fuzzer_stats", afl->in_dir);

  }

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) { return 0; }

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i;                                                 /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_item          : ");
  if (!off) { return 0; }

  ret = atoi(off + 20);
  if (ret >= afl->queued_items) { ret = 0; }
  return ret;

}

/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

void find_timeout(afl_state_t *afl) {

  u8 tmp[4096] = {0};                    /* Ought to be enough for anybody. */

  char *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!afl->resuming_fuzz) { return; }

  if (afl->in_place_resume) {

    fn = alloc_printf("%s/fuzzer_stats", afl->out_dir);

  } else {

    fn = alloc_printf("%s/../fuzzer_stats", afl->in_dir);

  }

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) { return; }

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i;                                                 /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout      : ");
  if (!off) { return; }

  ret = atoi(off + 20);
  if (ret <= 4) { return; }

  afl->fsrv.exec_tmout = ret;
  afl->timeout_given = 3;

}

/* A helper function for handle_existing_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(char *path, const char *prefix) {

  DIR           *d;
  struct dirent *d_ent;

  d = opendir(path);

  if (!d) { return 0; }

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.' &&
        (!prefix || !strncmp(d_ent->d_name, prefix, strlen(prefix)))) {

      u8 *fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) { PFATAL("Unable to delete '%s'", fname); }
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}

/* Get the number of runnable processes, with some simple smoothing. */

double get_runnable_processes(void) {

  double res = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE *f = fopen("/proc/stat", "r");
  char    tmp[1024];
  u32   val = 0;

  if (!f) { return 0; }

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) {

      val += atoi(tmp + 14);

    }

  }

  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif          /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__ || __NetBSD__) */

  return res;

}

/* Delete the temporary directory used for in-place session resume. */

void nuke_resume_dir(afl_state_t *afl) {

  char *fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", afl->out_dir);
  if (delete_files(fn, "auto_")) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", afl->out_dir);
  if (rmdir(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/_resume", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");

}

/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great.
   Resume fuzzing if `-` is set as in_dir or if AFL_AUTORESUME is set */

static void handle_existing_out_dir(afl_state_t *afl) {

  FILE *f;
  char *fn = alloc_printf("%s/fuzzer_stats", afl->out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  afl->fsrv.out_dir_fd = open(afl->out_dir, O_RDONLY);
  if (afl->fsrv.out_dir_fd < 0) { PFATAL("Unable to open '%s'", afl->out_dir); }


  f = fopen(fn, "r");

  if (f) {

    u64 start_time2, last_update;

    if (fscanf(f,
               "start_time     : %llu\n"
               "last_update    : %llu\n",
               &start_time2, &last_update) != 2) {

      FATAL("Malformed data in '%s'", fn);

    }

    fclose(f);

    /* Autoresume treats a normal run as in_place_resume if a valid out dir
     * already exists */

    if (!afl->in_place_resume && afl->autoresume) {

      OKF("Detected prior run with AFL_AUTORESUME set. Resuming.");
      afl->in_place_resume = 1;

    }

    /* Let's see how much work is at stake. */

    if (!afl->in_place_resume && last_update > start_time2 &&
        last_update - start_time2 > OUTPUT_GRACE * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results "
           "of more\n"
           "    than %d minutes worth of fuzzing. To avoid data loss, afl-fuzz "
           "will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the "
           "directory manually,\n"
           "    or specify a different output location for this job. To resume "
           "the old\n"
           "    session, pass '-' as input directory in the command line ('-i "
           "-')\n"
           "    or set the 'AFL_AUTORESUME=1' env variable and try again.\n",
           OUTPUT_GRACE);

      FATAL("At-risk data found in '%s'", afl->out_dir);

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (afl->in_place_resume) {

    char *orig_q = alloc_printf("%s/queue", afl->out_dir);

    afl->in_dir = alloc_printf("%s/_resume", afl->out_dir);

    rename(orig_q, afl->in_dir);                           /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <afl->out_dir>/.synced/.../id:*, if any are present. */

  if (!afl->in_place_resume) {

    fn = alloc_printf("%s/.synced", afl->out_dir);
    if (delete_files(fn, NULL)) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  /* Next, we need to clean up <afl->out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", afl->out_dir);
  if (delete_files(fn, "auto_")) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <afl->out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", afl->out_dir);
  if (rmdir(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue", afl->out_dir);
  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/queue_pklg", afl->out_dir);
  if (delete_files(fn, NULL)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/hangs_pklg", afl->out_dir);
  if (delete_files(fn, NULL)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/crashes_pklg", afl->out_dir);
  if (delete_files(fn, NULL)) { goto dir_cleanup_failed; }
  ck_free(fn);

  /* All right, let's do <afl->out_dir>/crashes/id:* and
   * <afl->out_dir>/hangs/id:*. */

  if (!afl->in_place_resume) {

    fn = alloc_printf("%s/crashes/README.txt", afl->out_dir);
    unlink(fn);                                            /* Ignore errors */
    ck_free(fn);

  }

  fn = alloc_printf("%s/crashes", afl->out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (afl->in_place_resume && rmdir(fn)) {

    time_t    cur_t = time(0);
    struct tm t;
    localtime_r(&cur_t, &t);

    char *nfn =
        alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

    rename(fn, nfn);                                      /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/hangs", afl->out_dir);

  /* Backup hangs, too. */

  if (afl->in_place_resume && rmdir(fn)) {

    time_t    cur_t = time(0);
    struct tm t;
    localtime_r(&cur_t, &t);

    char *nfn =
        alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn, t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

    rename(fn, nfn);                                      /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) { goto dir_cleanup_failed; }
  ck_free(fn);

  /* And now, for some finishing touches. */

  if (afl->file_extension) {

    fn = alloc_printf("%s/.cur_input.%s", afl->out_dir, afl->file_extension);

  } else {

    fn = alloc_printf("%s/.cur_input", afl->out_dir);

  }

  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  if (afl->afl_env.afl_tmpdir) {

    if (afl->file_extension) {

      fn = alloc_printf("%s/.cur_input.%s", afl->afl_env.afl_tmpdir,
                        afl->file_extension);

    } else {

      fn = alloc_printf("%s/.cur_input", afl->afl_env.afl_tmpdir);

    }

    if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  fn = alloc_printf("%s/fuzz_bitmap", afl->out_dir);
  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  if (!afl->in_place_resume) {

    fn = alloc_printf("%s/fuzzer_stats", afl->out_dir);
    if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  if (!afl->in_place_resume) {

    fn = alloc_printf("%s/plot_data", afl->out_dir);
    if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
    ck_free(fn);

  }

  fn = alloc_printf("%s/queue_data", afl->out_dir);
  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  fn = alloc_printf("%s/cmdline", afl->out_dir);
  if (unlink(fn) && errno != ENOENT) { goto dir_cleanup_failed; }
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped "
       "into\n"
       "    some files that shouldn't be there or that couldn't be removed - "
       "so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a "
       "different\n"
       "    output location for the tool.\n",
       fn);

  FATAL("Output directory cleanup failed");

}


/* Prepare output directories and fds. */

void setup_dirs_fds(afl_state_t *afl) {

  char *tmp;

  ACTF("Setting up output directories...");

  if (mkdir(afl->out_dir, 0700)) {

    if (errno != EEXIST) { PFATAL("Unable to create '%s'", afl->out_dir); }

    handle_existing_out_dir(afl);

  } else {

    if (afl->in_place_resume) {

      FATAL("Resume attempted but old output directory not found");

    }

    afl->fsrv.out_dir_fd = open(afl->out_dir, O_RDONLY);

#ifndef __sun

    if (afl->fsrv.out_dir_fd < 0 ||
        flock(afl->fsrv.out_dir_fd, LOCK_EX | LOCK_NB)) {

      PFATAL("Unable to flock() output directory.");

    }

#endif                                                            /* !__sun */

  }

  if (afl->is_main_node) {

    char *x = alloc_printf("%s/is_main_node", afl->out_dir);
    int fd = open(x, O_CREAT | O_RDWR, 0644);
    if (fd < 0) FATAL("cannot create %s", x);
    free(x);
    close(fd);

  }

  tmp = alloc_printf("%s/queue_pklg", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);
  
  tmp = alloc_printf("%s/hangs_pklg", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  tmp = alloc_printf("%s/crashes_pklg", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", afl->out_dir);
  if (mkdir(tmp, 0700)) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  /* Generally useful file descriptors. */

  afl->fsrv.dev_null_fd = open("/dev/null", O_RDWR);
  if (afl->fsrv.dev_null_fd < 0) { PFATAL("Unable to open /dev/null"); }

  afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", afl->out_dir);

  if (!afl->in_place_resume) {

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    ck_free(tmp);

    afl->fsrv.plot_file = fdopen(fd, "w");
    if (!afl->fsrv.plot_file) { PFATAL("fdopen() failed"); }

    fprintf(
        afl->fsrv.plot_file,
        "# relative_time, cycles_done, cur_item, corpus_count, "
        "pending_total, pending_favs, map_size, saved_crashes, "
        "saved_hangs, max_depth, execs_per_sec, total_execs, edges_found\n");

  } else {

    int fd = open(tmp, O_WRONLY | O_CREAT, DEFAULT_PERMISSION);
    if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
    ck_free(tmp);

    afl->fsrv.plot_file = fdopen(fd, "w");
    if (!afl->fsrv.plot_file) { PFATAL("fdopen() failed"); }

    fseek(afl->fsrv.plot_file, 0, SEEK_END);

  }

  fflush(afl->fsrv.plot_file);

  /* ignore errors */

}

void setup_cmdline_file(afl_state_t *afl, char **argv) {

  char *tmp;
  s32 fd;
  u32 i = 0;

  FILE *cmdline_file = NULL;

  /* Store the command line to reproduce our findings */
  tmp = alloc_printf("%s/cmdline", afl->out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (fd < 0) { PFATAL("Unable to create '%s'", tmp); }
  ck_free(tmp);

  cmdline_file = fdopen(fd, "w");
  if (!cmdline_file) { PFATAL("fdopen() failed"); }

  while (argv[i]) {

    fprintf(cmdline_file, "%s\n", argv[i]);
    ++i;

  }

  fclose(cmdline_file);

}

/* Setup the output file for fuzzed data, if not using -f. */

void setup_stdio_file(afl_state_t *afl) {

  if (afl->file_extension) {

    afl->fsrv.out_file =
        alloc_printf("%s/.cur_input.%s", afl->tmp_dir, afl->file_extension);

  } else {

    afl->fsrv.out_file = alloc_printf("%s/.cur_input", afl->tmp_dir);

  }

  unlink(afl->fsrv.out_file);                              /* Ignore errors */

  afl->fsrv.out_fd =
      open(afl->fsrv.out_file, O_RDWR | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  if (afl->fsrv.out_fd < 0) {

    PFATAL("Unable to create '%s'", afl->fsrv.out_file);

  }

}

/* Check CPU governor. */

void check_cpu_governor(afl_state_t *afl) {

#ifdef __linux__
  FILE *f;
  char    tmp[128];
  u64   min = 0, max = 0;

  if (afl->afl_env.afl_skip_cpufreq) { return; }

  if (afl->cpu_aff > 0) {

    snprintf(tmp, sizeof(tmp), "%s%d%s", "/sys/devices/system/cpu/cpu",
             afl->cpu_aff, "/cpufreq/scaling_governor");

  } else {

    snprintf(tmp, sizeof(tmp), "%s",
             "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");

  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) {

    if (afl->cpu_aff > 0) {

      snprintf(tmp, sizeof(tmp), "%s%d%s",
               "/sys/devices/system/cpu/cpufreq/policy", afl->cpu_aff,
               "/scaling_governor");

    } else {

      snprintf(tmp, sizeof(tmp), "%s",
               "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor");

    }

    f = fopen(tmp, "r");

  }

  if (!f) {

    WARNF("Could not check CPU scaling governor");
    return;

  }

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) { PFATAL("fgets() failed"); }

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) { return; }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {

    if (fscanf(f, "%llu", &min) != 1) { min = 0; }
    fclose(f);

  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {

    if (fscanf(f, "%llu", &max) != 1) { max = 0; }
    fclose(f);

  }

  if (min == max) { return; }

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in "
       "the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned "
       "by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing "
       "'performance'\n"
       "    with 'ondemand' or 'powersave'. If you don't want to change the "
       "settings,\n"
       "    set AFL_SKIP_CPUFREQ to make afl-fuzz skip this check - but expect "
       "some\n"
       "    performance drop.\n",
       min / 1024, max / 1024);
  FATAL("Suboptimal CPU scaling governor");

#elif defined __APPLE__
  u64    min = 0, max = 0;
  size_t mlen = sizeof(min);
  if (afl->afl_env.afl_skip_cpufreq) return;

  ACTF("Checking CPU scaling governor...");

  if (sysctlbyname("hw.cpufrequency_min", &min, &mlen, NULL, 0) == -1) {

    WARNF("Could not check CPU min frequency");
    return;

  }

  if (sysctlbyname("hw.cpufrequency_max", &max, &mlen, NULL, 0) == -1) {

    WARNF("Could not check CPU max frequency");
    return;

  }

  if (min == max) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz.\n"
       "    If you don't want to check those settings, set "
       "AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance "
       "drop.\n",
       min / 1024, max / 1024);
  FATAL("Suboptimal CPU scaling governor");
#else
  (void)afl;
#endif

}

/* Count the number of logical CPU cores. */

void get_core_count(afl_state_t *afl) {

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)

  size_t s = sizeof(afl->cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

  #ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &afl->cpu_core_count, &s, NULL, 0) < 0)
    return;

  #else

  int s_name[2] = {CTL_HW, HW_NCPU};

  if (sysctl(s_name, 2, &afl->cpu_core_count, &s, NULL, 0) < 0) return;

  #endif                                                      /* ^__APPLE__ */

#else

  #ifdef HAVE_AFFINITY

  afl->cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

  #else

  FILE *f = fopen("/proc/stat", "r");
  u8    tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) ++afl->cpu_core_count;

  fclose(f);

  #endif                                                  /* ^HAVE_AFFINITY */

#endif                        /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (afl->cpu_core_count > 0) {

    u32 cur_runnable = 0;

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    ++cur_runnable;

#endif                           /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %d CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        afl->cpu_core_count, afl->cpu_core_count > 1 ? "s" : "", cur_runnable,
        cur_runnable * 100.0 / afl->cpu_core_count);

    if (afl->cpu_core_count > 1) {

      if (cur_runnable > afl->cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if ((s64)cur_runnable + 1 <= (s64)afl->cpu_core_count) {

        OKF("Try parallel jobs - see "
            "%s/fuzzing_in_depth.md#c-using-multiple-cores",
            doc_path);

      }

    }

  } else {

    afl->cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");

  }

}


/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {

  (void)sig;
  afl_states_clear_screen();

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  (void)sig;
  OKF("Stop signal %d", sig);
  afl_states_stop();

}

/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  (void)sig;
  afl_states_request_skip();

}


/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

void setup_signal_handlers(void) {

  struct sigaction sa;
  int original_flags;

  memset((void *)&sa, 0, sizeof(sa));
  sa.sa_handler = NULL;
#ifdef SA_RESTART
  sa.sa_flags = SA_RESTART;
#endif
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  original_flags = sa.sa_flags;
  sa.sa_flags = SA_RESETHAND;
  sigaction(SIGSEGV, &sa, NULL);
  sa.sa_flags = original_flags;

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}

/* Make a copy of the current command line. */

void save_cmdline(afl_state_t *afl, u32 argc, char **argv) {

  u32 len = 1, i;
  u8 *buf;

  for (i = 0; i < argc; ++i) {

    len += strlen(argv[i]) + 1;

  }


  for (i = 0; i < argc; ++i) {

    u32 l = strlen(argv[i]);

    if (!argv[i] || !buf) { FATAL("null deref detected"); }

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) { *(buf++) = ' '; }

  }

  *buf = 0;

}

