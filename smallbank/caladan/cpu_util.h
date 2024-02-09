// cpu utilization stats

#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct cpuusage {
  char name[20];
  // Absolute values since last reboot.
  unsigned long long usertime;
  unsigned long long kerntime;
  unsigned long long totaltime;
};

struct cpustat {
  char name[20];
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal,
      guest, guest_nice;
};

static inline struct cpuusage cpuusage_from_cpustat(struct cpustat* s) {
  struct cpuusage r;
  strncpy(r.name, s->name, sizeof(r.name));
  r.name[sizeof(r.name) - 1] = '\0';
  r.usertime = s->user + s->nice;
  r.kerntime = s->system + s->irq + s->softirq;
  r.totaltime = r.usertime + r.kerntime + s->idle + s->iowait + s->steal +
                s->guest + s->guest_nice;
  return r;
}

static inline void cpuusage_get_diff(struct cpuusage* now, struct cpuusage* prev,
                       double* utime_pct, double* ktime_pct) {
  // the number of ticks that passed by since the last measurement
  const unsigned long long usertime = now->usertime - prev->usertime;
  const unsigned long long kerntime = now->kerntime - prev->kerntime;
  const unsigned long long totaltime = now->totaltime - prev->totaltime;
  // they are divided by themselves - so the unit does not matter.
  *utime_pct = usertime * 1.0 / totaltime;
  *ktime_pct = kerntime * 1.0 / totaltime;
}

static inline void get_cpu_usage(int* cpu_ids, int num_cpus, struct cpuusage* now) {
  assert(num_cpus < 32);
  char cpu_id_strs[32][20];
  for (int i = 0; i < num_cpus; i++)
    sprintf(cpu_id_strs[i], "cpu%d", cpu_ids[i]);
  now->usertime = now->kerntime = now->totaltime = 0;

  const int stat = open("/proc/stat", O_RDONLY);
  assert(stat != -1);
  fcntl(stat, F_SETFL, O_NONBLOCK);

  // let's read everything in one call so it's nicely synced.
  int r = lseek(stat, SEEK_SET, 0);
  assert(r != -1);
  char buffer[10001];
  const ssize_t readed = read(stat, buffer, sizeof(buffer) - 1);
  assert(readed != -1);
  buffer[readed] = '\0';
  // Read the values from the readed buffer.
  FILE* f = fmemopen(buffer, readed, "r");
  // Uch, so much boring typing.
  struct cpustat c = {0};
  int cnt = 0;
  while (fscanf(f, "%19s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                c.name, &c.user, &c.nice, &c.system, &c.idle, &c.iowait, &c.irq,
                &c.softirq, &c.steal, &c.guest, &c.guest_nice) == 11) {
    if (strcmp(c.name, cpu_id_strs[cnt]) == 0) {
      struct cpuusage this_now = cpuusage_from_cpustat(&c);
      now->usertime += this_now.usertime;
      now->kerntime += this_now.kerntime;
      now->totaltime += this_now.totaltime;
      cnt++;
    }
    if (cnt == num_cpus) break;
  }
  fclose(f);

  return;
}
