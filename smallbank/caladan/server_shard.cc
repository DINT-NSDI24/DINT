extern "C" {
#include <base/log.h>
#include <net/ip.h>
}

#include "base/init.h"
#include "runtime.h"
#include "thread.h"
#include "sync.h"
#include "timer.h"
#include "net.h"
#include "utils.h"
#include "smallbank.h"
#include "proto.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <utility>
#include <memory>
#include <chrono>
#include <vector>
#include <algorithm>
#include <numeric>
#include <random>

#include "cpu_util.h"
static volatile double user_used_cores; 
static volatile double kern_used_cores; 

namespace {

// shard id
int shard_id;

// the smallbank tables
// tables[0]: saving
// tables[1]: checking
kvs *tables[kTableNum];

// transaction locks
volatile int txn_locks[kTableNum][kLockNum];

// exclusive lock counter
uint32_t num_ex[kTableNum][kLockNum];

// shared lock counter
uint32_t num_sh[kTableNum][kLockNum];

// log
log_entry *txn_log[16];
thread_local uint32_t log_entry_cnt = 0;

void PopulateTables() {
  for (int i = 0; i < kTableNum; i++) 
    tables[i] = new kvs();

  kvs_init(tables[TableType::kSaving], kAccountNum * 3/2 / kKeysPerEntry);
  kvs_init(tables[TableType::kChecking], kAccountNum * 3/2 / kKeysPerEntry);

  populate_saving_and_checking_tables(tables[TableType::kSaving], tables[TableType::kChecking]);
}

void *cpu_mon_func(void *arg) {
#define num_cpus 16
  int cpu_ids[num_cpus] = {3,  5,  7,  9,  11, 13, 15, 17,
                           75, 77, 79, 81, 83, 85, 87, 89};

  struct cpuusage last_usage, cur_usage;
  double utime_pct, ktime_pct;

  get_cpu_usage(cpu_ids, num_cpus, &last_usage);

  while (true) {
    rt::Sleep(1000000);
    get_cpu_usage(cpu_ids, num_cpus, &cur_usage);

    cpuusage_get_diff(&cur_usage, &last_usage, &utime_pct, &ktime_pct);

    user_used_cores = num_cpus * utime_pct;
    kern_used_cores = num_cpus * ktime_pct;

    fprintf(stderr, "user_used_cores = %lf, kern_used_cores = %lf\n",
            user_used_cores, kern_used_cores);

    last_usage = cur_usage;
  }

  return NULL;
}

void *cpu_mon_handler(void *arg) {
#define CPU_MON_PORT 20231
  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, CPU_MON_PORT}));
  if (unlikely(c == nullptr)) panic("couldn't listen for cpu_mon connections");

  struct cpu_mon_message {
    double ucores;
    double kcores;
  } msg;
  netaddr cliaddr;

  while (1) {
    ssize_t ret = c->ReadFrom(&msg, sizeof(cpu_mon_message), &cliaddr);
    msg.ucores = user_used_cores;
    msg.kcores = kern_used_cores;
    ret = c->WriteTo(&msg, sizeof(cpu_mon_message), &cliaddr);
  }

  return NULL;
}

// main processing loop for server
void ServerLoop(int worker_id, rt::UdpConn *c) {
  log_emerg("worker %d started", worker_id);

  message msg;
  netaddr cliaddr;

  while (1) {
    ssize_t ret = c->ReadFrom(&msg, sizeof(message), &cliaddr);
    if (ret != sizeof(message)) panic("couldn't receive message");
    uint64_t lh = lock_hash(tables[msg.table], msg.key);

    if (msg.type == PktType::kAcquireShared || msg.type == PktType::kAcquireExclusive ||
        msg.type == PktType::kReleaseShared || msg.type == PktType::kReleaseExclusive) {
      int ret = __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 0, 1);
      if (ret == 1) {
        msg.type = PktType::kRetry;
        ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
        if (ret != sizeof(message)) panic("couldn't send message");
        continue;
      }
    }

    if (msg.type == PktType::kAcquireShared) {
      if (num_ex[msg.table][lh] == 0) {
        num_sh[msg.table][lh]++;
        kvs_get(tables[msg.table], msg.key, msg.val, &msg.ver);
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kGrantShared;
        ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
        if (ret != sizeof(message)) panic("couldn't send message");
      } else {
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kRejectShared;
        ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
        if (ret != sizeof(message)) panic("couldn't send message");
      }
    }

    else if (msg.type == PktType::kAcquireExclusive) {
      if (num_ex[msg.table][lh] == 0 && num_sh[msg.table][lh] == 0) {
        num_ex[msg.table][lh]++;
        kvs_get(tables[msg.table], msg.key, msg.val, &msg.ver);
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kGrantExclusive;
        ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
        if (ret != sizeof(message)) panic("couldn't send message");
      } else {
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kRejectExclusive;
        ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
        if (ret != sizeof(message)) panic("couldn't send message");
      }
    }

    else if (msg.type == PktType::kReleaseShared) {
      num_sh[msg.table][lh]--;
      __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
      msg.type = PktType::kReleaseSharedAck;
      ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
      if (ret != sizeof(message)) panic("couldn't send message");
    }

    else if (msg.type == PktType::kReleaseExclusive) {
      num_ex[msg.table][lh]--;
      __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
      msg.type = PktType::kReleaseExclusiveAck;
      ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
      if (ret != sizeof(message)) panic("couldn't send message");
    }

    else if (msg.type == PktType::kCommitPrim) {
      kvs_set(tables[msg.table], msg.key, msg.val);
      msg.type = PktType::kCommitPrimAck;
      ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
      if (ret != sizeof(message)) panic("couldn't send message");
    }
    
    else if (msg.type == PktType::kCommitBck) {
      kvs_set(tables[msg.table], msg.key, msg.val);
      msg.type = PktType::kCommitBckAck;
      ssize_t ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
      if (ret != sizeof(message)) panic("couldn't send message");
    }
    
    else if (msg.type == PktType::kCommitLog) {
      int cpu_id = rt::read_once(kthread_idx);
      txn_log[cpu_id][log_entry_cnt].table = msg.table;
      txn_log[cpu_id][log_entry_cnt].key = msg.key;
      memcpy(txn_log[cpu_id][log_entry_cnt].val, msg.val, kValSize);
      txn_log[cpu_id][log_entry_cnt].ver = msg.ver;
      log_entry_cnt = (log_entry_cnt + 1) % kMaxLogEntryNum;

      msg.type = PktType::kCommitLogAck;
      ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
      if (ret != sizeof(message)) panic("couldn't send message");
    }

    else panic("unknown operation %d", msg.type);
  }
}

void ServerHandler(void *arg) {
  if (shard_id == 1) {
    rt::Spawn([]() { cpu_mon_func(NULL); });
    rt::Spawn([]() { cpu_mon_handler(NULL); });
  }

  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, kFasstPort}));
  if (unlikely(c == nullptr)) panic("couldn't listen for control connections");

  while (true) {
    net_req req;
    netaddr raddr;
    ssize_t ret = c->ReadFrom(&req, sizeof(req), &raddr);
    if (ret != sizeof(req)) panic("couldn't read request");

    rt::Spawn([=, &c]{
      union {
        net_resp resp;
        char buf[rt::UdpConn::kMaxPayloadSize];
      };
      resp.nports = req.nports;

      std::vector<rt::Thread> th;

      // Create the worker threads.
      for (int i = 0; i < req.nports; ++i) {
        std::unique_ptr<rt::UdpConn> cin(rt::UdpConn::Listen({0, 0}));
        if (unlikely(cin == nullptr)) panic("couldn't dial data connection");
        resp.ports[i] = cin->LocalAddr().port;
        th.emplace_back(rt::Thread(std::bind(ServerLoop, i, cin.release())));
      }

      // Send the port numbers to the client.
      ssize_t len = sizeof(net_resp) + sizeof(uint16_t) * req.nports;
      if (len > static_cast<ssize_t>(rt::UdpConn::kMaxPayloadSize))
        panic("too big");
      ssize_t ret = c->WriteTo(&resp, len, &raddr);
      if (ret != len) 
        panic("udp write failed, ret = %ld", ret);

      for (auto &t: th)
        t.Join();
    });
  }
}

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: [cfg_file] [shard_id]" << std::endl;
    return -EINVAL;
  }

  shard_id = std::stoi(argv[2], nullptr, 0);
  PopulateTables();

  for (int i = 0; i < 16; ++i)
    txn_log[i] = new log_entry[kMaxLogEntryNum];

  log_emerg("finish initialization");

  int ret = runtime_init(argv[1], ServerHandler, NULL);
  if (ret) {
    printf("failed to start client runtime\n");
    return ret;
  }

  return 0;
}