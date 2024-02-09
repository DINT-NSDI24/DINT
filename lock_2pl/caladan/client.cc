extern "C" {
#include <base/log.h>
#include <net/ip.h>
}

#include "base/init.h"
#include "runtime.h"
#include "thread.h"
#include "sync.h"
#include "base/time.h"
#include "timer.h"
#include "net.h"
#include "proto.h"
#include "stat.h"

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
#include <atomic>

namespace {

// machine id
int machine_id;

// number of worker threads
int threads;

// run mode
std::string mode;

// server address
netaddr raddr;

// trace
std::vector<std::vector<uint32_t>> trace_tid;
std::vector<std::vector<uint8_t>> trace_action;
std::vector<std::vector<uint32_t>> trace_lid;
std::vector<std::vector<uint8_t>> trace_type;

std::vector<std::vector<uint32_t>> txn_l;
std::vector<std::vector<uint32_t>> txn_r;

// statistics
std::vector<std::vector<uint64_t>> lat_samples;
std::vector<uint64_t> pkt_cnt, suc_pkt_cnt;
std::atomic<bool> stat_started {false};

void CollectStat() {
  uint64_t total_pkt = std::accumulate(pkt_cnt.begin(), pkt_cnt.end(), 0UL);
  uint64_t total_suc_pkt = std::accumulate(suc_pkt_cnt.begin(), suc_pkt_cnt.end(), 0UL);

  std::vector<uint64_t> lat_aggr;
  for (int i = 0; i < threads; i++)
    lat_aggr.insert(lat_aggr.end(), lat_samples[i].begin(), lat_samples[i].end());
  uint64_t total_lat = std::accumulate(lat_aggr.begin(), lat_aggr.end(), 0UL);

  log_emerg("throughput: %lu", total_pkt / (kStatsEndSec - kStatsStartSec));
  log_emerg("goodput: %lu", total_suc_pkt / (kStatsEndSec - kStatsStartSec));
  log_emerg("average latency: %lu", total_lat / lat_aggr.size());
  log_emerg("median latency: %lu", Percentile(lat_aggr, 50));
  log_emerg("99th percentile latency: %lu", Percentile(lat_aggr, 99));
  log_emerg("99.9th percentile latency: %lu", Percentile(lat_aggr, 99.9));
}

// print throughput
void PrintTput(uint32_t poll_cnt) {
  log_emerg("%u throughput", poll_cnt);

  static uint64_t last_pkt = 0, last_suc_pkt = 0;
  uint64_t total_pkt = std::accumulate(pkt_cnt.begin(), pkt_cnt.end(), 0UL);
  uint64_t total_suc_pkt = std::accumulate(suc_pkt_cnt.begin(), suc_pkt_cnt.end(), 0UL);
  log_emerg("pkt: %lu", total_pkt - last_pkt);
  log_emerg("suc_pkt: %lu", total_suc_pkt - last_suc_pkt);
  last_pkt = total_pkt;
  last_suc_pkt = total_suc_pkt;
}

void StatLoop() {
  uint32_t poll_cnt = 0;
  while (1) {
    rt::Sleep(kStatsPollIntv*1000000);
    if (mode.compare("debug") == 0 && stat_started) PrintTput(poll_cnt);
    poll_cnt++;
    if (unlikely(poll_cnt == kStatsStartSec + 1)) 
      stat_started = true;

    if (unlikely(poll_cnt == kStatsEndSec + 1)) {
      stat_started = false;
      CollectStat();
    }

    if (unlikely(poll_cnt > kExitSec)) {
      init_shutdown(EXIT_SUCCESS);
    }
  }
}

void GetTraces(int worker_id) {
  // two kinds of benchmarks
  std::string filename = "traces/microbenchmarks/lock_24000000_r_0.8/trace_" 
    + std::to_string((machine_id - 1) * threads + worker_id) + ".csv";

  // get the traces
  std::ifstream fin(filename);
  std::string buffer;

  // read the first line of csv, which does not contain data
  std::getline(fin, buffer);

  int count_a = 0, count_r = 0;
  uint32_t c_tid, c_lid, last_tid = 0, len = 0;
  uint8_t c_action, c_type;

  // parse the trace line by line
  while (std::getline(fin, buffer)) {
    if (sscanf(buffer.c_str(), "%u,%hhu,%u,%hhu", &c_tid, &c_action, &c_lid, &c_type) != 4)
      panic("failed to parse trace");
    
    if (c_tid != last_tid) {
      txn_r[worker_id][last_tid] = len;
      txn_l[worker_id][c_tid] = len;
      last_tid = c_tid;
    }

    trace_tid[worker_id].push_back(c_tid);
    trace_action[worker_id].push_back(c_action);
    trace_lid[worker_id].push_back(c_lid);
    trace_type[worker_id].push_back(c_type);

    if (c_type == 0) count_a++;
    else if (c_type == 1) count_r++;
    
    len++;
  }

  txn_r[worker_id][last_tid] = len;

  fin.close();
  log_emerg("number of reads: %d, number of writes: %d", count_a, count_r);
}

void NetHandshake(message *msg, rt::UdpConn *c, netaddr raddr, int worker_id) {
  uint64_t begin = microtime();

  ssize_t ret = c->WriteTo(msg, sizeof(*msg), &raddr);
  if (ret != sizeof(*msg)) panic("couldn't send message");

  ret = c->ReadFrom(msg, sizeof(*msg), NULL);
  if (ret != sizeof(*msg)) panic("couldn't receive message");

  uint64_t lat = microtime() - begin;
  if (stat_started) {
    pkt_cnt[worker_id]++;
    lat_samples[worker_id].push_back(lat);
  }
}

void ClientLoop(int worker_id) {
  log_emerg("worker %d started", worker_id);

  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, 0}));
  if (c == nullptr) panic("couldn't establish connection");

  uint32_t idx = 0, last_tid = 0;

  while (true) {
    if (unlikely(idx == trace_lid[worker_id].size())) idx = 0;

    uint32_t lid = trace_lid[worker_id][idx];
    uint32_t tid = trace_tid[worker_id][idx];

    if (trace_action[worker_id][idx] == PktType::kAcquireLock) {
      if (mode.compare("debug") == 0) {
        if (unlikely(tid != last_tid)) {
          if (unlikely(tid % 10000 == 0)) 
            log_emerg("worker %d finished %u transactions", worker_id, tid);
          last_tid = tid;
        }
      }

      message msg = {PktType::kAcquireLock, lid, trace_type[worker_id][idx]};
      
      while (true) {
        msg.action = PktType::kAcquireLock;
        NetHandshake(&msg, c.get(), raddr, worker_id);
        assert(msg.lid == lid && msg.type == trace_type[worker_id][idx]);

        if (msg.action == PktType::kGrantLock || msg.action == PktType::kRejectLock) break;
        else assert(msg.action == PktType::kRetry);
      }

      if (msg.action == PktType::kGrantLock) {
        if (stat_started) suc_pkt_cnt[worker_id]++;
        idx++;
      }
      else if (msg.action == PktType::kRejectLock) {
        // release locks and retry txn
        for (auto i = txn_l[worker_id][tid]; i < idx; i++) {
          msg = {PktType::kReleaseLock, trace_lid[worker_id][i], trace_type[worker_id][i]};
          while (true) {
            msg.action = PktType::kReleaseLock;
            NetHandshake(&msg, c.get(), raddr, worker_id);
            assert(msg.lid == trace_lid[worker_id][i] && msg.type == trace_type[worker_id][i]);

            if (msg.action == PktType::kReleaseAck) break;
            else assert(msg.action == PktType::kRetry);
          }
        }
        idx = txn_l[worker_id][tid];
      } else panic("unknown action type");
    } 
    
    else if (trace_action[worker_id][idx] == PktType::kReleaseLock) {
      message msg = {PktType::kReleaseLock, lid, trace_type[worker_id][idx]};

      while (true) {
        msg.action = PktType::kReleaseLock;
        NetHandshake(&msg, c.get(), raddr, worker_id);
        assert(msg.lid == lid && msg.type == trace_type[worker_id][idx]);

        if (msg.action == PktType::kReleaseAck) break;
        else assert(msg.action == PktType::kRetry);
      }
      if (stat_started) suc_pkt_cnt[worker_id]++;

      idx++;
    }
    
    else panic("unknown action type");
  }
}

void ClientHandler(void *arg) {
  for (int i = 0; i < threads; i++)
    GetTraces(i);

  log_emerg("finish getting traces");

  std::vector<rt::Thread> th;
  for (int i = 0; i < threads; i++) {
    th.emplace_back(rt::Thread([&, i]{
      ClientLoop(i);
    }));
  }
 
  rt::Thread(StatLoop).Detach();

  for (auto& t: th)
    t.Join();
}

int StringToAddr(const char *str, uint32_t *addr) {
  uint8_t a, b, c, d;

  if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4)
    return -EINVAL;

  *addr = MAKE_IP_ADDR(a, b, c, d);
  return 0;
}

}

int main(int argc, char **argv) {
  if (argc != 5) {
    std::cerr << "usage: [cfg_file] [machine_id]"
              << " [#threads] [debug/expr]" << std::endl;
    return -EINVAL;
  }
  
  machine_id = std::stoi(argv[2], nullptr, 0);
  threads = std::stoi(argv[3], nullptr, 0);
  mode = argv[4];

  trace_tid.resize(threads);
  trace_type.resize(threads);
  trace_lid.resize(threads);
  trace_action.resize(threads);

  txn_l.resize(threads);
  txn_r.resize(threads);
  for (int i = 0; i < threads; i++) {
    txn_l[i].resize(kMaxTxnNum);
    txn_r[i].resize(kMaxTxnNum);
  }

  lat_samples.resize(threads);
  pkt_cnt.resize(threads, 0);
  suc_pkt_cnt.resize(threads, 0);

  int ret;

  ret = StringToAddr("10.10.1.1", &raddr.ip);
  if (ret) return -EINVAL;
  raddr.port = kMagicPort;

  log_emerg("finish initialization");

  ret = runtime_init(argv[1], ClientHandler, NULL);
  if (ret) {
    printf("failed to start client runtime\n");
    return ret;
  }

  return 0;
}
