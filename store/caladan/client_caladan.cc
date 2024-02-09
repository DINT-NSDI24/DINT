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
#include "stat.h"
#include "tatp.h"
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
#include <atomic>

namespace {

// machine id
int machine_id;

// number of worker threads per machine
int threads;

// benchmark
std::string benchmark;

// run mode
std::string mode;

// server address
netaddr raddr;

// workload generator array
std::vector<TxnType> workgen_arr;

// statistics
std::vector<std::vector<uint64_t>> lat_samples;
std::vector<uint64_t> pkt_cnt, suc_pkt_cnt;
std::atomic<bool> stat_started {false};

// create workload generator array
void CreateWorkgenArr(std::string benchmark) {
  workgen_arr.reserve(100);
  if (benchmark.compare("contention") == 0) {
    workgen_arr.insert(workgen_arr.end(), 50, TxnType::kTxnRead);
    workgen_arr.insert(workgen_arr.end(), 50, TxnType::kTxnSet);
  } else if (benchmark.compare("parallel") == 0) {
    workgen_arr.insert(workgen_arr.end(), 100, TxnType::kTxnRead);
  } else panic("unknown benchmark");

  assert(workgen_arr.size() == 100);
}

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

// read
bool TxnRead(int worker_id, uint64_t &tg_seed, rt::UdpConn *c, netaddr servaddr) {
  // transaction parameters
  uint32_t s_id = tatp_nurand(&tg_seed);
  uint8_t sf_type = (fastrand(&tg_seed) % 4) + 1;
  uint8_t start_time = (fastrand(&tg_seed) % 3) * 8;

  // read the call forwarding record
  store_key_t store_key;
  store_key.s_id = s_id;
  store_key.sf_type = sf_type;
  store_key.start_time = start_time;

  message msg;
  msg.type = PktType::kRead;
  msg.key = store_key.key;
  NetHandshake(&msg, c, servaddr, worker_id);

  assert(msg.key == store_key.key);

  if (msg.type == PktType::kNotExist) return false;
  else assert(msg.type == PktType::kGrantRead);
  if (stat_started) suc_pkt_cnt[worker_id]++;

  auto *val = (store_val_t *)&msg.val;
  _unused(val);
  assert(val->numberx[0] == kValMagic);

  return true;
}

// set
bool TxnSet(int worker_id, uint64_t &tg_seed, rt::UdpConn *c, netaddr servaddr) {
  // transaction parameters
  uint32_t s_id = tatp_nurand(&tg_seed);
  uint8_t sf_type = (fastrand(&tg_seed) % 4) + 1;
  uint8_t start_time = (fastrand(&tg_seed) % 3) * 8;
  uint8_t end_time = (fastrand(&tg_seed) % 24) * 1;

  // read the call forwarding record
  store_key_t store_key;
  store_key.s_id = s_id;
  store_key.sf_type = sf_type;
  store_key.start_time = start_time;

  message msg;
  msg.type = PktType::kRead;
  msg.key = store_key.key;
  
  store_val_t *val = (store_val_t *)&msg.val;
  val->numberx[0] = kValMagic;
  val->end_time = end_time;

  NetHandshake(&msg, c, servaddr, worker_id);

  assert(msg.key == store_key.key);

  if (msg.type == PktType::kNotExist) return false;
  else assert(msg.type == PktType::kSetAck);
  if (stat_started) suc_pkt_cnt[worker_id]++;

  return true;
}

// main client thread
void ClientLoop(int wrkr_gid, netaddr servaddr) {
  int wrkr_lid = wrkr_gid % threads;
  uint64_t tg_seed = 0xdeadbeef + wrkr_gid;
  log_emerg("worker %d started", wrkr_lid);

  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, 0}));
  if (c == nullptr) panic("failed to create socket");

  while (true) {
    auto txn_type = workgen_arr[fastrand(&tg_seed) % 100];

    bool txn_committed = false; _unused(txn_committed);
    switch (txn_type) {
      case TxnType::kTxnRead:
        txn_committed = TxnRead(wrkr_lid, tg_seed, c.get(), servaddr);
        break;
      case TxnType::kTxnSet:
        txn_committed = TxnSet(wrkr_lid, tg_seed, c.get(), servaddr);
        break;
      default:
        panic("unknown transaction type %d", static_cast<int>(txn_type));
    }
  }
}

void ClientHandler(void *arg) {
  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, 0}));
  if (c == nullptr) panic("couldn't establish control connection");

  // Send the control message.
  net_req req = {threads};
  ssize_t ret = c->WriteTo(&req, sizeof(req), &raddr);
  if (ret != sizeof(req)) panic("couldn't send control message");

  // Receive the control response.
  union {
    net_resp resp;
    char buf[rt::UdpConn::kMaxPayloadSize];
  };
  ret = c->ReadFrom(&resp, rt::UdpConn::kMaxPayloadSize, NULL);
  if (ret < static_cast<ssize_t>(sizeof(net_resp)))
    panic("failed to receive control response");
  if (resp.nports != threads)
    panic("got back invalid control response");

  // Create one UDP connection per thread.
  std::vector<rt::Thread> th;
  for (int i = 0; i < threads; ++i) {
    th.emplace_back(rt::Thread(std::bind(ClientLoop, i, netaddr{raddr.ip, resp.ports[i]})));
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

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 6) {
    std::cerr << "usage: [cfg_file] [machine_id] [#threads] [benchmark] [debug/expr]" << std::endl;
    return -EINVAL;
  }

  machine_id = std::stoi(argv[2], nullptr, 0);
  threads = std::stoi(argv[3], nullptr, 0);
  benchmark = argv[4];
  mode = argv[5];
  CreateWorkgenArr(benchmark);

  pkt_cnt.resize(threads, 0);
  suc_pkt_cnt.resize(threads, 0);
  lat_samples.resize(threads);

  int ret;

  ret = StringToAddr("10.10.1.1", &raddr.ip);
  if (ret) return -EINVAL;
  raddr.port = kFasstPort;

  log_emerg("finish initialization");

  ret = runtime_init(argv[1], ClientHandler, NULL);
  if (ret) {
    printf("failed to start client runtime\n");
    return ret;
  }

  return 0;
}