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

// the id of the client machine
int machine_id;

// the number of worker threads to spawn
int threads;

// run mode
std::string mode;

// the remote address of the server
netaddr raddr;

// trace
std::vector<std::vector<uint64_t>> trace_key;
std::vector<std::vector<uint8_t *>> trace_val;
std::vector<std::vector<uint32_t>> trace_ver;

// statistics
std::vector<std::vector<uint64_t>> lat_samples;
std::vector<uint64_t> pkt_cnt;
std::atomic<bool> stat_started {false};

void CollectStat() {
  uint64_t total_pkt = std::accumulate(pkt_cnt.begin(), pkt_cnt.end(), 0UL);

  std::vector<uint64_t> lat_aggr;
  for (int i = 0; i < threads; i++)
    lat_aggr.insert(lat_aggr.end(), lat_samples[i].begin(), lat_samples[i].end());
  uint64_t total_lat = std::accumulate(lat_aggr.begin(), lat_aggr.end(), 0UL);

  log_emerg("throughput: %lu", total_pkt / (kStatsEndSec - kStatsStartSec));
  log_emerg("goodput: %lu", total_pkt / (kStatsEndSec - kStatsStartSec));
  log_emerg("average latency: %lu", total_lat / lat_aggr.size());
  log_emerg("median latency: %lu", Percentile(lat_aggr, 50));
  log_emerg("99th percentile latency: %lu", Percentile(lat_aggr, 99));
  log_emerg("99.9th percentile latency: %lu", Percentile(lat_aggr, 99.9));
}

// print throughput
void PrintTput(uint32_t poll_cnt) {
  log_emerg("%u throughput", poll_cnt);

  static uint64_t last_pkt = 0;
  uint64_t total_pkt = std::accumulate(pkt_cnt.begin(), pkt_cnt.end(), 0UL);
  log_emerg("pkt: %lu", total_pkt - last_pkt);
  last_pkt = total_pkt;
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
  std::string filename = "traces/microbenchmarks/trace_" 
      + std::to_string((machine_id - 1) * threads + worker_id) + ".csv";

  // get the traces
  std::ifstream fin(filename);
  std::string buffer;

  // read the first line of csv, which does not contain data
  std::getline(fin, buffer);

  uint64_t c_key;
  char *c_val_literal = new char[kValSize*2+1];
  uint32_t c_ver;

  // parse the trace line by line
  while (std::getline(fin, buffer)) {
    if (sscanf(buffer.c_str(), "%lu,%u,%s", &c_key, &c_ver, c_val_literal) != 3)
      panic("failed to parse trace");
    
    uint8_t *c_val = new uint8_t[kValSize]();
    
    for (int i = 0; i < kValSize; i++)
      sscanf(c_val_literal + 2*i, "%02hhx", &c_val[i]);

    trace_key[worker_id].push_back(c_key);
    trace_val[worker_id].push_back(c_val);
    trace_ver[worker_id].push_back(c_ver);
  }

  fin.close();
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

void ClientLoop(int worker_id, netaddr servaddr) {
  log_emerg("worker %d started", worker_id);

  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, 0}));
  if (unlikely(c == nullptr)) panic("couldn't open socket");

  uint32_t idx = 0;
  while (true) {
    if (idx == trace_key[worker_id].size()) idx = 0;

    message msg;
    msg.type = kCommit;
    msg.key = trace_key[worker_id][idx];
    memcpy(msg.val, trace_val[worker_id][idx], kValSize);
    msg.ver = trace_ver[worker_id][idx];

    NetHandshake(&msg, c.get(), servaddr, worker_id);
    assert(msg.type == PktType::kAck);
  }
}

void ClientHandler(void *arg) {
  for (int i = 0; i < threads; i++)
    GetTraces(i);

  log_emerg("finish getting traces");

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

} // anonymous namespace

int main(int argc, char *argv[]) {
  if (argc != 5) {
    std::cerr << "usage: [cfg_file] [machine_id]"
              << " [#threads] [debug/expr]"
              << std::endl;
    return -EINVAL;
  }

  machine_id = std::stoi(argv[2], nullptr, 0);
  threads = std::stoi(argv[3], nullptr, 0);
  mode = argv[4];

  trace_key.resize(threads);
  trace_val.resize(threads);
  trace_ver.resize(threads);

  lat_samples.resize(threads);
  pkt_cnt.resize(threads);

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
