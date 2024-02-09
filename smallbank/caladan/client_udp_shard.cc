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
#include <atomic>

namespace {

// machine id
int machine_id;

// number of worker threads per machine
int threads;

// run mode
std::string mode;

// interval for load control
uint64_t net_intv;

// server address
netaddr servaddr[3];

// workload generator array
std::vector<TxnType> workgen_arr;

// statistics
std::vector<std::vector<uint64_t>> lat_samples;
std::vector<uint64_t> txn_cnt, pkt_cnt, suc_txn_cnt, suc_pkt_cnt;
std::atomic<bool> stat_started {false};

// create workload generator array
void CreateWorkgenArr() {
  workgen_arr.reserve(100);
  workgen_arr.insert(workgen_arr.end(), kFreqAmalgamate, TxnType::kAmalgamate);
  workgen_arr.insert(workgen_arr.end(), kFreqBalance, TxnType::kBalance);
  workgen_arr.insert(workgen_arr.end(), kFreqDepositChecking, TxnType::kDepositChecking);
  workgen_arr.insert(workgen_arr.end(), kFreqSendPayment, TxnType::kSendPayment);
  workgen_arr.insert(workgen_arr.end(), kFreqTransactSaving, TxnType::kTransactSaving);
  workgen_arr.insert(workgen_arr.end(), kFreqWriteCheck, TxnType::kWriteCheck);
  assert(workgen_arr.size() == 100);
}

void CollectStat() {
#define CPU_MON_PORT 20231

  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, 0}));
  if (c == nullptr) panic("failed to create socket");

  struct cpu_mon_message {
    double ucores;
    double kcores;
  } msg;

  netaddr primaddr_mon = servaddr[0];
  primaddr_mon.port = CPU_MON_PORT;
  ssize_t ret = c->WriteTo(&msg, sizeof(msg), &primaddr_mon);
  if (ret != sizeof(msg)) panic("couldn't send message");

  ret = c->ReadFrom(&msg, sizeof(msg), NULL);
  if (ret != sizeof(msg)) panic("couldn't receive message");

  uint64_t total_txn = std::accumulate(txn_cnt.begin(), txn_cnt.end(), 0UL);
  uint64_t total_suc_txn = std::accumulate(suc_txn_cnt.begin(), suc_txn_cnt.end(), 0UL);

  std::vector<uint64_t> lat_aggr;
  for (int i = 0; i < threads; i++)
    lat_aggr.insert(lat_aggr.end(), lat_samples[i].begin(), lat_samples[i].end());
  uint64_t total_lat = std::accumulate(lat_aggr.begin(), lat_aggr.end(), 0UL);

  log_emerg("throughput: %lu", total_txn / (kStatsEndSec - kStatsStartSec));
  log_emerg("goodput: %lu", total_suc_txn / (kStatsEndSec - kStatsStartSec));
  log_emerg("average latency: %lu", total_lat / lat_aggr.size());
  log_emerg("median latency: %lu", Percentile(lat_aggr, 50));
  log_emerg("99th percentile latency: %lu", Percentile(lat_aggr, 99));
  log_emerg("99.9th percentile latency: %lu", Percentile(lat_aggr, 99.9));

  log_emerg("primary ucores: %lf", msg.ucores);
  log_emerg("primary kcores: %lf", msg.kcores);
}

// print throughput
void PrintTput(uint32_t poll_cnt) {
  log_emerg("%u throughput", poll_cnt);

  static uint64_t last_txn = 0;
  static uint64_t last_pkt = 0;
  static uint64_t last_suc_txn = 0;
  static uint64_t last_suc_pkt = 0;

  uint64_t total_txn = std::accumulate(txn_cnt.begin(), txn_cnt.end(), 0UL);
  uint64_t total_pkt = std::accumulate(pkt_cnt.begin(), pkt_cnt.end(), 0UL);
  uint64_t total_suc_txn = std::accumulate(suc_txn_cnt.begin(), suc_txn_cnt.end(), 0UL);
  uint64_t total_suc_pkt = std::accumulate(suc_pkt_cnt.begin(), suc_pkt_cnt.end(), 0UL);

  log_emerg("txn: %lu", total_txn - last_txn);
  log_emerg("pkt: %lu", total_pkt - last_pkt);
  log_emerg("suc_txn: %lu", total_suc_txn - last_suc_txn);
  log_emerg("suc_pkt: %lu", total_suc_pkt - last_suc_pkt);

  last_txn = total_txn;
  last_pkt = total_pkt;
  last_suc_txn = total_suc_txn;
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

void NetHandshake(message *msg, rt::UdpConn *c, netaddr raddr) {
  ssize_t ret = c->WriteTo(msg, sizeof(*msg), &raddr);
  if (ret != sizeof(*msg)) panic("couldn't send message");

  ret = c->ReadFrom(msg, sizeof(*msg), nullptr);
  if (ret != sizeof(*msg)) panic("couldn't receive message");
}

void NetSend(message *msg, rt::UdpConn *c, netaddr raddr) {
  ssize_t ret = c->WriteTo(msg, sizeof(*msg), &raddr);
  if (ret != sizeof(*msg)) panic("couldn't send message");
}

void NetRecv(message *msg, rt::UdpConn *c, netaddr *raddr) {
  ssize_t ret = c->ReadFrom(msg, sizeof(*msg), raddr);
  if (ret != sizeof(*msg)) panic("couldn't receive message");
}

// AMALGAMATE
bool TxnAmalgamate(int worker_id, uint64_t &txn_suc_pkt_cnt,
                   uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  uint64_t acct_id_0, acct_id_1;
  get_two_accounts(&tg_seed, &acct_id_0, &acct_id_1);

  // read from savings and checking tables for acct_id_0
  sb_sav_key_t sav_key_0;
  sav_key_0.acct_id = acct_id_0;

  sb_chk_key_t chk_key_0;
  chk_key_0.acct_id = acct_id_0;

  sb_chk_key_t chk_key_1;
  chk_key_1.acct_id = acct_id_1;

  message sav_msg_0, chk_msg_0, chk_msg_1;

  sav_msg_0.type = PktType::kAcquireExclusive;
  sav_msg_0.table = TableType::kSaving;
  sav_msg_0.key = *(uint64_t *)&sav_key_0;

  chk_msg_0.type = PktType::kAcquireExclusive;
  chk_msg_0.table = TableType::kChecking;
  chk_msg_0.key = *(uint64_t *)&chk_key_0;

  chk_msg_1.type = PktType::kAcquireExclusive;
  chk_msg_1.table = TableType::kChecking;
  chk_msg_1.key = *(uint64_t *)&chk_key_1;

  shard_msgs[sav_msg_0.key%3].push_back(&sav_msg_0);
  shard_msgs[chk_msg_0.key%3].push_back(&chk_msg_0);
  shard_msgs[chk_msg_1.key%3].push_back(&chk_msg_1);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantExclusive || msg.type == PktType::kRejectExclusive) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = PktType::kAcquireExclusive;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  if (sav_msg_0.type == PktType::kRejectExclusive || 
      chk_msg_0.type == PktType::kRejectExclusive ||
      chk_msg_1.type == PktType::kRejectExclusive) {
    // abort
    if (sav_msg_0.type == PktType::kGrantExclusive) {
      while (true) {
        sav_msg_0.type = PktType::kReleaseExclusive;
        NetHandshake(&sav_msg_0, conns[sav_msg_0.key%3], servaddr[sav_msg_0.key%3]);
        assert(sav_msg_0.key == *(uint64_t *)&sav_key_0);
        assert(sav_msg_0.table == TableType::kSaving);
        txn_suc_pkt_cnt++;
        if (sav_msg_0.type == PktType::kReleaseExclusiveAck) break;
        else assert(sav_msg_0.type == PktType::kRetry);
      }
    } else assert(sav_msg_0.type == PktType::kRejectExclusive);

    if (chk_msg_0.type == PktType::kGrantExclusive) {
      while (true) {
        chk_msg_0.type = PktType::kReleaseExclusive;
        NetHandshake(&chk_msg_0, conns[chk_msg_0.key%3], servaddr[chk_msg_0.key%3]);
        assert(chk_msg_0.key == *(uint64_t *)&chk_key_0);
        assert(chk_msg_0.table == TableType::kChecking);
        txn_suc_pkt_cnt++;
        if (chk_msg_0.type == PktType::kReleaseExclusiveAck) break;
        else assert(chk_msg_0.type == PktType::kRetry);
      }
    } else assert(chk_msg_0.type == PktType::kRejectExclusive);

    if (chk_msg_1.type == PktType::kGrantExclusive) {
      while (true) {
        chk_msg_1.type = PktType::kReleaseExclusive;
        NetHandshake(&chk_msg_1, conns[chk_msg_1.key%3], servaddr[chk_msg_1.key%3]);
        assert(chk_msg_1.key == *(uint64_t *)&chk_key_1);
        assert(chk_msg_1.table == TableType::kChecking);
        txn_suc_pkt_cnt++;
        if (chk_msg_1.type == PktType::kReleaseExclusiveAck) break;
        else assert(chk_msg_1.type == PktType::kRetry);
      }
    } else assert(chk_msg_1.type == PktType::kRejectExclusive);

    return false;
  } else assert(sav_msg_0.type == PktType::kGrantExclusive && 
                chk_msg_0.type == PktType::kGrantExclusive &&
                chk_msg_1.type == PktType::kGrantExclusive);

  // if we are here, execution succeeded and we have locks
  sb_sav_val_t *sav_val_0 = (sb_sav_val_t *)sav_msg_0.val;
  sb_chk_val_t *chk_val_0 = (sb_chk_val_t *)chk_msg_0.val;
  sb_chk_val_t *chk_val_1 = (sb_chk_val_t *)chk_msg_1.val;
  assert(sav_val_0->magic == sb_sav_magic);
  assert(chk_val_0->magic == sb_chk_magic);
  assert(chk_val_1->magic == sb_chk_magic);

  // increase acct_id_1's balance and set acct_id_0's balances to 0
  chk_val_1->bal += (sav_val_0->bal + chk_val_0->bal);
  sav_val_0->bal = 0;
  chk_val_0->bal = 0;

  // commit
  sav_msg_0.ver++;
  chk_msg_0.ver++;
  chk_msg_1.ver++;

  sav_msg_0.type = PktType::kCommitLog;
  chk_msg_0.type = PktType::kCommitLog;
  chk_msg_1.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto sav_msg_cpy = new message;
    memcpy(sav_msg_cpy, &sav_msg_0, sizeof(message));
    shard_msgs[i].push_back(sav_msg_cpy);

    auto chk_msg_cpy_0 = new message;
    memcpy(chk_msg_cpy_0, &chk_msg_0, sizeof(message));
    shard_msgs[i].push_back(chk_msg_cpy_0);

    auto chk_msg_cpy_1 = new message;
    memcpy(chk_msg_cpy_1, &chk_msg_1, sizeof(message));
    shard_msgs[i].push_back(chk_msg_cpy_1);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitLogAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  sav_msg_0.type = PktType::kCommitBck;
  chk_msg_0.type = PktType::kCommitBck;
  chk_msg_1.type = PktType::kCommitBck;

  shard_msgs[((sav_msg_0.key%3)+1)%3].push_back(&sav_msg_0);
  shard_msgs[((chk_msg_0.key%3)+1)%3].push_back(&chk_msg_0);
  shard_msgs[((chk_msg_1.key%3)+1)%3].push_back(&chk_msg_1);
  {
    auto sav_msg_cpy = new message;
    memcpy(sav_msg_cpy, &sav_msg_0, sizeof(message));
    auto chk_msg_cpy_0 = new message;
    memcpy(chk_msg_cpy_0, &chk_msg_0, sizeof(message));
    auto chk_msg_cpy_1 = new message;
    memcpy(chk_msg_cpy_1, &chk_msg_1, sizeof(message));

    shard_msgs[((sav_msg_0.key%3)+2)%3].push_back(sav_msg_cpy);
    shard_msgs[((chk_msg_0.key%3)+2)%3].push_back(chk_msg_cpy_0);
    shard_msgs[((chk_msg_1.key%3)+2)%3].push_back(chk_msg_cpy_1);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitBckAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  sav_msg_0.type = PktType::kCommitPrim;
  chk_msg_0.type = PktType::kCommitPrim;
  chk_msg_1.type = PktType::kCommitPrim;

  shard_msgs[sav_msg_0.key%3].push_back(&sav_msg_0);
  shard_msgs[chk_msg_0.key%3].push_back(&chk_msg_0);
  shard_msgs[chk_msg_1.key%3].push_back(&chk_msg_1);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitPrimAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  sav_msg_0.type = PktType::kReleaseExclusive;
  chk_msg_0.type = PktType::kReleaseExclusive;
  chk_msg_1.type = PktType::kReleaseExclusive;

  shard_msgs[sav_msg_0.key%3].push_back(&sav_msg_0);
  shard_msgs[chk_msg_0.key%3].push_back(&chk_msg_0);
  shard_msgs[chk_msg_1.key%3].push_back(&chk_msg_1);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kReleaseExclusiveAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = PktType::kReleaseExclusive;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  return true;
}

// BALANCE
bool TxnBalance(int worker_id, uint64_t &txn_suc_pkt_cnt,
                uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;

  uint64_t acct_id;
  get_account(&tg_seed, &acct_id);

  // read from savings and checking tables
  sb_sav_key_t sav_key;
  sav_key.acct_id = acct_id;

  sb_chk_key_t chk_key;
  chk_key.acct_id = acct_id;

  message sav_msg, chk_msg;

  sav_msg.type = PktType::kAcquireShared;
  sav_msg.table = TableType::kSaving;
  sav_msg.key = *(uint64_t *)&sav_key;

  chk_msg.type = PktType::kAcquireShared;
  chk_msg.table = TableType::kChecking;
  chk_msg.key = *(uint64_t *)&chk_key;

  shard_msgs[sav_msg.key%3].push_back(&sav_msg);
  shard_msgs[chk_msg.key%3].push_back(&chk_msg);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantShared || msg.type == PktType::kRejectShared) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = PktType::kAcquireShared;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  if (sav_msg.type == PktType::kRejectShared || chk_msg.type == PktType::kRejectShared) {
    // abort
    if (sav_msg.type == PktType::kGrantShared) {
      while (true) {
        sav_msg.type = PktType::kReleaseShared;
        NetHandshake(&sav_msg, conns[sav_msg.key%3], servaddr[sav_msg.key%3]);
        assert(sav_msg.key == *(uint64_t *)&sav_key);
        assert(sav_msg.table == TableType::kSaving);
        txn_suc_pkt_cnt++;
        if (sav_msg.type == PktType::kReleaseSharedAck) break;
        else assert(sav_msg.type == PktType::kRetry);
      }
    } else assert(sav_msg.type == PktType::kRejectShared);

    if (chk_msg.type == PktType::kGrantShared) {
      while (true) {
        chk_msg.type = PktType::kReleaseShared;
        NetHandshake(&chk_msg, conns[chk_msg.key%3], servaddr[chk_msg.key%3]);
        assert(chk_msg.key == *(uint64_t *)&chk_key);
        assert(chk_msg.table == TableType::kChecking);
        txn_suc_pkt_cnt++;
        if (chk_msg.type == PktType::kReleaseSharedAck) break;
        else assert(chk_msg.type == PktType::kRetry);
      }
    } else assert(chk_msg.type == PktType::kRejectShared);

    return false;
  } else assert(sav_msg.type == PktType::kGrantShared && chk_msg.type == PktType::kGrantShared);

  sb_sav_val_t *sav_val = (sb_sav_val_t *)sav_msg.val; _unused(sav_val);
  sb_chk_val_t *chk_val = (sb_chk_val_t *)chk_msg.val; _unused(chk_val);
  assert(sav_val->magic == sb_sav_magic);
  assert(chk_val->magic == sb_chk_magic);

  // release locks
  sav_msg.type = PktType::kReleaseShared;
  chk_msg.type = PktType::kReleaseShared;
 
  shard_msgs[sav_msg.key%3].push_back(&sav_msg);
  shard_msgs[chk_msg.key%3].push_back(&chk_msg);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kReleaseSharedAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = PktType::kReleaseShared;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  return true;
}

// DEPOSIT_CHECKING
bool TxnDepositChecking(int worker_id, uint64_t &txn_suc_pkt_cnt,
                        uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  uint64_t acct_id;
  get_account(&tg_seed, &acct_id);
  float amount = 1.3;

  // Read from checking table
  sb_chk_key_t chk_key;
  chk_key.acct_id = acct_id;

  message chk_msg;
  chk_msg.table = TableType::kChecking;
  chk_msg.key = *(uint64_t *)&chk_key;

  while (true) {
    chk_msg.type = PktType::kAcquireExclusive;
    NetHandshake(&chk_msg, conns[chk_msg.key%3], servaddr[chk_msg.key%3]);
    assert(chk_msg.key == *(uint64_t *)&chk_key);
    assert(chk_msg.table == TableType::kChecking);
    txn_suc_pkt_cnt++;
    if (chk_msg.type == PktType::kGrantExclusive || 
        chk_msg.type == PktType::kRejectExclusive) break;
    else assert(chk_msg.type == PktType::kRetry);
  }

  if (chk_msg.type == PktType::kRejectExclusive) return false;

  // if we are here, execution succeeded and we have a lock
  sb_chk_val_t *chk_val = (sb_chk_val_t *)chk_msg.val;
  assert(chk_val->magic == sb_chk_magic);

  chk_val->bal += amount;	// update checking balance

  // commit
  chk_msg.ver++;
  chk_msg.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto chk_msg_cpy = new message;
    memcpy(chk_msg_cpy, &chk_msg, sizeof(message));
    shard_msgs[i].push_back(chk_msg_cpy);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitLogAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  chk_msg.type = PktType::kCommitBck;

  shard_msgs[((chk_msg.key%3)+1)%3].push_back(&chk_msg);
  {
    auto chk_msg_cpy = new message;
    memcpy(chk_msg_cpy, &chk_msg, sizeof(message));
    shard_msgs[((chk_msg.key%3)+2)%3].push_back(chk_msg_cpy);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitBckAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();

  chk_msg.type = PktType::kCommitPrim;
  NetHandshake(&chk_msg, conns[chk_msg.key%3], servaddr[chk_msg.key%3]);
  assert(chk_msg.key == *(uint64_t *)&chk_key);
  assert(chk_msg.table == TableType::kChecking);
  assert(chk_msg.type == PktType::kCommitPrimAck);
  txn_suc_pkt_cnt++;

  // release locks
  while (true) {
    chk_msg.type = PktType::kReleaseExclusive;
    NetHandshake(&chk_msg, conns[chk_msg.key%3], servaddr[chk_msg.key%3]);
    assert(chk_msg.key == *(uint64_t *)&chk_key);
    assert(chk_msg.table == TableType::kChecking);
    txn_suc_pkt_cnt++;
    if (chk_msg.type == PktType::kReleaseExclusiveAck) break;
    else assert(chk_msg.type == PktType::kRetry);
  }
  return true;
}

// SEND_PAYMENT
bool TxnSendPayment(int worker_id, uint64_t &txn_suc_pkt_cnt,
                    uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  uint64_t acct_id_0, acct_id_1;
  get_two_accounts(&tg_seed, &acct_id_0, &acct_id_1);
  float amount = 5.0;

  // read from checking table
  sb_chk_key_t chk_key_0, chk_key_1;
  chk_key_0.acct_id = acct_id_0;
  chk_key_1.acct_id = acct_id_1;

  message chk_msg_0, chk_msg_1;

  chk_msg_0.type = PktType::kAcquireExclusive;
  chk_msg_0.table = TableType::kChecking;
  chk_msg_0.key = *(uint64_t *)&chk_key_0;

  chk_msg_1.type = PktType::kAcquireExclusive;
  chk_msg_1.table = TableType::kChecking;
  chk_msg_1.key = *(uint64_t *)&chk_key_1;

  shard_msgs[chk_msg_0.key%3].push_back(&chk_msg_0);
  shard_msgs[chk_msg_1.key%3].push_back(&chk_msg_1);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantExclusive || msg.type == PktType::kRejectExclusive) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = PktType::kAcquireExclusive;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  if (chk_msg_0.type == PktType::kRejectExclusive || chk_msg_1.type == PktType::kRejectExclusive) {
    // abort
    if (chk_msg_0.type == PktType::kGrantExclusive) {
      while (true) {
        chk_msg_0.type = PktType::kReleaseExclusive;
        NetHandshake(&chk_msg_0, conns[chk_msg_0.key%3], servaddr[chk_msg_0.key%3]);
        txn_suc_pkt_cnt++;
        if (chk_msg_0.type == PktType::kReleaseExclusiveAck) break;
        else assert(chk_msg_0.type == PktType::kRetry);
      }
    } else assert(chk_msg_0.type == PktType::kRejectExclusive);

    if (chk_msg_1.type == PktType::kGrantExclusive) {
      while (true) {
        chk_msg_1.type = PktType::kReleaseExclusive;
        NetHandshake(&chk_msg_1, conns[chk_msg_1.key%3], servaddr[chk_msg_1.key%3]);
        txn_suc_pkt_cnt++;
        if (chk_msg_1.type == PktType::kReleaseExclusiveAck) break;
        else assert(chk_msg_1.type == PktType::kRetry);
      }
    } else assert(chk_msg_1.type == PktType::kRejectExclusive);

    return false;
  } else assert(chk_msg_0.type == PktType::kGrantExclusive && chk_msg_1.type == PktType::kGrantExclusive);

  // if we are here, execution succeeded and we have locks
  sb_chk_val_t *chk_val_0 = (sb_chk_val_t *)chk_msg_0.val;
  sb_chk_val_t *chk_val_1 = (sb_chk_val_t *)chk_msg_1.val;
  assert(chk_val_0->magic == sb_chk_magic);
  assert(chk_val_1->magic == sb_chk_magic);

  if (chk_val_0->bal < amount) {
    // abort
    while (true) {
      chk_msg_0.type = PktType::kReleaseExclusive;
      NetHandshake(&chk_msg_0, conns[chk_msg_0.key%3], servaddr[chk_msg_0.key%3]);
      assert(chk_msg_0.key == *(uint64_t *)&chk_key_0);
      assert(chk_msg_0.table == TableType::kChecking);
      txn_suc_pkt_cnt++;
      if (chk_msg_0.type == PktType::kReleaseExclusiveAck) break;
      else assert(chk_msg_0.type == PktType::kRetry);
    }
    while (true) {
      chk_msg_1.type = PktType::kReleaseExclusive;
      NetHandshake(&chk_msg_1, conns[chk_msg_1.key%3], servaddr[chk_msg_1.key%3]);
      assert(chk_msg_1.key == *(uint64_t *)&chk_key_1);
      assert(chk_msg_1.table == TableType::kChecking);
      txn_suc_pkt_cnt++;
      if (chk_msg_1.type == PktType::kReleaseExclusiveAck) break;
      else assert(chk_msg_1.type == PktType::kRetry);
    }
    return false;
  }

  chk_val_0->bal -= amount;
  chk_val_1->bal += amount;

  // commit
  chk_msg_0.ver++;
  chk_msg_1.ver++;

  chk_msg_0.type = PktType::kCommitLog;
  chk_msg_1.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto chk_msg_cpy_0 = new message;
    memcpy(chk_msg_cpy_0, &chk_msg_0, sizeof(message));
    shard_msgs[i].push_back(chk_msg_cpy_0);

    auto chk_msg_cpy_1 = new message;
    memcpy(chk_msg_cpy_1, &chk_msg_1, sizeof(message));
    shard_msgs[i].push_back(chk_msg_cpy_1);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitLogAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  chk_msg_0.type = PktType::kCommitBck;
  chk_msg_1.type = PktType::kCommitBck;

  shard_msgs[((chk_msg_0.key%3)+1)%3].push_back(&chk_msg_0);
  shard_msgs[((chk_msg_1.key%3)+1)%3].push_back(&chk_msg_1);
  {
    auto chk_msg_cpy_0 = new message;
    memcpy(chk_msg_cpy_0, &chk_msg_0, sizeof(message));
    auto chk_msg_cpy_1 = new message;
    memcpy(chk_msg_cpy_1, &chk_msg_1, sizeof(message));

    shard_msgs[((chk_msg_0.key%3)+2)%3].push_back(chk_msg_cpy_0);
    shard_msgs[((chk_msg_1.key%3)+2)%3].push_back(chk_msg_cpy_1);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitBckAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  chk_msg_0.type = PktType::kCommitPrim;
  chk_msg_1.type = PktType::kCommitPrim;

  shard_msgs[chk_msg_0.key%3].push_back(&chk_msg_0);
  shard_msgs[chk_msg_1.key%3].push_back(&chk_msg_1);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitPrimAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  chk_msg_0.type = PktType::kReleaseExclusive;
  chk_msg_1.type = PktType::kReleaseExclusive;

  // release locks
  shard_msgs[chk_msg_0.key%3].push_back(&chk_msg_0);
  shard_msgs[chk_msg_1.key%3].push_back(&chk_msg_1);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kReleaseExclusiveAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = PktType::kReleaseExclusive;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  return true;
}

// TRANSACT_SAVING
bool TxnTransactSaving(int worker_id, uint64_t &txn_suc_pkt_cnt,
                       uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  uint64_t acct_id;
  get_account(&tg_seed, &acct_id);
  float amount = 20.20;

  // read from saving table
  sb_sav_key_t sav_key;
  sav_key.acct_id = acct_id;

  message sav_msg;
  sav_msg.table = TableType::kSaving;
  sav_msg.key = *(uint64_t *)&sav_key;

  while (true) {
    sav_msg.type = PktType::kAcquireExclusive;
    NetHandshake(&sav_msg, conns[sav_msg.key%3], servaddr[sav_msg.key%3]);
    assert(sav_msg.key == *(uint64_t *)&sav_key);
    assert(sav_msg.table == TableType::kSaving);
    txn_suc_pkt_cnt++;
    if (sav_msg.type == PktType::kGrantExclusive || 
        sav_msg.type == PktType::kRejectExclusive) break;
    else assert(sav_msg.type == PktType::kRetry);
  }

  if (sav_msg.type == PktType::kRejectExclusive) return false;

  // if we are here, execution succeeded and we have a lock
  sb_sav_val_t *sav_val = (sb_sav_val_t *)sav_msg.val;
  assert(sav_val->magic == sb_sav_magic);

  sav_val->bal += amount;	// update saving balance

  // commit
  sav_msg.ver++;
  sav_msg.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto sav_msg_cpy = new message;
    memcpy(sav_msg_cpy, &sav_msg, sizeof(message));
    shard_msgs[i].push_back(sav_msg_cpy);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitLogAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  sav_msg.type = PktType::kCommitBck;

  shard_msgs[((sav_msg.key%3)+1)%3].push_back(&sav_msg);
  {
    auto sav_msg_cpy = new message;
    memcpy(sav_msg_cpy, &sav_msg, sizeof(message));
    shard_msgs[((sav_msg.key%3)+2)%3].push_back(sav_msg_cpy);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitBckAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();

  sav_msg.type = PktType::kCommitPrim;
  NetHandshake(&sav_msg, conns[sav_msg.key%3], servaddr[sav_msg.key%3]);
  assert(sav_msg.key == *(uint64_t *)&sav_key);
  assert(sav_msg.table == TableType::kSaving);
  assert(sav_msg.type == PktType::kCommitPrimAck);
  txn_suc_pkt_cnt++;

  // release locks
  while (true) {
    sav_msg.type = PktType::kReleaseExclusive;
    NetHandshake(&sav_msg, conns[sav_msg.key%3], servaddr[sav_msg.key%3]);
    assert(sav_msg.key == *(uint64_t *)&sav_key);
    assert(sav_msg.table == TableType::kSaving);
    txn_suc_pkt_cnt++;
    if (sav_msg.type == PktType::kReleaseExclusiveAck) break;
    else assert(sav_msg.type == PktType::kRetry);
  }
  return true;
}

// WRITE_CHECK
bool TxnWriteCheck(int worker_id, uint64_t &txn_suc_pkt_cnt,
                   uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  uint64_t acct_id;
  get_account(&tg_seed, &acct_id);
  float amount = 5.0;

  // read from savings, read checking record for update
  sb_sav_key_t sav_key;
  sav_key.acct_id = acct_id;

  sb_chk_key_t chk_key;
  chk_key.acct_id = acct_id;

  message sav_msg, chk_msg;

  sav_msg.type = PktType::kAcquireShared;
  sav_msg.table = TableType::kSaving;
  sav_msg.key = *(uint64_t *)&sav_key;

  chk_msg.type = PktType::kAcquireExclusive;
  chk_msg.table = TableType::kChecking;
  chk_msg.key = *(uint64_t *)&chk_key;

  shard_msgs[sav_msg.key%3].push_back(&sav_msg);
  shard_msgs[chk_msg.key%3].push_back(&chk_msg);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          auto prev_type = shard_msgs[i][msg.ord]->type;
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantShared || msg.type == PktType::kRejectShared ||
              msg.type == PktType::kGrantExclusive || msg.type == PktType::kRejectExclusive) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = prev_type;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  if (sav_msg.type == PktType::kRejectShared || chk_msg.type == PktType::kRejectExclusive) {
    // abort
    if (sav_msg.type == PktType::kGrantShared) {
      while (true) {
        sav_msg.type = PktType::kReleaseShared;
        NetHandshake(&sav_msg, conns[sav_msg.key%3], servaddr[sav_msg.key%3]);
        txn_suc_pkt_cnt++;
        if (sav_msg.type == PktType::kReleaseSharedAck) break;
        else assert(sav_msg.type == PktType::kRetry);
      }
    } else assert(sav_msg.type == PktType::kRejectShared);

    if (chk_msg.type == PktType::kGrantExclusive) {
      while (true) {
        chk_msg.type = PktType::kReleaseExclusive;
        NetHandshake(&chk_msg, conns[chk_msg.key%3], servaddr[chk_msg.key%3]);
        txn_suc_pkt_cnt++;
        if (chk_msg.type == PktType::kReleaseExclusiveAck) break;
        else assert(chk_msg.type == PktType::kRetry);
      }
    } else assert(chk_msg.type == PktType::kRejectExclusive);

    return false;
  } else assert(sav_msg.type == PktType::kGrantShared && chk_msg.type == PktType::kGrantExclusive);

  sb_sav_val_t *sav_val = (sb_sav_val_t *)sav_msg.val;
  sb_chk_val_t *chk_val = (sb_chk_val_t *)chk_msg.val;
  assert(sav_val->magic == sb_sav_magic);
  assert(chk_val->magic == sb_chk_magic);

  if (sav_val->bal + chk_val->bal < amount) chk_val->bal -= (amount + 1);
  else chk_val->bal -= amount;

  // commit
  chk_msg.ver++;
  chk_msg.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto chk_msg_cpy = new message;
    memcpy(chk_msg_cpy, &chk_msg, sizeof(message));
    shard_msgs[i].push_back(chk_msg_cpy);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitLogAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  chk_msg.type = PktType::kCommitBck;

  shard_msgs[((chk_msg.key%3)+1)%3].push_back(&chk_msg);
  {
    auto chk_msg_cpy = new message;
    memcpy(chk_msg_cpy, &chk_msg, sizeof(message));
    shard_msgs[((chk_msg.key%3)+2)%3].push_back(chk_msg_cpy);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kCommitBckAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  chk_msg.type = PktType::kCommitPrim;
  NetHandshake(&chk_msg, conns[chk_msg.key%3], servaddr[chk_msg.key%3]);
  assert(chk_msg.key == *(uint64_t *)&chk_key);
  assert(chk_msg.table == TableType::kChecking);
  assert(chk_msg.type == PktType::kCommitPrimAck);
  txn_suc_pkt_cnt++;

  sav_msg.type = PktType::kReleaseShared;
  chk_msg.type = PktType::kReleaseExclusive;

  // release locks
  shard_msgs[sav_msg.key%3].push_back(&sav_msg);
  shard_msgs[chk_msg.key%3].push_back(&chk_msg);

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      while (!shard_msgs[i].empty()) {
        int size = shard_msgs[i].size();
        std::vector<bool> done(size, false);
        for (int j = 0; j < size; ++j) {
          auto msg = shard_msgs[i][j];
          msg->ord = j;
          NetSend(msg, conns[i], servaddr[i]);
        }

        for (int j = 0; j < size; ++j) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          auto prev_type = shard_msgs[i][msg.ord]->type;
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(message));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kReleaseExclusiveAck || msg.type == PktType::kReleaseSharedAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRetry);
            shard_msgs[i][msg.ord]->type = prev_type;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  return true;
}

// main client thread
void ClientLoop(int wrkr_gid) {
  int wrkr_lid = wrkr_gid % threads;
  uint64_t tg_seed = 0xdeadbeef + wrkr_gid;
  log_emerg("worker %d started", wrkr_lid);

  std::vector<rt::UdpConn *> conns;
  std::unique_ptr<rt::UdpConn> c_shard_0(rt::UdpConn::Listen({0, 0}));
  std::unique_ptr<rt::UdpConn> c_shard_1(rt::UdpConn::Listen({0, 0}));
  std::unique_ptr<rt::UdpConn> c_shard_2(rt::UdpConn::Listen({0, 0}));
  if (c_shard_0 == nullptr || c_shard_1 == nullptr || c_shard_2 == nullptr) 
    panic("failed to create socket");

  conns.push_back(c_shard_0.release());
  conns.push_back(c_shard_1.release());
  conns.push_back(c_shard_2.release());

  uint64_t cur_time = microtime();

  while (true) {
    if (net_intv > 0) {
      rt::SleepUntil(cur_time + net_intv);
      cur_time += net_intv;
    }

    auto txn_type = workgen_arr[fastrand(&tg_seed) % 100];

    bool txn_committed = false;
    uint64_t txn_suc_pkt_cnt = 0;
    uint64_t begin = microtime();
    switch (txn_type) {
      case TxnType::kAmalgamate:
        txn_committed = TxnAmalgamate(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kBalance:
        txn_committed = TxnBalance(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kDepositChecking:
        txn_committed = TxnDepositChecking(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kSendPayment:
        txn_committed = TxnSendPayment(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kTransactSaving:
        txn_committed = TxnTransactSaving(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kWriteCheck:
        txn_committed = TxnWriteCheck(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      default:
        panic("unknown transaction type %d", static_cast<int>(txn_type));
    }
    uint64_t lat = microtime() - begin;
    if (stat_started) {
      txn_cnt[wrkr_lid]++;
      pkt_cnt[wrkr_lid] += txn_suc_pkt_cnt;
      if (txn_committed) {
        suc_txn_cnt[wrkr_lid]++;
        suc_pkt_cnt[wrkr_lid] += txn_suc_pkt_cnt;
        lat_samples[wrkr_lid].push_back(lat);
      }
    }
  }
}

void ClientHandler(void *arg) {
  std::vector<rt::Thread> th;
  for (int i = 0; i < threads; i++) {
    auto wrkr_gid = machine_id * threads + i;
    th.emplace_back(rt::Thread([&, wrkr_gid]{
      ClientLoop(wrkr_gid);
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

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 7) {
    std::cerr << "usage: [cfg_file] [machine_id] [#clients] [#threads] [target_load] [debug/expr]" << std::endl;
    return -EINVAL;
  }

  machine_id = std::stoi(argv[2], nullptr, 0);
  threads = std::stoi(argv[4], nullptr, 0);
  mode = argv[6];

  uint64_t machine_num = std::stoul(argv[3], nullptr, 0);
  uint64_t target_load = std::stoul(argv[5], nullptr, 0);
  
  if (target_load == 0) net_intv = 0;
  else net_intv = machine_num * threads * 1000000UL / target_load;

  CreateWorkgenArr();

  txn_cnt.resize(threads, 0);
  suc_txn_cnt.resize(threads, 0);
  pkt_cnt.resize(threads, 0);
  suc_pkt_cnt.resize(threads, 0);
  lat_samples.resize(threads);

  int ret;

  for (int i = 0; i < 3; ++i) {
    ret = StringToAddr(ip_list[i], &servaddr[i].ip);
    if (ret) return -EINVAL;
    servaddr[i].port = kFasstPort;
  }

  log_emerg("finish initialization");

  ret = runtime_init(argv[1], ClientHandler, NULL);
  if (ret) {
    printf("failed to start client runtime\n");
    return ret;
  }

  return 0;
}