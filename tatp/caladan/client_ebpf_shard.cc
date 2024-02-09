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

// map 0-999 to 12b, 4b/digit decimal representation
uint16_t *map_1000;

namespace {

constexpr int kStatsStartSec = 5;
constexpr int kStatsEndSec = 15;
constexpr int kExitSec = 20;

// machine id
int machine_id;

// number of client machines
int machine_num;

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
  workgen_arr.insert(workgen_arr.end(), kFreqGetSubscriberData, TxnType::kGetSubscriberData);
  workgen_arr.insert(workgen_arr.end(), kFreqGetAccessData, TxnType::kGetAccessData);
  workgen_arr.insert(workgen_arr.end(), kFreqGetNewDestination, TxnType::kGetNewDestination);
  workgen_arr.insert(workgen_arr.end(), kFreqUpdateSubscriberData, TxnType::kUpdateSubscriberData);
  workgen_arr.insert(workgen_arr.end(), kFreqUpdateLocation, TxnType::kUpdateLocation);
  workgen_arr.insert(workgen_arr.end(), kFreqInsertCallForwarding, TxnType::kInsertCallForwarding);
  workgen_arr.insert(workgen_arr.end(), kFreqDeleteCallForwarding, TxnType::kDeleteCallForwarding);
  assert(workgen_arr.size() == 100);
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

void PopulateThread(int wid) {
  uint64_t tmp_seed = 0xdeadbeef;

  uint32_t kSliceSize = kSubscriberNum / threads;
  uint32_t l_sid = wid * kSliceSize;
  uint32_t r_sid = (wid == threads - 1) ? kSubscriberNum : (wid + 1) * kSliceSize;

  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, 0}));
  if (c == nullptr) panic("failed to create socket");

  message msg;

  // populate subscriber table
  for (uint32_t s_id = l_sid; s_id < r_sid; s_id++) {
    tatp_sub_key_t key;
    key.s_id = s_id;
    
    // initialize the subscriber payload
    tatp_sub_val_t sub_val;
    sub_val.sub_nbr = tatp_sid_to_sub_nbr(s_id);

    for (int i = 0; i < 5; i++)
      sub_val.hex[i] = fastrand(&tmp_seed);

    for (int i = 0; i < 10; i++)
      sub_val.bytes[i] = fastrand(&tmp_seed);

    sub_val.bits = fastrand(&tmp_seed);
    sub_val.msc_location = tatp_sub_msc_location_magic;
    sub_val.vlr_location = fastrand(&tmp_seed);

    msg.key = *(uint64_t *)&key;
    memset(msg.val, 0, sizeof(msg.val));
    memcpy(msg.val, &sub_val, sizeof(sub_val));
    msg.table = TableType::kSubscriber;

    while (true) {
      msg.type = PktType::kInsertPrim;
      NetHandshake(&msg, c.get(), servaddr[msg.key%3]);
      if (msg.type == PktType::kInsertPrimAck) break;
      else assert(msg.type == PktType::kRejectCommit);
    }

    while (true) {
      msg.type = PktType::kInsertBck;
      NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+1)%3]);
      if (msg.type == PktType::kInsertBckAck) break;
      else assert(msg.type == PktType::kRejectCommit);
    }

    while (true) {
      msg.type = PktType::kInsertBck;
      NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+2)%3]);
      if (msg.type == PktType::kInsertBckAck) break;
      else assert(msg.type == PktType::kRejectCommit);
    }
  }

  log_emerg("worker %d populate subscriber table done", wid);

  // populate secondary subscriber table
  for (uint32_t s_id = l_sid; s_id < r_sid; s_id++) {
    tatp_sec_sub_key_t key;
    key.sub_nbr = tatp_sid_to_sub_nbr(s_id);
    
    // initialize the subscriber payload
    tatp_sec_sub_val_t sec_sub_val;
    sec_sub_val.s_id = s_id;
    sec_sub_val.magic = tatp_sec_sub_magic;

    msg.key = *(uint64_t *)&key;
    memset(msg.val, 0, sizeof(msg.val));
    memcpy(msg.val, &sec_sub_val, sizeof(sec_sub_val));
    msg.table = TableType::kSecondSubscriber;

    while (true) {
      msg.type = PktType::kInsertPrim;
      NetHandshake(&msg, c.get(), servaddr[msg.key%3]);
      if (msg.type == PktType::kInsertPrimAck) break;
      else assert(msg.type == PktType::kRejectCommit);
    }

    while (true) {
      msg.type = PktType::kInsertBck;
      NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+1)%3]);
      if (msg.type == PktType::kInsertBckAck) break;
      else assert(msg.type == PktType::kRejectCommit);
    }

    while (true) {
      msg.type = PktType::kInsertBck;
      NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+2)%3]);
      if (msg.type == PktType::kInsertBckAck) break;
      else assert(msg.type == PktType::kRejectCommit);
    }
  }

  log_emerg("worker %d populate secondary subscriber table done", wid);

  // populate access_info table
  std::vector<uint8_t> ai_type_values = {1, 2, 3, 4};

  for (uint32_t s_id = l_sid; s_id < r_sid; s_id++) {
    std::vector<uint8_t> ai_type_vec = select_between_n_and_m_from(
      tmp_seed, ai_type_values, 1, 4);

    for (uint8_t &ai_type : ai_type_vec) {
      // insert access info record
      tatp_accinf_key_t key;
      key.s_id = s_id;
      key.ai_type = ai_type;
      
      tatp_accinf_val_t accinf_val;
      accinf_val.data1 = tatp_accinf_data1_magic;

      // pad the value
      msg.key = *(uint64_t *)&key;
      memset(msg.val, 0, sizeof(msg.val));
      memcpy(msg.val, &accinf_val, sizeof(accinf_val));
      msg.table = TableType::kAccessInfo;

      while (true) {
        msg.type = PktType::kInsertPrim;
        NetHandshake(&msg, c.get(), servaddr[msg.key%3]);
        if (msg.type == PktType::kInsertPrimAck) break;
        else assert(msg.type == PktType::kRejectCommit);
      }

      while (true) {
        msg.type = PktType::kInsertBck;
        NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+1)%3]);
        if (msg.type == PktType::kInsertBckAck) break;
        else assert(msg.type == PktType::kRejectCommit);
      }

      while (true) {
        msg.type = PktType::kInsertBck;
        NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+2)%3]);
        if (msg.type == PktType::kInsertBckAck) break;
        else assert(msg.type == PktType::kRejectCommit);
      }
    }
  }

  log_emerg("worker %d populate access_info table done", wid);

  // populate special_facility table and call_forwarding table
  std::vector<uint8_t> sf_type_values = {1, 2, 3, 4};
  std::vector<uint8_t> start_time_values = {0, 8, 16};

  for (uint32_t s_id = l_sid; s_id < r_sid; s_id++) {
    std::vector<uint8_t> sf_type_vec = select_between_n_and_m_from(
      tmp_seed, sf_type_values, 1, 4);

    for (uint8_t &sf_type : sf_type_vec) {
      // insert the special facility record
      tatp_specfac_key_t key;
      key.s_id = s_id;
      key.sf_type = sf_type;
      
      tatp_specfac_val_t specfac_val;
      specfac_val.data_b[0] = tatp_specfac_data_b0_magic;
      specfac_val.is_active = (fastrand(&tmp_seed) % 100 < 85) ? 1 : 0;

      msg.key = *(uint64_t *)&key;
      memset(msg.val, 0, sizeof(msg.val));
      memcpy(msg.val, &specfac_val, sizeof(specfac_val));
      msg.table = TableType::kSpecialFacility;

      while (true) {
        msg.type = PktType::kInsertPrim;
        NetHandshake(&msg, c.get(), servaddr[msg.key%3]);
        if (msg.type == PktType::kInsertPrimAck) break;
        else assert(msg.type == PktType::kRejectCommit);
      }

      while (true) {
        msg.type = PktType::kInsertBck;
        NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+1)%3]);
        if (msg.type == PktType::kInsertBckAck) break;
        else assert(msg.type == PktType::kRejectCommit);
      }

      while (true) {
        msg.type = PktType::kInsertBck;
        NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+2)%3]);
        if (msg.type == PktType::kInsertBckAck) break;
        else assert(msg.type == PktType::kRejectCommit);
      }

      /*
       * The TATP spec requires a different initial probability
       * distribution of Call Forwarding records (see README). Here, we
       * populate the table using the steady state distribution.
       */
      for (size_t start_time = 0; start_time <= 16; start_time += 8) {
        /*
         * At steady state, each @start_time for <s_id, sf_type> is
         * equally likely to be present or absent.
         */
        if (fastrand(&tmp_seed) % 2 == 0) continue;

        // insert the call forwarding record
        tatp_callfwd_key_t key;
        key.s_id = s_id;
        key.sf_type = sf_type;
        key.start_time = start_time;
        
        tatp_callfwd_val_t callfwd_val;
        callfwd_val.numberx[0] = tatp_callfwd_numberx0_magic;
        /* At steady state, @end_time is unrelated to @start_time */
        callfwd_val.end_time = (fastrand(&tmp_seed) % 24) + 1;

        msg.key = *(uint64_t *)&key;
        memset(msg.val, 0, sizeof(msg.val));
        memcpy(msg.val, &callfwd_val, sizeof(callfwd_val));
        msg.table = TableType::kCallForwarding;

        while (true) {
          msg.type = PktType::kInsertPrim;
          NetHandshake(&msg, c.get(), servaddr[msg.key%3]);
          if (msg.type == PktType::kInsertPrimAck) break;
          else assert(msg.type == PktType::kRejectCommit);
        }

        while (true) {
          msg.type = PktType::kInsertBck;
          NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+1)%3]);
          if (msg.type == PktType::kInsertBckAck) break;
          else assert(msg.type == PktType::kRejectCommit);
        }

        while (true) {
          msg.type = PktType::kInsertBck;
          NetHandshake(&msg, c.get(), servaddr[((msg.key%3)+2)%3]);
          if (msg.type == PktType::kInsertBckAck) break;
          else assert(msg.type == PktType::kRejectCommit);
        }
      }	// loop start_time
    }	// loop sf_type
  }	// loop s_id

  log_emerg("worker %d populate special_facility table and call_forwarding table done", wid);
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

// GET_SUBSCRIBER_DATA
bool TxnGetSubscriberData(int worker_id, uint64_t &txn_suc_pkt_cnt,
                          uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  tatp_sub_key_t key;
  key.s_id = tatp_nurand(&tg_seed);

  message msg;
  msg.table = TableType::kSubscriber;
  msg.key = *(uint64_t *)&key;

  while (true) {
    msg.type = PktType::kRead;
    NetHandshake(&msg, conns[msg.key%3], servaddr[msg.key%3]);
    assert(msg.key == *(uint64_t *)&key);
    assert(msg.table == TableType::kSubscriber);
    txn_suc_pkt_cnt++;
    if (msg.type == PktType::kGrantRead) break;
    else assert(msg.type == PktType::kRejectRead);
  }

  tatp_sub_val_t *val = (tatp_sub_val_t *)&msg.val; _unused(val);
  assert(val->msc_location == tatp_sub_msc_location_magic);

  // no need to commit, since there's no write
  return true;
}

// GET_NEW_DESTINATION
bool TxnGetNewDestination(int worker_id, uint64_t &txn_suc_pkt_cnt,
                          uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  // transaction parameters
  uint32_t s_id = tatp_nurand(&tg_seed);
  uint8_t sf_type = (fastrand(&tg_seed) % 4) + 1;
  uint8_t start_time = (fastrand(&tg_seed) % 3) * 8;
  uint8_t end_time = (fastrand(&tg_seed) % 24) * 1;

  unsigned cf_to_fetch = (start_time / 8) + 1;
  assert(cf_to_fetch >= 1 && cf_to_fetch <= 3);

  // fetch a single special facility record
  tatp_specfac_key_t specfac_key;

  specfac_key.s_id = s_id;
  specfac_key.sf_type = sf_type;

  message specfac_msg;
  specfac_msg.table = TableType::kSpecialFacility;
  specfac_msg.key = *(uint64_t *)&specfac_key;

  while (true) {
    specfac_msg.type = PktType::kRead;
    NetHandshake(&specfac_msg, conns[specfac_msg.key%3], servaddr[specfac_msg.key%3]);
    assert(specfac_msg.key == *(uint64_t *)&specfac_key);
    assert(specfac_msg.table == TableType::kSpecialFacility);
    txn_suc_pkt_cnt++;
    if (specfac_msg.type == PktType::kGrantRead || specfac_msg.type == PktType::kNotExist) break;
    else assert(specfac_msg.type == PktType::kRejectRead);
  }

  /*
   * The Special Facility record exists only 62.5% of the time, and is_active
   * 85% of the time. So avoid issuing the Call Forwarding fetches if we
   * have a non-existent or inactive Special Facility record.
   */
  if (specfac_msg.type == PktType::kNotExist) return false;

  // if we are here, the special facility record exists
  tatp_specfac_val_t *specfac_val = (tatp_specfac_val_t *)&specfac_msg.val;
  assert(specfac_val->data_b[0] == tatp_specfac_data_b0_magic);
  if (specfac_val->is_active == 0) return false;

  /* Fetch possibly multiple call forwarding records. */
  tatp_callfwd_key_t callfwd_key[3];
  message callfwd_msg[3];

  for (unsigned i = 0; i < cf_to_fetch; i++) {
    callfwd_key[i].s_id = s_id;
    callfwd_key[i].sf_type = sf_type;
    callfwd_key[i].start_time = (i * 8);

    callfwd_msg[i].type = PktType::kRead;
    callfwd_msg[i].table = TableType::kCallForwarding;
    callfwd_msg[i].key = *(uint64_t *)&callfwd_key[i];
  }

  for (unsigned i = 0; i < cf_to_fetch; i++)
    shard_msgs[callfwd_msg[i].key%3].push_back(&callfwd_msg[i]);

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

        for (int j = 0; j < size; j++) {
          message msg;
          NetRecv(&msg, conns[i], nullptr);
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantRead || msg.type == PktType::kNotExist) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectRead);
            shard_msgs[i][msg.ord]->type = PktType::kRead;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();

  bool callfwd_success = false;
  for (unsigned i = 0; i < cf_to_fetch; i++) {
    if (callfwd_msg[i].type == PktType::kNotExist) continue;

    tatp_callfwd_val_t *callfwd_val = (tatp_callfwd_val_t *)&callfwd_msg[i].val;
    assert(callfwd_val->numberx[0] == tatp_callfwd_numberx0_magic);

    if (callfwd_key[i].start_time <= start_time &&
        end_time < callfwd_val->end_time) {
      // All conditions satisfied
      callfwd_success = true;
    }
  }

  // no need to commit, since there's no write
  return callfwd_success;
}

// GET_ACCESS_DATA
bool TxnGetAccessData(int worker_id, uint64_t &txn_suc_pkt_cnt,
                      uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  tatp_accinf_key_t key;
  key.s_id = tatp_nurand(&tg_seed);
  key.ai_type = (fastrand(&tg_seed) & 3) + 1;

  message msg;
  msg.table = TableType::kAccessInfo;
  msg.key = *(uint64_t *)&key;

  while (true) {
    msg.type = PktType::kRead;
    NetHandshake(&msg, conns[msg.key%3], servaddr[msg.key%3]);
    assert(msg.key == *(uint64_t *)&key);
    assert(msg.table == TableType::kAccessInfo);
    txn_suc_pkt_cnt++;
    if (msg.type == PktType::kGrantRead || msg.type == PktType::kNotExist) break;
    else assert(msg.type == PktType::kRejectRead);
  }

  if (msg.type == PktType::kNotExist) return false;

  // the key was found
  tatp_accinf_val_t *val = (tatp_accinf_val_t *)&msg.val; _unused(val);
  assert(val->data1 == tatp_accinf_data1_magic);

  // no need to commit, since there's no write
  return true;
}

// UPDATE_SUBSCRIBER_DATA
bool TxnUpdateSubscriberData(int worker_id, uint64_t &txn_suc_pkt_cnt,
                             uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  // transaction parameters
  uint32_t s_id = tatp_nurand(&tg_seed);
  uint8_t sf_type = (fastrand(&tg_seed) % 4) + 1;

  message sub_msg_read, sub_msg_lock, specfac_msg_read, specfac_msg_lock;

  // read the subscriber record
  tatp_sub_key_t sub_key;
  sub_key.s_id = s_id;

  sub_msg_read.type = PktType::kRead;
  sub_msg_read.table = TableType::kSubscriber;
  sub_msg_read.key = *(uint64_t *)&sub_key;

  // read the special facilty record 
  tatp_specfac_key_t specfac_key;
  specfac_key.s_id = s_id;
  specfac_key.sf_type = sf_type;

  specfac_msg_read.type = PktType::kRead;
  specfac_msg_read.table = TableType::kSpecialFacility;
  specfac_msg_read.key = *(uint64_t *)&specfac_key;

  // lock the subscriber record
  sub_msg_lock.type = PktType::kAcquireLock;
  sub_msg_lock.table = TableType::kSubscriber;
  sub_msg_lock.key = *(uint64_t *)&sub_key;

  // lock the special facility record
  specfac_msg_lock.type = PktType::kAcquireLock;
  specfac_msg_lock.table = TableType::kSpecialFacility;
  specfac_msg_lock.key = *(uint64_t *)&specfac_key;

  shard_msgs[sub_msg_read.key%3].push_back(&sub_msg_read);
  shard_msgs[sub_msg_lock.key%3].push_back(&sub_msg_lock);
  shard_msgs[specfac_msg_read.key%3].push_back(&specfac_msg_read);
  shard_msgs[specfac_msg_lock.key%3].push_back(&specfac_msg_lock);

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantRead || msg.type == PktType::kNotExist || 
              msg.type == PktType::kGrantLock || msg.type == PktType::kRejectLock) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectRead);
            shard_msgs[i][msg.ord]->type = PktType::kRead;
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

  assert(sub_msg_read.type == PktType::kGrantRead);

  if (specfac_msg_read.type == PktType::kNotExist || sub_msg_lock.type == PktType::kRejectLock || 
      specfac_msg_lock.type == PktType::kRejectLock) {
    // release lock on subscriber record
    if (sub_msg_lock.type == PktType::kGrantLock) {
      sub_msg_lock.type = PktType::kAbort;
      NetHandshake(&sub_msg_lock, conns[sub_msg_lock.key%3], servaddr[sub_msg_lock.key%3]);

      assert(sub_msg_lock.type == PktType::kAbortAck);
      txn_suc_pkt_cnt++;
    } else assert(sub_msg_lock.type == PktType::kRejectLock);

    // release lock on special facility record
    if (specfac_msg_lock.type == PktType::kGrantLock) {
      specfac_msg_lock.type = PktType::kAbort;
      NetHandshake(&specfac_msg_lock, conns[specfac_msg_lock.key%3], servaddr[specfac_msg_lock.key%3]);

      assert(specfac_msg_lock.type == PktType::kAbortAck);
      txn_suc_pkt_cnt++;
    } else assert(specfac_msg_lock.type == PktType::kRejectLock);

    return false;
  } else assert(specfac_msg_read.type == PktType::kGrantRead && sub_msg_lock.type == PktType::kGrantLock && 
                specfac_msg_lock.type == PktType::kGrantLock);

  // if we are here, execution succeeded and we have locks
  tatp_sub_val_t *sub_val = (tatp_sub_val_t *)sub_msg_read.val;
  assert(sub_val->msc_location == tatp_sub_msc_location_magic);
  sub_val->bits = fastrand(&tg_seed);

  tatp_specfac_val_t *specfac_val = (tatp_specfac_val_t *)specfac_msg_read.val;
  assert(specfac_val->data_b[0] == tatp_specfac_data_b0_magic);
  specfac_val->data_a = fastrand(&tg_seed);

  // verify stage
  message sub_msg_ver, specfac_msg_ver;

  // verify the subscriber record
  sub_msg_ver.type = PktType::kRead;
  sub_msg_ver.table = TableType::kSubscriber;
  sub_msg_ver.key = *(uint64_t *)&sub_key;

  // verify the special facility record
  specfac_msg_ver.type = PktType::kRead;
  specfac_msg_ver.table = TableType::kSpecialFacility;
  specfac_msg_ver.key = *(uint64_t *)&specfac_key;

  shard_msgs[sub_msg_ver.key%3].push_back(&sub_msg_ver);
  shard_msgs[specfac_msg_ver.key%3].push_back(&specfac_msg_ver);

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantRead) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectRead);
            shard_msgs[i][msg.ord]->type = PktType::kRead;
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

  if (sub_msg_read.ver != sub_msg_ver.ver || specfac_msg_read.ver != specfac_msg_ver.ver) {
    // abort
    sub_msg_lock.type = PktType::kAbort;
    NetHandshake(&sub_msg_lock, conns[sub_msg_lock.key%3], servaddr[sub_msg_lock.key%3]);
    assert(sub_msg_lock.type == PktType::kAbortAck);
    txn_suc_pkt_cnt++;
    
    specfac_msg_lock.type = PktType::kAbort;
    NetHandshake(&specfac_msg_lock, conns[specfac_msg_lock.key%3], servaddr[specfac_msg_lock.key%3]);
    assert(specfac_msg_lock.type == PktType::kAbortAck);
    txn_suc_pkt_cnt++;

    return false;
  }

  // commit stage
  sub_msg_read.ver++;
  specfac_msg_read.ver++;

  sub_msg_read.type = PktType::kCommitLog;
  specfac_msg_read.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto sub_msg = new message;
    memcpy(sub_msg, &sub_msg_read, sizeof(message));

    auto specfac_msg = new message;
    memcpy(specfac_msg, &specfac_msg_read, sizeof(message));

    shard_msgs[i].push_back(sub_msg);
    shard_msgs[i].push_back(specfac_msg);
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

  sub_msg_read.type = PktType::kCommitBck;
  specfac_msg_read.type = PktType::kCommitBck;

  shard_msgs[((sub_msg_read.key%3)+1)%3].push_back(&sub_msg_read);
  shard_msgs[((specfac_msg_read.key%3)+1)%3].push_back(&specfac_msg_read);
  {
    auto sub_msg = new message;
    memcpy(sub_msg, &sub_msg_read, sizeof(message));
    auto specfac_msg = new message;
    memcpy(specfac_msg, &specfac_msg_read, sizeof(message));
    shard_msgs[((sub_msg_read.key%3)+2)%3].push_back(sub_msg);
    shard_msgs[((specfac_msg_read.key%3)+2)%3].push_back(specfac_msg);
  }

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kCommitBckAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectCommit);
            shard_msgs[i][msg.ord]->type = PktType::kCommitBck;
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

  sub_msg_read.type = PktType::kCommitPrim;
  specfac_msg_read.type = PktType::kCommitPrim;

  shard_msgs[sub_msg_read.key%3].push_back(&sub_msg_read);
  shard_msgs[specfac_msg_read.key%3].push_back(&specfac_msg_read);

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kCommitPrimAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectCommit);
            shard_msgs[i][msg.ord]->type = PktType::kCommitPrim;
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

// UPDATE_LOCATION
bool TxnUpdateLocation(int worker_id, uint64_t &txn_suc_pkt_cnt,
                       uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  // transaction parameters
  uint32_t s_id = tatp_nurand(&tg_seed);
  uint32_t vlr_location = fastrand(&tg_seed);

  // read the secondary subscriber record
  tatp_sec_sub_key_t sec_sub_key;
  sec_sub_key.sub_nbr = tatp_sid_to_sub_nbr(s_id);

  message sec_sub_msg;
  sec_sub_msg.table = TableType::kSecondSubscriber;
  sec_sub_msg.key = *(uint64_t *)&sec_sub_key;

  while (true) {
    sec_sub_msg.type = PktType::kRead;
    NetHandshake(&sec_sub_msg, conns[sec_sub_msg.key%3], servaddr[sec_sub_msg.key%3]);
    assert(sec_sub_msg.key == *(uint64_t *)&sec_sub_key);
    assert(sec_sub_msg.table == TableType::kSecondSubscriber);
    txn_suc_pkt_cnt++;
    if (sec_sub_msg.type == PktType::kGrantRead) break;
    else assert(sec_sub_msg.type == PktType::kRejectRead);
  }

  tatp_sec_sub_val_t *sec_sub_val = (tatp_sec_sub_val_t *)sec_sub_msg.val;
  _unused(sec_sub_val);
  assert(sec_sub_val->magic == tatp_sec_sub_magic);
  assert(sec_sub_val->s_id == s_id);

  // read and lock the subscriber record
  tatp_sub_key_t sub_key;
  sub_key.s_id = s_id;

  message sub_msg_read, sub_msg_lock;

  sub_msg_read.type = PktType::kRead;
  sub_msg_read.table = TableType::kSubscriber;
  sub_msg_read.key = *(uint64_t *)&sub_key;

  sub_msg_lock.type = PktType::kAcquireLock;
  sub_msg_lock.table = TableType::kSubscriber;
  sub_msg_lock.key = *(uint64_t *)&sub_key;

  shard_msgs[sub_msg_read.key%3].push_back(&sub_msg_read);
  shard_msgs[sub_msg_lock.key%3].push_back(&sub_msg_lock);
  
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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantRead || msg.type == PktType::kGrantLock || 
              msg.type == PktType::kRejectLock) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectRead);
            shard_msgs[i][msg.ord]->type = PktType::kRead;
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

  assert(sub_msg_read.type == PktType::kGrantRead);
  if (sub_msg_lock.type == PktType::kRejectLock) return false;
  else assert(sub_msg_lock.type == PktType::kGrantLock);

  tatp_sub_val_t *sub_val = (tatp_sub_val_t *)sub_msg_read.val;
  assert(sub_val->msc_location == tatp_sub_msc_location_magic);
  sub_val->vlr_location = vlr_location;

  // verify stage
  message sub_msg_ver;

  // verify the subscriber record
  sub_msg_ver.table = TableType::kSubscriber;
  sub_msg_ver.key = *(uint64_t *)&sub_key;

  while (1) {
    sub_msg_ver.type = PktType::kRead;
    NetHandshake(&sub_msg_ver, conns[sub_msg_ver.key%3], servaddr[sub_msg_ver.key%3]);
    assert(sub_msg_ver.key == *(uint64_t *)&sub_key);
    assert(sub_msg_ver.table == TableType::kSubscriber);
    txn_suc_pkt_cnt++;
    if (sub_msg_ver.type == PktType::kGrantRead) break;
    else assert(sub_msg_ver.type == PktType::kRejectRead);
  }

  if (sub_msg_ver.ver != sub_msg_read.ver) {
    sub_msg_lock.type = PktType::kAbort;
    NetHandshake(&sub_msg_lock, conns[sub_msg_lock.key%3], servaddr[sub_msg_lock.key%3]);
    assert(sub_msg_lock.type == PktType::kAbortAck);
    txn_suc_pkt_cnt++;
    return false;
  }
  
  // commit stage
  sub_msg_read.ver++;
  sub_msg_read.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto sub_msg = new message;
    memcpy(sub_msg, &sub_msg_read, sizeof(message));
    shard_msgs[i].push_back(sub_msg);
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

  sub_msg_read.type = PktType::kCommitBck;

  shard_msgs[((sub_msg_read.key%3)+1)%3].push_back(&sub_msg_read);
  {
    auto sub_msg = new message;
    memcpy(sub_msg, &sub_msg_read, sizeof(message));
    shard_msgs[((sub_msg_read.key%3)+2)%3].push_back(sub_msg);
  }

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kCommitBckAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectCommit);
            shard_msgs[i][msg.ord]->type = PktType::kCommitBck;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();

  while (true) {
    sub_msg_read.type = PktType::kCommitPrim;
    NetHandshake(&sub_msg_read, conns[sub_msg_read.key%3], servaddr[sub_msg_read.key%3]);
    txn_suc_pkt_cnt++;
    if (sub_msg_read.type == PktType::kCommitPrimAck) break;
    else assert(sub_msg_read.type == PktType::kRejectCommit);
  }

  return true;
}

// INSERT_CALL_FORWARDING
bool TxnInsertCallForwarding(int worker_id, uint64_t &txn_suc_pkt_cnt,
                             uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;
  
  // Transaction parameters
  uint32_t s_id = tatp_nurand(&tg_seed);
  uint8_t sf_type = (fastrand(&tg_seed) % 4) + 1;
  uint8_t start_time = (fastrand(&tg_seed) % 3) * 8;
  uint8_t end_time = (fastrand(&tg_seed) % 24) * 1;

  // Read the secondary subscriber record
  tatp_sec_sub_key_t sec_sub_key;
  sec_sub_key.sub_nbr = tatp_sid_to_sub_nbr(s_id);

  message sec_sub_msg;
  sec_sub_msg.table = TableType::kSecondSubscriber;
  sec_sub_msg.key = *(uint64_t *)&sec_sub_key;

  while (true) {
    sec_sub_msg.type = PktType::kRead;
    NetHandshake(&sec_sub_msg, conns[sec_sub_msg.key%3], servaddr[sec_sub_msg.key%3]);
    assert(sec_sub_msg.key == *(uint64_t *)&sec_sub_key);
    assert(sec_sub_msg.table == TableType::kSecondSubscriber);
    txn_suc_pkt_cnt++;
    if (sec_sub_msg.type == PktType::kGrantRead) break;
    else assert(sec_sub_msg.type == PktType::kRejectRead);
  }

  tatp_sec_sub_val_t *sec_sub_val = (tatp_sec_sub_val_t *)sec_sub_msg.val;
  _unused(sec_sub_val);
  assert(sec_sub_val->magic == tatp_sec_sub_magic);
  assert(sec_sub_val->s_id == s_id);

  // read the special facility record
  tatp_specfac_key_t specfac_key;
  specfac_key.s_id = s_id;
  specfac_key.sf_type = sf_type;

  message specfac_msg_read;
  specfac_msg_read.table = TableType::kSpecialFacility;
  specfac_msg_read.key = *(uint64_t *)&specfac_key;

  while (true) {
    specfac_msg_read.type = PktType::kRead;
    NetHandshake(&specfac_msg_read, conns[specfac_msg_read.key%3], servaddr[specfac_msg_read.key%3]);
    assert(specfac_msg_read.key == *(uint64_t *)&specfac_key);
    assert(specfac_msg_read.table == TableType::kSpecialFacility);
    txn_suc_pkt_cnt++;
    if (specfac_msg_read.type == PktType::kGrantRead || specfac_msg_read.type == PktType::kNotExist) break;
    else assert(specfac_msg_read.type == PktType::kRejectRead);
  }

  if (specfac_msg_read.type == PktType::kNotExist) return false;

  // if we are here, the special facility record exists
  tatp_specfac_val_t *specfac_val = (tatp_specfac_val_t *)&specfac_msg_read.val;
  _unused(specfac_val);
  assert(specfac_val->data_b[0] == tatp_specfac_data_b0_magic);

  tatp_callfwd_key_t callfwd_key;
  callfwd_key.s_id = s_id;
  callfwd_key.sf_type = sf_type;
  callfwd_key.start_time = start_time;

  // read the call forwarding record
  message callfwd_msg_read;
  callfwd_msg_read.type = PktType::kRead;
  callfwd_msg_read.table = TableType::kCallForwarding;
  callfwd_msg_read.key = *(uint64_t *)&callfwd_key;
  
  // lock the call forwarding record
  message callfwd_msg_lock;
  callfwd_msg_lock.type = PktType::kAcquireLock;
  callfwd_msg_lock.table = TableType::kCallForwarding;
  callfwd_msg_lock.key = *(uint64_t *)&callfwd_key;

  shard_msgs[callfwd_msg_read.key%3].push_back(&callfwd_msg_read);
  shard_msgs[callfwd_msg_lock.key%3].push_back(&callfwd_msg_lock);

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantRead || msg.type == PktType::kNotExist ||
              msg.type == PktType::kGrantLock || msg.type == PktType::kRejectLock) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectRead);
            shard_msgs[i][msg.ord]->type = PktType::kRead;
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

  if (callfwd_msg_read.type == PktType::kGrantRead || callfwd_msg_lock.type == PktType::kRejectLock) {
    // release lock on call forwarding record
    if (callfwd_msg_lock.type == PktType::kGrantLock) {
      callfwd_msg_lock.type = PktType::kAbort;
      NetHandshake(&callfwd_msg_lock, conns[callfwd_msg_lock.key%3], servaddr[callfwd_msg_lock.key%3]);

      assert(callfwd_msg_lock.type == PktType::kAbortAck);
      txn_suc_pkt_cnt++;
    } else assert(callfwd_msg_lock.type == PktType::kRejectLock);

    return false;
  } else assert(callfwd_msg_read.type == PktType::kNotExist && callfwd_msg_lock.type == PktType::kGrantLock);

  // if we are here, we have acquired the lock
  // construct the object to insert
  tatp_callfwd_val_t *callfwd_val = (tatp_callfwd_val_t *)&callfwd_msg_read.val;
  callfwd_val->numberx[0] = tatp_callfwd_numberx0_magic;
  callfwd_val->end_time = end_time;
  
  // verify stage
  message specfac_msg_ver, callfwd_msg_ver;
  
  // verify the special facility record
  specfac_msg_ver.type = PktType::kRead;
  specfac_msg_ver.table = TableType::kSpecialFacility;
  specfac_msg_ver.key = *(uint64_t *)&specfac_key;

  // verify the call forwarding record
  callfwd_msg_ver.type = PktType::kRead;
  callfwd_msg_ver.table = TableType::kCallForwarding;
  callfwd_msg_ver.key = *(uint64_t *)&callfwd_key;

  shard_msgs[specfac_msg_ver.key%3].push_back(&specfac_msg_ver);
  shard_msgs[callfwd_msg_ver.key%3].push_back(&callfwd_msg_ver);

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantRead || msg.type == PktType::kNotExist) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectRead);
            shard_msgs[i][msg.ord]->type = PktType::kRead;
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

  assert(specfac_msg_ver.type == PktType::kGrantRead);

  if (specfac_msg_read.ver != specfac_msg_ver.ver || callfwd_msg_ver.type == PktType::kGrantRead) {
    // abort
    callfwd_msg_lock.type = PktType::kAbort;
    NetHandshake(&callfwd_msg_lock, conns[callfwd_msg_lock.key%3], servaddr[callfwd_msg_lock.key%3]);
    assert(callfwd_msg_lock.type == PktType::kAbortAck);
    txn_suc_pkt_cnt++;

    return false;
  } else assert(callfwd_msg_ver.type == PktType::kNotExist);

  // commit stage
  callfwd_msg_read.ver = 0;
  callfwd_msg_read.type = PktType::kCommitLog;

  for (int i = 0; i < 3; ++i) {
    auto callfwd_msg = new message;
    memcpy(callfwd_msg, &callfwd_msg_read, sizeof(message));
    shard_msgs[i].push_back(callfwd_msg);
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

  callfwd_msg_read.type = PktType::kInsertBck;

  shard_msgs[((callfwd_msg_read.key%3)+1)%3].push_back(&callfwd_msg_read);
  {
    auto callfwd_msg = new message;
    memcpy(callfwd_msg, &callfwd_msg_read, sizeof(message));
    shard_msgs[((callfwd_msg_read.key%3)+2)%3].push_back(callfwd_msg);
  }

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kInsertBckAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectCommit);
            shard_msgs[i][msg.ord]->type = PktType::kInsertBck;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();

  while (true) {
    callfwd_msg_read.type = PktType::kInsertPrim;
    NetHandshake(&callfwd_msg_read, conns[callfwd_msg_read.key%3], servaddr[callfwd_msg_read.key%3]);
    txn_suc_pkt_cnt++;
    if (callfwd_msg_read.type == PktType::kInsertPrimAck) break;
    else assert(callfwd_msg_read.type == PktType::kRejectCommit);
  }
  return true;
}

// DELETE_CALL_FORWARDING
bool TxnDeleteCallForwarding(int worker_id, uint64_t &txn_suc_pkt_cnt,
                             uint64_t &tg_seed, const std::vector<rt::UdpConn *> &conns) {
  std::vector<message *> shard_msgs[3];
  std::vector<rt::Thread> shard_wrkrs;

  // transaction parameters
  uint32_t s_id = tatp_nurand(&tg_seed);
  uint8_t sf_type = (fastrand(&tg_seed) % 4) + 1;
  uint8_t start_time = (fastrand(&tg_seed) % 3) * 8;

  // read the secondary subscriber record
  tatp_sec_sub_key_t sec_sub_key;
  sec_sub_key.sub_nbr = tatp_sid_to_sub_nbr(s_id);

  message sec_sub_msg;

  sec_sub_msg.table = TableType::kSecondSubscriber;
  sec_sub_msg.key = *(uint64_t *)&sec_sub_key;

  while (true) {
    sec_sub_msg.type = PktType::kRead;
    NetHandshake(&sec_sub_msg, conns[sec_sub_msg.key%3], servaddr[sec_sub_msg.key%3]);
    assert(sec_sub_msg.key == *(uint64_t *)&sec_sub_key);
    assert(sec_sub_msg.table == TableType::kSecondSubscriber);
    txn_suc_pkt_cnt++;
    if (sec_sub_msg.type == PktType::kGrantRead) break;
    else assert(sec_sub_msg.type == PktType::kRejectRead);
  }

  tatp_sec_sub_val_t *sec_sub_val = (tatp_sec_sub_val_t *)sec_sub_msg.val;
  _unused(sec_sub_val);
  assert(sec_sub_val->magic == tatp_sec_sub_magic);
  assert(sec_sub_val->s_id == s_id);

  // read the call forwarding record
  tatp_callfwd_key_t callfwd_key;
  callfwd_key.s_id = s_id;
  callfwd_key.sf_type = sf_type;
  callfwd_key.start_time = start_time;

  message callfwd_msg_read, callfwd_msg_lock;

  callfwd_msg_read.type = PktType::kRead;
  callfwd_msg_read.table = TableType::kCallForwarding;
  callfwd_msg_read.key = *(uint64_t *)&callfwd_key;

  // lock the call forwarding record
  callfwd_msg_lock.type = PktType::kAcquireLock;
  callfwd_msg_lock.table = TableType::kCallForwarding;
  callfwd_msg_lock.key = *(uint64_t *)&callfwd_key;

  shard_msgs[callfwd_msg_read.key%3].push_back(&callfwd_msg_read);
  shard_msgs[callfwd_msg_lock.key%3].push_back(&callfwd_msg_lock);

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kGrantRead || msg.type == PktType::kNotExist ||
              msg.type == PktType::kGrantLock || msg.type == PktType::kRejectLock) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectRead);
            shard_msgs[i][msg.ord]->type = PktType::kRead;
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

  if (callfwd_msg_read.type == PktType::kNotExist || callfwd_msg_lock.type == PktType::kRejectLock) {
    // release lock on call forwarding record
    if (callfwd_msg_lock.type == PktType::kGrantLock) {
      callfwd_msg_lock.type = PktType::kAbort;
      NetHandshake(&callfwd_msg_lock, conns[callfwd_msg_lock.key%3], servaddr[callfwd_msg_lock.key%3]);

      assert(callfwd_msg_lock.type == PktType::kAbortAck);
      txn_suc_pkt_cnt++;
    } else assert(callfwd_msg_lock.type == PktType::kRejectLock);

    return false;
  } else assert(callfwd_msg_read.type == PktType::kGrantRead && callfwd_msg_lock.type == PktType::kGrantLock);

  // if we are here, we have a call forwarding record to delete
  auto *callfwd_val = (tatp_callfwd_val_t *)&callfwd_msg_read.val;
  _unused(callfwd_val);
  assert(callfwd_val->numberx[0] == tatp_callfwd_numberx0_magic);

  // verify the call forwarding record
  message callfwd_msg_ver;
  callfwd_msg_ver.table = TableType::kCallForwarding;
  callfwd_msg_ver.key = *(uint64_t *)&callfwd_key;

  while (true) {
    callfwd_msg_ver.type = PktType::kRead;
    NetHandshake(&callfwd_msg_ver, conns[callfwd_msg_ver.key%3], servaddr[callfwd_msg_ver.key%3]);
    assert(callfwd_msg_ver.key == *(uint64_t *)&callfwd_key);
    assert(callfwd_msg_ver.table == TableType::kCallForwarding);
    txn_suc_pkt_cnt++;
    if (callfwd_msg_ver.type == PktType::kGrantRead || callfwd_msg_ver.type == PktType::kNotExist) break;
    else assert(callfwd_msg_ver.type == PktType::kRejectRead);
  }

  if (callfwd_msg_ver.type == PktType::kNotExist || callfwd_msg_ver.ver != callfwd_msg_read.ver) {
    // deleted by another transaction, abort
    callfwd_msg_lock.type = PktType::kAbort;
    NetHandshake(&callfwd_msg_lock, conns[callfwd_msg_lock.key%3], servaddr[callfwd_msg_lock.key%3]);
    assert(callfwd_msg_lock.type == PktType::kAbortAck);
    txn_suc_pkt_cnt++;
    return false;
  } else assert(callfwd_msg_ver.type == PktType::kGrantRead);

  // commit stage
  callfwd_msg_read.type = PktType::kDeleteLog;

  for (int i = 0; i < 3; ++i) {
    auto callfwd_msg = new message;
    memcpy(callfwd_msg, &callfwd_msg_read, sizeof(message));
    shard_msgs[i].push_back(callfwd_msg);
  }

  for (int i = 0; i < 3; ++i) {
    shard_wrkrs.emplace_back(rt::Thread([&, i]() {
      for (auto &msg: shard_msgs[i])
        NetSend(msg, conns[i], servaddr[i]);

      for (auto &msg: shard_msgs[i]) {
        NetRecv(msg, conns[i], nullptr);
        assert(msg->type == PktType::kDeleteLogAck);
        __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();
  shard_wrkrs.clear();
  for (auto &msgs: shard_msgs) msgs.clear();

  callfwd_msg_read.type = PktType::kDeleteBck;

  shard_msgs[((callfwd_msg_read.key%3)+1)%3].push_back(&callfwd_msg_read);
  {
    auto callfwd_msg = new message;
    memcpy(callfwd_msg, &callfwd_msg_read, sizeof(message));
    shard_msgs[((callfwd_msg_read.key%3)+2)%3].push_back(callfwd_msg);
  }

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
          memcpy(shard_msgs[i][msg.ord], &msg, sizeof(msg));
          __sync_fetch_and_add(&txn_suc_pkt_cnt, 1);
          if (msg.type == PktType::kDeleteBckAck) {
            done[msg.ord] = true;
          }
          else {
            assert(msg.type == PktType::kRejectCommit);
            shard_msgs[i][msg.ord]->type = PktType::kDeleteBck;
          }
        }

        for (int j = size-1; j >= 0; --j) {
          if (done[j]) shard_msgs[i].erase(shard_msgs[i].begin() + j);
        }
      }
    }));
  } 
  for (auto &wrkr: shard_wrkrs) wrkr.Join();

  while (true) {
    callfwd_msg_read.type = PktType::kDeletePrim;
    NetHandshake(&callfwd_msg_read, conns[callfwd_msg_read.key%3], servaddr[callfwd_msg_read.key%3]);
    txn_suc_pkt_cnt++;
    if (callfwd_msg_read.type == PktType::kDeletePrimAck) break;
    else assert(callfwd_msg_read.type == PktType::kRejectCommit);
  }
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
      case TxnType::kGetSubscriberData:
        txn_committed = TxnGetSubscriberData(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kGetNewDestination:
        txn_committed = TxnGetNewDestination(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kGetAccessData:
        txn_committed = TxnGetAccessData(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kUpdateSubscriberData:
        txn_committed = TxnUpdateSubscriberData(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kUpdateLocation:
        txn_committed = TxnUpdateLocation(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kInsertCallForwarding:
        txn_committed = TxnInsertCallForwarding(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
        break;
      case TxnType::kDeleteCallForwarding:
        txn_committed = TxnDeleteCallForwarding(wrkr_lid, txn_suc_pkt_cnt, tg_seed, conns);
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
  if (machine_id == 1) {
    auto threads_old = threads;
    threads = 600;

    std::vector<rt::Thread> pop_th;
    for (int i = 0; i < threads; i++) {
      pop_th.emplace_back(rt::Thread([&, i]{
        PopulateThread(i);
      }));
    }

    for (auto &t: pop_th)
      t.Join();

    threads = threads_old;

    std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, 0}));
    if (c == nullptr) panic("failed to create socket");

    for (int i = 1; i < machine_num; i++) {
      message msg;
      netaddr caddr = {MAKE_IP_ADDR(10, 10, 1, (i + 4)), kFasstPort};
      ssize_t ret = c->WriteTo(&msg, sizeof(msg), &caddr);
      if (ret != sizeof(msg)) panic("couldn't send synch message");
    }
  } else {
    std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, kFasstPort}));
    if (c == nullptr) panic("failed to create socket");

    message msg;
    ssize_t ret = c->ReadFrom(&msg, sizeof(msg), NULL);
    if (ret != sizeof(msg)) panic("couldn't receive synch message");
  }

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
  machine_num = std::stoi(argv[3], nullptr, 0);
  threads = std::stoi(argv[4], nullptr, 0);
  mode = argv[6];

  uint64_t target_load = std::stoul(argv[5], nullptr, 0);
  
  if (target_load == 0) net_intv = 0;
  else net_intv = machine_num * threads * 1000000UL / target_load;

  CreateWorkgenArr();
  create_map1000();

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