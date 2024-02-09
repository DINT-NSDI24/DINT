// networking

#pragma once

#include <stdint.h>
#include <inttypes.h>

#include "kvs.h"

// magic port
constexpr int kFasstPort = 20230;

// packet types
enum PktType {
  // client
  kAcquireShared = 0,
  kAcquireExclusive = 1,
  kReleaseShared = 2,
  kReleaseExclusive = 3,
  kCommitPrim = 4,
  kCommitBck = 5,
  kCommitLog = 6,

  // server
  kGrantShared = 7,
  kRejectShared = 8,
  kGrantExclusive = 9,
  kRejectExclusive = 10,
  kReleaseSharedAck = 11,
  kReleaseExclusiveAck = 12,
  kCommitPrimAck = 13,
  kCommitBckAck = 14,
  kCommitLogAck = 15,
  kRetry = 16,
  kWarmupRead = 17,
  kWarmupReadAck = 18,
};

// for adjusting server socket buffer size
constexpr int kSocketBufSize = 10485760;

#pragma pack(push, 1)
struct message {
  uint8_t ord;             // order
  uint8_t type;            // packet type
  uint8_t table;           // table id
  uint64_t key;            // key
  uint8_t val[kValSize];   // value
  uint32_t ver;            // version
};

struct net_req {
  int nports;
};

struct net_resp {
  int nports;
  uint16_t ports[];
};

#pragma pack(pop)

constexpr char ip_list[][32] = {
  "10.10.1.1",
  "10.10.1.2",
  "10.10.1.3",
};
