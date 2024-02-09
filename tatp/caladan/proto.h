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
  kRead = 0,
  kAcquireLock = 1,
  kAbort = 2,
  kCommit = 3,

  // server
  kGrantRead = 4,
  kRejectRead = 5,
  kNotExist = 6,
  kGrantLock = 7,
  kRejectLock = 8,
  kAbortAck = 9,
  kCommitAck = 10,
  kRejectCommit = 11,

  // only used in sharding
  kCommitPrim = 12,
  kCommitBck = 13,
  kCommitLog = 14,
  kCommitPrimAck = 15,
  kCommitBckAck = 16,
  kCommitLogAck = 17,

  // only used in tatp
  kInsertPrim = 18,
  kInsertBck = 19,
  kInsertPrimAck = 20,
  kInsertBckAck = 21,

  kDeletePrim = 22,
  kDeleteBck = 23,
  kDeleteLog = 24,
  kDeletePrimAck = 25,
  kDeleteBckAck = 26,
  kDeleteLogAck = 27,

  kRejectLockSameKey = 28,
};

// for adjusting server socket buffer size
constexpr int kSocketBufSize = 10485760;

#pragma pack(push, 1)
struct message {
  uint8_t ord;             // order of the message
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
