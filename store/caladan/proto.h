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
  kSet = 1,
  kInsert = 2,

  // server
  kGrantRead = 3,
  kRejectRead = 4,
  kSetAck = 5,
  kRejectSet = 6,
  kNotExist = 7,
  kInsertAck = 8,
  kRejectInsert = 9,
};

// for adjusting server socket buffer size
constexpr int kSocketBufSize = 10485760;

#pragma pack(push, 1)
struct message {
  uint8_t type;            // packet type
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
