// a really basic encoding for experiment messages

#pragma once

constexpr uint64_t kFasstPort = 20230;

constexpr int kMaxLogEntryNum = 1000000;
constexpr int kValSize = 40;

enum PktType {
  kCommit = 0,
  kAck = 1,
};

struct log_entry {
  uint64_t key;            // key
  uint8_t val[kValSize];   // value
  uint32_t ver;            // version
};

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
