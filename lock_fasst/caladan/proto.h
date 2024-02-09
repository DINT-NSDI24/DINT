// a really basic encoding for experiment messages

#pragma once

// maximum number of transactions
constexpr uint32_t kMaxTxnNum = 100000;

// maximum number of locks
constexpr uint32_t kLockHashSize = 36000000;

// operation types.
enum TxnType {
  kR = 0,
  kW = 1,
};

constexpr uint64_t kFasstPort = 20230;

enum PktType {
  kRead = 0,
  kAcquireLock = 1,
  kAbort = 2,
  kCommit = 3,
  kGrantRead = 4,
  kGrantLock = 5,
  kRejectLock = 6,
  kAbortAck = 7,
  kCommitAck = 8,
};

#pragma pack(push, 1)
struct message {
  uint8_t type;
  uint32_t lid;
  uint32_t ver;
};

struct net_req {
  int nports;
};

struct net_resp {
  int nports;
  uint16_t ports[];
};
#pragma pack(pop)

// Compression function for Merkle-Damgard construction.
// This function is generated using the framework provided.
static inline uint64_t fasthash_mix(uint64_t h) {
  h ^= h >> 23;
  h *= 0x2127599bf4325c37ULL;
  h ^= h >> 47;
  return h;
}

static inline uint64_t fasthash64(const void *buf, uint64_t len, uint64_t seed) {
  const uint64_t m = 0x880355f21e6d1965ULL;
  const uint64_t *pos = (const uint64_t *)buf;
  const uint64_t *end = pos + (len / 8);
  const unsigned char *pos2;
  uint64_t h = seed ^ (len * m);
  uint64_t v;

  while (pos != end) {
    v  = *pos++;
    h ^= fasthash_mix(v);
    h *= m;
  }

  pos2 = (const unsigned char*)pos;
  v = 0;

  switch (len & 7) {
  case 7: v ^= (uint64_t)pos2[6] << 48;
  case 6: v ^= (uint64_t)pos2[5] << 40;
  case 5: v ^= (uint64_t)pos2[4] << 32;
  case 4: v ^= (uint64_t)pos2[3] << 24;
  case 3: v ^= (uint64_t)pos2[2] << 16;
  case 2: v ^= (uint64_t)pos2[1] << 8;
  case 1: v ^= (uint64_t)pos2[0];
    h ^= fasthash_mix(v);
    h *= m;
  }

  return fasthash_mix(h);
}

static inline uint32_t fasthash32(const void *buf, uint64_t len, uint32_t seed)
{
  // the following trick converts the 64-bit hashcode to Fermat
  // residue, which shall retain information from both the higher
  // and lower parts of hashcode.
  uint64_t h = fasthash64(buf, len, seed);
  return h - (h >> 32);
}