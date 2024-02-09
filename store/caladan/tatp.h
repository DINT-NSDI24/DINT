// tatp spec

#pragma once

#include <string>
#include <assert.h>
#include "kvs.h"
#include "utils.h"

constexpr int kSubscriberNum = 2000000;
constexpr int A = 1048575;
constexpr uint8_t kValMagic = 0x5a;

enum TxnType {
  kTxnRead = 0,
  kTxnSet = 1,
  kTxnTypeNum = 2,
};

union store_key_t {
  struct {
    uint32_t s_id;
    uint8_t sf_type;
    uint8_t start_time;
    uint8_t unused[2];
  };
  uint64_t key;
  store_key_t() : key(0) {}
};

struct store_val_t {
  uint8_t end_time;
  char numberx[39];
};

// random number generator
static inline uint32_t fastrand(uint64_t *seed) {
  *seed = *seed * 1103515245 + 12345;
  return (uint32_t)(*seed >> 32);
}

// get a non-uniform-random distributed subscriber ID according to spec
// To get a non-uniformly random number between 0 and y:
// NURand(A, 0, y) = (get_random(0, A) | get_random(0, y)) % (y + 1)
static inline uint32_t tatp_nurand(uint64_t *tg_seed) {
  return ((fastrand(tg_seed) % kSubscriberNum) |
      (fastrand(tg_seed) & A)) % kSubscriberNum;
}

// populate table
static inline void populate_table(kvs *table) {
  std::vector<uint8_t> sf_type_values = {1, 2, 3, 4};

  uint64_t tmp_seed = 0xdeadbeef;

  for (uint32_t s_id = 0; s_id < kSubscriberNum; s_id++) {
    for (uint8_t &sf_type : sf_type_values) {
      for (size_t start_time = 0; start_time <= 16; start_time += 8) {
        store_key_t store_key;
        store_key.s_id = s_id;
        store_key.sf_type = sf_type;
        store_key.start_time = start_time;

        store_val_t val;
        val.end_time = (fastrand(&tmp_seed) % 24) + 1;
        val.numberx[0] = kValMagic;

        kvs_insert(table, store_key.key, (uint8_t *)&val);
      }	// loop start_time
    }	// loop sf_type
  }	// loop s_id
}