// tatp spec

#pragma once

#include <string>
#include <assert.h>
#include "kvs.h"
#include "utils.h"

constexpr int kLockNum = 36000000;

static inline int lock_hash(kvs *kvs, uint64_t key) {
  return (int)(fasthash64(&key, sizeof(key), 0xdeadbeef) % (uint64_t)(kKeysPerEntry * kvs->hash_size));
}

constexpr int kFreqHotTxn = 90;
constexpr int kAccountNum = 24000000;
constexpr int kHotAccountNum = 960000;

// random number generator
static inline uint32_t fastrand(uint64_t *seed) {
  *seed = *seed * 1103515245 + 12345;
  return (uint32_t)(*seed >> 32);
}

/*
  * Generators for new account IDs. Called once per transaction because
  * we need to decide hot-or-not per transaction, not per account.
  */
static inline void get_account(uint64_t *seed, uint64_t *acct_id) {
  if (fastrand(seed) % 100 < kFreqHotTxn) {
    *acct_id = fastrand(seed) % kHotAccountNum;
  } else {
    *acct_id = fastrand(seed) % kAccountNum;
  }
}

static inline void get_two_accounts(uint64_t *seed, uint64_t *acct_id_0, uint64_t *acct_id_1) {
  if (fastrand(seed) % 100 < kFreqHotTxn) {
    *acct_id_0 = fastrand(seed) % kHotAccountNum;
    *acct_id_1 = fastrand(seed) % kHotAccountNum;
    while (*acct_id_1 == *acct_id_0)
      *acct_id_1 = fastrand(seed) % kHotAccountNum;
  } else {
    *acct_id_0 = fastrand(seed) % kAccountNum;
    *acct_id_1 = fastrand(seed) % kAccountNum;
    while (*acct_id_1 == *acct_id_0) 
      *acct_id_1 = fastrand(seed) % kAccountNum;
  }
}

// transaction types
enum TxnType {
  kAmalgamate = 0,
  kBalance = 1,
  kDepositChecking = 2,
  kSendPayment = 3,
  kTransactSaving = 4,
  kWriteCheck = 5,
};

// transaction frequencies
constexpr int kFreqAmalgamate = 15;
constexpr int kFreqBalance = 15;
constexpr int kFreqDepositChecking = 15;
constexpr int kFreqSendPayment = 25;
constexpr int kFreqTransactSaving = 15;
constexpr int kFreqWriteCheck = 15;

// Magic numbers for debugging. These are unused in the spec.
#define SB_MAGIC 97	/* Some magic number <= 255 */
#define sb_sav_magic (SB_MAGIC)
#define sb_chk_magic (SB_MAGIC + 1)

// Smallbank table keys and values
// All keys have been sized to 8 bytes
// All values have been sized to the next multiple of 8 bytes

/*
 * SAVINGS table.
 */
union sb_sav_key_t {
  uint64_t acct_id;
  sb_sav_key_t() { acct_id = 0; }
};

struct sb_sav_val_t {
  uint32_t magic;
  float bal;
};

/*
 * CHECKING table
 */
union sb_chk_key_t {
  uint64_t acct_id;
  sb_chk_key_t() { acct_id = 0; }
};

struct sb_chk_val_t {
  uint32_t magic;
  float bal;
};

static inline void populate_saving_and_checking_tables(kvs *saving_table, kvs *checking_table) {
  for (uint32_t acct_id = 0; acct_id < kAccountNum; acct_id++) {
    // Savings
    sb_sav_key_t sav_key;
    sav_key.acct_id = (uint64_t)acct_id;

    sb_sav_val_t sav_val;
    sav_val.magic = sb_sav_magic;
    sav_val.bal = 1000000000ull;

    kvs_insert(saving_table, *(uint64_t *)&sav_key, (uint8_t *)&sav_val);

    // Checking
    sb_chk_key_t chk_key;
    chk_key.acct_id = (uint64_t) acct_id;

    sb_chk_val_t chk_val;
    chk_val.magic = sb_chk_magic;
    chk_val.bal = 1000000000ull;

    kvs_insert(checking_table, *(uint64_t *)&chk_key, (uint8_t *)&chk_val);
  }
}