// tatp spec

#ifndef _SMALLBANK_H_
#define _SMALLBANK_H_

#include <string.h>
#include <assert.h>
#include "kvs.h"
#include "utils.h"

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
};

struct sb_chk_val_t {
  uint32_t magic;
  float bal;
};

static inline void populate_saving_and_checking_tables(struct kvs *saving_table, struct kvs *checking_table) {
  for (uint32_t acct_id = 0; acct_id < ACCOUNT_NUM; acct_id++) {
    // Savings
    union sb_sav_key_t sav_key;
    sav_key.acct_id = (uint64_t)acct_id;

    struct sb_sav_val_t sav_val;
    sav_val.magic = sb_sav_magic;
    sav_val.bal = 1000000000ull;

    kvs_insert(saving_table, *(uint64_t *)&sav_key, (uint8_t *)&sav_val);

    // Checking
    union sb_chk_key_t chk_key;
    chk_key.acct_id = (uint64_t) acct_id;

    struct sb_chk_val_t chk_val;
    chk_val.magic = sb_chk_magic;
    chk_val.bal = 1000000000ull;

    kvs_insert(checking_table, *(uint64_t *)&chk_key, (uint8_t *)&chk_val);
  }
}

#endif // _SMALLBANK_H_