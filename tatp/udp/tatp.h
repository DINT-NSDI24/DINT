// tatp spec

#pragma once

#include <string>
#include <assert.h>
#include "kvs.h"
#include "utils.h"

constexpr int kLockNum = 84000000;

static inline int lock_hash(kvs *kvs, uint64_t key) {
  return (int)(fasthash64(&key, sizeof(key), 0xdeadbeef) % (uint64_t)(kKeysPerEntry * kvs->hash_size));
}

extern uint16_t *map_1000;

void create_map1000() {
  map_1000 = new uint16_t[1000];
  for (size_t i = 0; i < 1000; i++) {
    uint32_t dig_1 = (i / 1) % 10;
    uint32_t dig_2 = (i / 10) % 10;
    uint32_t dig_3 = (i / 100) % 10;
    map_1000[i] = (dig_3 << 8) | (dig_2 << 4) | dig_1;
  }
}

constexpr int kSubscriberNum = 7000000;
constexpr int A = 1048575;

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

// transaction types
enum TxnType {
  kGetSubscriberData,
  kGetNewDestination,
  kGetAccessData,
  kUpdateSubscriberData,
  kUpdateLocation,
  kInsertCallForwarding,
  kDeleteCallForwarding,
};

// transaction frequencies
constexpr int kFreqGetSubscriberData = 35;
constexpr int kFreqGetAccessData = 35;
constexpr int kFreqGetNewDestination = 10;
constexpr int kFreqUpdateSubscriberData = 2;
constexpr int kFreqUpdateLocation = 14;
constexpr int kFreqInsertCallForwarding = 2;
constexpr int kFreqDeleteCallForwarding = 2;

// magic numbers for debugging
// these are unused in the spec
#define TATP_MAGIC 97	// some magic number <= 255
#define tatp_sub_msc_location_magic (TATP_MAGIC)
#define tatp_sec_sub_magic (TATP_MAGIC + 1)
#define tatp_accinf_data1_magic (TATP_MAGIC + 2)
#define tatp_specfac_data_b0_magic (TATP_MAGIC + 3)
#define tatp_callfwd_numberx0_magic (TATP_MAGIC + 4)

// TATP table keys and values
// All keys have been sized to 8 bytes
// All values have been sized to the next multiple of 8 bytes

/* A 64-bit encoding for 15-character decimal strings. */
union tatp_sub_nbr_t {
  struct {
    uint32_t dec_0 :4;
    uint32_t dec_1 :4;
    uint32_t dec_2 :4;
    uint32_t dec_3 :4;
    uint32_t dec_4 :4;
    uint32_t dec_5 :4;
    uint32_t dec_6 :4;
    uint32_t dec_7 :4;
    uint32_t dec_8 :4;
    uint32_t dec_9 :4;
    uint32_t dec_10 :4;
    uint32_t dec_11 :4;
    uint32_t dec_12 :4;
    uint32_t dec_13 :4;
    uint32_t dec_14 :4;
    uint32_t dec_15 :4;
  };

  struct {
    uint64_t dec_0_1_2 :12;
    uint64_t dec_3_4_5 :12;
    uint64_t dec_6_7_8 :12;
    uint64_t dec_9_10_11 :12;
    uint64_t unused :16;
  };
};

// /* Debug-only */
// static std::string tatp_sub_nbr_to_string(const tatp_sub_nbr_t &sub_nbr)
// {
// 	std::string ret;
// 	ret += std::to_string(sub_nbr.dec_14);
// 	ret += std::to_string(sub_nbr.dec_13);
// 	ret += std::to_string(sub_nbr.dec_12);
// 	ret += std::to_string(sub_nbr.dec_11);
// 	ret += std::to_string(sub_nbr.dec_10);
// 	ret += std::to_string(sub_nbr.dec_9);
// 	ret += std::to_string(sub_nbr.dec_8);
// 	ret += std::to_string(sub_nbr.dec_7);
// 	ret += std::to_string(sub_nbr.dec_6);
// 	ret += std::to_string(sub_nbr.dec_5);
// 	ret += std::to_string(sub_nbr.dec_4);
// 	ret += std::to_string(sub_nbr.dec_3);
// 	ret += std::to_string(sub_nbr.dec_2);
// 	ret += std::to_string(sub_nbr.dec_1);
// 	ret += std::to_string(sub_nbr.dec_0);

// 	printf("ret = %s\n", ret.c_str());
// 	return ret;
// }

static inline tatp_sub_nbr_t tatp_sid_to_sub_nbr(uint32_t s_id)
{
  tatp_sub_nbr_t sub_nbr;
  sub_nbr.dec_0_1_2 = map_1000[s_id % 1000];
  s_id /= 1000;
  sub_nbr.dec_3_4_5 = map_1000[s_id % 1000];
  s_id /= 1000;
  sub_nbr.dec_6_7_8 = map_1000[s_id % 1000];
  sub_nbr.dec_9_10_11 = 0;
  sub_nbr.unused = 0;

  return sub_nbr;
}

/*
 * SUBSCRIBER table
 * Primary key: <uint32_t s_id>
 * Value size: 40 bytes. Full value read in GET_SUBSCRIBER_DATA.
 */
union tatp_sub_key_t {
  struct {
    uint32_t s_id;
    uint8_t unused[4];
  };
  uint64_t key;
  tatp_sub_key_t() : key(0) {}
};

struct tatp_sub_val_t {
  tatp_sub_nbr_t sub_nbr;
  char sub_nbr_unused[7];	/* sub_nbr should be 15 bytes. We used 8 above. */
  char hex[5];
  char bytes[10];
  short bits;
  uint32_t msc_location;
  uint32_t vlr_location;
};

/*
 * Secondary SUBSCRIBER table
 * Key: <tatp_sub_nbr_t>
 * Value size: 8 bytes
 */
union tatp_sec_sub_key_t {
  tatp_sub_nbr_t sub_nbr;
  uint64_t key;
  tatp_sec_sub_key_t() : key(0) {}
};

struct tatp_sec_sub_val_t {
  uint32_t s_id;
  uint8_t magic;
  uint8_t unused[3];
};

/*
 * ACCESS INFO table
 * Primary key: <uint32_t s_id, uint8_t ai_type>
 * Value size: 16 bytes
 */
union tatp_accinf_key_t {
  struct {
    uint32_t s_id;
    uint8_t ai_type;
    uint8_t unused[3];
  };
  uint64_t key;
  tatp_accinf_key_t() : key(0) {}
};

struct tatp_accinf_val_t {
  char data1;
  char data2;
  char data3[3];
  char data4[5];
  uint8_t unused[6];
}; 

/*
 * SPECIAL FACILITY table
 * Primary key: <uint32_t s_id, uint8_t sf_type>
 * Value size: 8 bytes
 */
union tatp_specfac_key_t {
  struct {
    uint32_t s_id;
    uint8_t sf_type;
    uint8_t unused[3];
  };
  uint64_t key;
  tatp_specfac_key_t() : key(0) {}
};

struct tatp_specfac_val_t {
  char is_active;
  char error_cntl;
  char data_a;
  char data_b[5];
};

/*
 * CALL FORWARDING table
 * Primary key: <uint32_t s_id, uint8_t sf_type, uint8_t start_time>
 * Value size: 16 bytes
 */
union tatp_callfwd_key_t {
  struct {
    uint32_t s_id;
    uint8_t sf_type;
    uint8_t start_time;
    uint8_t unused[2];
  };
  uint64_t key;
  tatp_callfwd_key_t() : key(0) {}
};

struct tatp_callfwd_val_t {
  uint8_t end_time;
  char numberx[15];
};

// select values from a vector
static inline std::vector<uint8_t> select_between_n_and_m_from(uint64_t &tmp_seed,
      const std::vector<uint8_t> &values, unsigned N, unsigned M) {
  assert(M >= N);
  assert(M <= values.size());

  std::vector<uint8_t> ret;

  int used[32];
  memset(used, 0, 32 * sizeof(int));

  int to_select = (fastrand(&tmp_seed) % (M - N + 1)) + N;
  for (int i = 0; i < to_select; i++) {
    int index = fastrand(&tmp_seed) % values.size();
    uint8_t value = values[index];
    assert(value < 32);

    if (used[value] == 1) {
      i--;
      continue;
    }

    used[value] = 1;
    ret.push_back(value);
  }

  return ret;
}

// populate subscriber table
static inline void populate_subscriber_table(kvs *table) {
  uint64_t tmp_seed = 0xdeadbeef;

  for (uint32_t s_id = 0; s_id < kSubscriberNum; s_id++) {
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

    // pad the value
    auto val = new uint8_t[kValSize]();
    memcpy(val, &sub_val, sizeof(sub_val));
    kvs_insert(table, *(uint64_t *)&key, val);
  }
}

// populate secondary subscriber table
static inline void populate_second_subscriber_table(kvs *table) {
  for (uint32_t s_id = 0; s_id < kSubscriberNum; s_id++) {
    tatp_sec_sub_key_t key;
    key.sub_nbr = tatp_sid_to_sub_nbr(s_id);
    
    // initialize the subscriber payload
    tatp_sec_sub_val_t sec_sub_val;
    sec_sub_val.s_id = s_id;
    sec_sub_val.magic = tatp_sec_sub_magic;

    // pad the value
    auto val = new uint8_t[kValSize]();
    memcpy(val, &sec_sub_val, sizeof(sec_sub_val));
    kvs_insert(table, *(uint64_t *)&key, val);
  }
}

// populate access info table
static inline void populate_access_info_table(kvs *table) {
  std::vector<uint8_t> ai_type_values = {1, 2, 3, 4};

  uint64_t tmp_seed = 0xdeadbeef;

  for (uint32_t s_id = 0; s_id < kSubscriberNum; s_id++) {
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
      auto val = new uint8_t[kValSize]();
      memcpy(val, &accinf_val, sizeof(accinf_val));
      kvs_insert(table, *(uint64_t *)&key, val);
    }
  }
}

// populate special facility table
static inline void populate_specfac_and_callfwd_table(kvs *specfac_table, kvs *callfwd_table) {
  std::vector<uint8_t> sf_type_values = {1, 2, 3, 4};
  std::vector<uint8_t> start_time_values = {0, 8, 16};

  uint64_t tmp_seed = 0xdeadbeef;

  for (uint32_t s_id = 0; s_id < kSubscriberNum; s_id++) {
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

      // pad the value
      auto val = new uint8_t[kValSize]();
      memcpy(val, &specfac_val, sizeof(specfac_val));
      kvs_insert(specfac_table, *(uint64_t *)&key, val);

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

        // pad the value
        auto val = new uint8_t[kValSize]();
        memcpy(val, &callfwd_val, sizeof(callfwd_val));
        kvs_insert(callfwd_table, *(uint64_t *)&key, val);
      }	// loop start_time
    }	// loop sf_type
  }	// loop s_id
}
