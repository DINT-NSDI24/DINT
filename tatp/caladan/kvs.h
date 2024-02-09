// key-value store

#pragma once

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include "utils.h"

enum TableType {
  kSubscriber = 0,
  kSecondSubscriber = 1,
  kAccessInfo = 2,
  kSpecialFacility = 3,
  kCallForwarding = 4,
  kTableNum = 5,
};

constexpr int kMaxLogEntryNum = 1000000;
constexpr int kValSize = 40;
constexpr int kKeysPerEntry = 4;

struct log_entry {
  uint8_t is_del;          // 0: insert or set, 1: delete
  uint8_t table;           // table id
  uint64_t key;            // key
  uint8_t val[kValSize];   // value
  uint32_t ver;            // version
};

struct kvs_entry {
  uint64_t key[kKeysPerEntry];
  uint8_t val[kKeysPerEntry][kValSize];
  uint32_t ver[kKeysPerEntry];
  uint8_t valid[kKeysPerEntry];
  kvs_entry *next;
};

struct kvs {
  int hash_size;
  kvs_entry **bucket_heads;
  int *locks;
};

static inline void kvs_init(kvs *kvs, int hash_size) {
  kvs->hash_size = hash_size;
  kvs->bucket_heads = (kvs_entry **)calloc(hash_size, sizeof(kvs_entry *));
  kvs->locks = (int *)calloc(hash_size, sizeof(int));
}

static inline int kvs_hash(kvs *kvs, uint64_t key) {
  return (int)(fasthash64(&key, sizeof(key), 0xdeadbeef) % (uint64_t)kvs->hash_size);
}

static inline int kvs_get(kvs *kvs, uint64_t key, uint8_t *val, uint32_t *ver) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    for (int i = 0; i < kKeysPerEntry; i++) {
      if (head->key[i] == key && head->valid[i]) {
        memcpy(val, head->val[i], kValSize);
        *ver = head->ver[i];
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return 0;
      }
    }
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  return 1;
}

static inline int kvs_set(kvs *kvs, uint64_t key, uint8_t *val) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    for (int i = 0; i < kKeysPerEntry; i++) {
      if (head->key[i] == key && head->valid[i]) {
        memcpy(head->val[i], val, kValSize);
        head->ver[i]++;
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return 0;
      }
    }
    head = head->next;
  }
  panic("kvs_set: key not found");
}

static inline void kvs_insert(kvs *kvs, uint64_t key, uint8_t *val) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    for (int i = 0; i < kKeysPerEntry; i++) {
      if (!head->valid[i]) {
        head->key[i] = key;
        memcpy(head->val[i], val, kValSize);
        head->ver[i] = 0;
        head->valid[i] = 1;
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return;
      }
    }
    head = head->next;
  }
  kvs_entry *e = new kvs_entry;
  e->key[0] = key;
  memcpy(e->val[0], val, kValSize);
  e->ver[0] = 0;
  memset(e->valid, 0, sizeof(e->valid));
  e->valid[0] = 1;
  e->next = kvs->bucket_heads[hash];
  kvs->bucket_heads[hash] = e;
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
}

static inline void kvs_delete(kvs *kvs, uint64_t key) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  kvs_entry *head = kvs->bucket_heads[hash], *prev = nullptr;
  while (head) {
    for (int i = 0; i < kKeysPerEntry; i++) {
      if (head->key[i] == key && head->valid[i]) {
        head->valid[i] = 0;
        // if all keys in this entry are invalid, delete the entry
        bool all_invalid = true;
        for (int j = 0; j < kKeysPerEntry; j++) {
          if (head->valid[j]) {
            all_invalid = false;
            break;
          }
        }
        if (all_invalid) {
          if (prev) prev->next = head->next;
          else kvs->bucket_heads[hash] = head->next;
          delete head;
        }
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return;
      }
    }
    prev = head;
    head = head->next;
  }
  panic("kvs_delete: key not found");
}
