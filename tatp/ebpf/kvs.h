// key-value store

#ifndef _KVS_H_
#define _KVS_H_

#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define MAX_LOG_ENTRY_NUM 1000000

struct kvs_entry {
  uint64_t key[KEYS_PER_ENTRY];
  uint8_t val[KEYS_PER_ENTRY][VAL_SIZE];
  uint32_t ver[KEYS_PER_ENTRY];
  uint8_t valid[KEYS_PER_ENTRY];
  struct kvs_entry *next;
};

struct kvs {
  int hash_size;
  struct kvs_entry **bucket_heads;
  int *locks;
};

static inline void kvs_init(struct kvs *kvs, int hash_size) {
  kvs->hash_size = hash_size;
  kvs->bucket_heads = calloc(hash_size, sizeof(struct kvs_entry *));
  kvs->locks = calloc(hash_size, sizeof(int));
}

static inline uint32_t kvs_hash(struct kvs *kvs, uint64_t key) {
  return (uint32_t)(fasthash64(&key, sizeof(key), 0xdeadbeef) % (uint64_t)kvs->hash_size);
}

static inline int kvs_get(struct kvs *kvs, uint64_t key, uint8_t *val, uint32_t *ver) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    for (int i = 0; i < KEYS_PER_ENTRY; i++) {
      if (head->key[i] == key && head->valid[i]) {
        memcpy(val, head->val[i], VAL_SIZE);
        *ver = head->ver[i];
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return 0;
      }
    }
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  return 1; // not found
}

static inline void kvs_insert(struct kvs *kvs, uint64_t key, uint8_t *val) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    for (int i = 0; i < KEYS_PER_ENTRY; i++) {
      if (!head->valid[i]) {
        head->key[i] = key;
        memcpy(head->val[i], val, VAL_SIZE);
        head->ver[i] = 0;
        head->valid[i] = 1;
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return;
      }
    }
    head = head->next;
  }
  struct kvs_entry *e = calloc(1, sizeof(struct kvs_entry));
  e->key[0] = key;
  memcpy(e->val[0], val, VAL_SIZE);
  e->ver[0] = 0;
  e->valid[0] = 1;
  e->next = kvs->bucket_heads[hash];
  kvs->bucket_heads[hash] = e;
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
}

static inline uint32_t kvs_set(struct kvs *kvs, uint64_t key, uint8_t *val, uint32_t ver) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *head = kvs->bucket_heads[hash];
  while (head) {
    for (int i = 0; i < KEYS_PER_ENTRY; i++) {
      if (head->key[i] == key && head->valid[i]) {
        memcpy(head->val[i], val, VAL_SIZE);
        if (ver != 0) head->ver[i] = ver;
        else head->ver[i]++;
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return head->ver[i];
      }
    }
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
  kvs_insert(kvs, key, val);
  return 0;
}

static inline void kvs_delete(struct kvs *kvs, uint64_t key) {
  uint32_t hash = kvs_hash(kvs, key);
  while (__sync_lock_test_and_set(&kvs->locks[hash], 1));

  struct kvs_entry *head = kvs->bucket_heads[hash], *prev = NULL;
  while (head) {
    for (int i = 0; i < KEYS_PER_ENTRY; i++) {
      if (head->key[i] == key && head->valid[i]) {
        head->valid[i] = 0;
        int all_invalid = 1;
        for (int j = 0; j < KEYS_PER_ENTRY; j++) {
          if (head->valid[j]) {
            all_invalid = 0;
            break;
          }
        }
        if (all_invalid) {
          if (prev) prev->next = head->next;
          else kvs->bucket_heads[hash] = head->next;
          free(head);
        }
        __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
        return;
      }
    }
    prev = head;
    head = head->next;
  }
  __sync_val_compare_and_swap(&kvs->locks[hash], 1, 0);
}

#endif // _KVS_H_