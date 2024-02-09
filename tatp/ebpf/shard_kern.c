#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "linux/tools/lib/bpf/bpf_helpers.h"

#include "utils.h"

char LICENSE[] SEC("license") = "GPL";
static const uint32_t zero = 0;

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, uint32_t);
  __type(value, uint32_t);
  __uint(max_entries, MAX_PROG_NUM);
} map_progs_xdp SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, uint32_t);
  __type(value, uint32_t);
  __uint(max_entries, MAX_PROG_NUM);
} map_progs_tc SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, uint64_t);
  __uint(max_entries, SUB_HASH_SIZE*KEYS_PER_ENTRY);
} map_locks_sub SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, uint64_t);
  __uint(max_entries, SEC_SUB_HASH_SIZE*KEYS_PER_ENTRY);
} map_locks_sec_sub SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, uint64_t);
  __uint(max_entries, AI_HASH_SIZE*KEYS_PER_ENTRY);
} map_locks_ai SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, uint64_t);
  __uint(max_entries, SF_HASH_SIZE*KEYS_PER_ENTRY);
} map_locks_sf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, uint64_t);
  __uint(max_entries, CF_HASH_SIZE*KEYS_PER_ENTRY);
} map_locks_cf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, struct cache_entry);
  __uint(max_entries, SUB_HASH_SIZE);
} map_cache_sub SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, struct cache_entry);
  __uint(max_entries, SEC_SUB_HASH_SIZE);
} map_cache_sec_sub SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, struct cache_entry);
  __uint(max_entries, AI_HASH_SIZE);
} map_cache_ai SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, struct cache_entry);
  __uint(max_entries, SF_HASH_SIZE);
} map_cache_sf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, struct cache_entry);
  __uint(max_entries, CF_HASH_SIZE);
} map_cache_cf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, uint32_t);
  __type(value, struct log_entry);
  __uint(max_entries, MAX_LOG_ENTRY_NUM);
} map_log SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, uint32_t);
  __type(value, uint32_t);
  __uint(max_entries, 1);
} map_log_cnt SEC(".maps");

SEC("tps_prim_xdp")
int tps_prim_xdp_main(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if (eth + 1 > data_end) return XDP_PASS;

  struct iphdr *ip = data + sizeof(*eth);
  if (ip + 1 > data_end) return XDP_PASS;

  void *transp = data + sizeof(*eth) + sizeof(*ip);
  struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
  if (udp + 1 > data_end) return XDP_PASS;

  char *payload = transp + sizeof(*udp);
  struct message *msg = (struct message *)payload;
  if (msg + 1 > data_end) return XDP_PASS;

  if (udp->dest != htons(FASST_PORT)) return XDP_PASS;
  if (msg->type != READ && msg->type != ACQUIRE_LOCK &&
      msg->type != ABORT && msg->type != COMMIT_PRIM &&
      msg->type != INSERT_PRIM && msg->type != DELETE_PRIM &&
      msg->type != COMMIT_BCK && msg->type != INSERT_BCK &&
      msg->type != DELETE_BCK && msg->type != COMMIT_LOG && 
      msg->type != DELETE_LOG) 
    return XDP_PASS;

  uint64_t hash = fasthash64(&msg->key, sizeof(msg->key), 0xdeadbeef);

  if (msg->type == READ) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_READ;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    int idx;
    for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
      if (e->key[idx] == msg->key && e->valid[idx] == 1) break;
    }

    if (idx < KEYS_PER_ENTRY) {
      msg->type = GRANT_READ;
      msg->ver = e->ver[idx];
      memcpy(msg->val, e->val[idx], VAL_SIZE);

      // update bloom filter
      int bf_hash = (int)((hash & 0xfc00000000000000UL) >> 58);
      e->bloom_filter |= (1UL << bf_hash);

      __sync_val_compare_and_swap(&e->lock, 1, 0);

      prepare_packet(eth, ip, udp);
      return XDP_TX;
    } else {
      int bf_hash = (int)((hash & 0xfc00000000000000UL) >> 58);
      if ((e->bloom_filter & (1UL << bf_hash)) == 0) {
        // bloom filter says the key does not exist
        __sync_val_compare_and_swap(&e->lock, 1, 0);
        msg->type = NOT_EXIST;
        prepare_packet(eth, ip, udp);
        return XDP_TX;
      } else {
        bpf_xdp_adjust_tail(ctx, sizeof(struct ext_message)-sizeof(struct message));
        data_end = (void *)(long)ctx->data_end;
        data = (void *)(long)ctx->data;

        eth = data;
        if (eth + 1 > data_end) return XDP_PASS;

        ip = data + sizeof(*eth);
        if (ip + 1 > data_end) return XDP_PASS;

        transp = data + sizeof(*eth) + sizeof(*ip);
        udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
        if (udp + 1 > data_end) return XDP_PASS;

        adjust_packet_len(ip, udp, (int)(sizeof(struct ext_message))-(int)(sizeof(struct message)));

        payload = transp + sizeof(*udp);
        struct ext_message *ext_msg = (struct ext_message *)payload;
        if (ext_msg + 1 > data_end) return XDP_PASS;

        int idx;
        for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
          if (e->valid[idx] == 0) break;
        }
        if (idx == KEYS_PER_ENTRY) {
          for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
            if (e->dirty[idx] == 0) break;
          }
        }
        if (idx == KEYS_PER_ENTRY) idx = 0;
        ext_msg->idx = idx;

        if (e->valid[idx] == 1 && e->dirty[idx] == 1) {
          ext_msg->key2 = e->key[idx];
          memcpy(ext_msg->val2, e->val[idx], VAL_SIZE);
          ext_msg->ver2 = e->ver[idx];
          ext_msg->ver1 = 1;
        } else ext_msg->ver1 = 0;

        return XDP_PASS;
      }
    }
  }

  else if (msg->type == ACQUIRE_LOCK) {
    uint64_t *lock;
    uint32_t lock_hash;
    switch (msg->table) {
      case SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sub, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SEC_SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sec_sub, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case ACCESS_INFO:
        lock_hash = (uint32_t)(hash % (uint64_t)(AI_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_ai, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        lock_hash = (uint32_t)(hash % (uint64_t)(SF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sf, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        lock_hash = (uint32_t)(hash % (uint64_t)(CF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_cf, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(lock, 0, 1);
    if (ret == 0) {
      msg->type = GRANT_LOCK;
      
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    } else if (ret == 1) {
      msg->type = REJECT_LOCK;
      
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }
  }

  else if (msg->type == ABORT) {
    uint64_t *lock;
    uint32_t lock_hash;
    switch (msg->table) {
      case SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sub, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SEC_SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sec_sub, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case ACCESS_INFO:
        lock_hash = (uint32_t)(hash % (uint64_t)(AI_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_ai, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        lock_hash = (uint32_t)(hash % (uint64_t)(SF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sf, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        lock_hash = (uint32_t)(hash % (uint64_t)(CF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_cf, &lock_hash);
        if (!lock) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    __sync_val_compare_and_swap(lock, 1, 0);
    msg->type = ABORT_ACK;
    
    prepare_packet(eth, ip, udp);
    return XDP_TX;
  }

  else if (msg->type == COMMIT_PRIM) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_COMMIT;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    int idx;
    for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
      if (e->key[idx] == msg->key && e->valid[idx] == 1) break;
    }
    
    if (idx < KEYS_PER_ENTRY) {
      uint64_t *lock;
      uint32_t lock_hash;
      switch (msg->table) {
        case SUBSCRIBER:
          lock_hash = (uint32_t)(hash % (uint64_t)(SUB_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_sub, &lock_hash);
          if (!lock) return XDP_PASS;
          break;
        case SECOND_SUBSCRIBER:
          lock_hash = (uint32_t)(hash % (uint64_t)(SEC_SUB_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_sec_sub, &lock_hash);
          if (!lock) return XDP_PASS;
          break;
        case ACCESS_INFO:
          lock_hash = (uint32_t)(hash % (uint64_t)(AI_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_ai, &lock_hash);
          if (!lock) return XDP_PASS;
          break;
        case SPECIAL_FACILITY:
          lock_hash = (uint32_t)(hash % (uint64_t)(SF_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_sf, &lock_hash);
          if (!lock) return XDP_PASS;
          break;
        case CALL_FORWARDING:
          lock_hash = (uint32_t)(hash % (uint64_t)(CF_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_cf, &lock_hash);
          if (!lock) return XDP_PASS;
          break;
        default:
          return XDP_PASS;
      }

      __sync_val_compare_and_swap(lock, 1, 0);

      // using memcpy here would cause exceeded stack space
      // this happens only with VAL_SIZE >= 64
      memcpy(e->val[idx], msg->val, VAL_SIZE);

      e->ver[idx]++;
      e->dirty[idx] = 1;
      __sync_val_compare_and_swap(&e->lock, 1, 0);

      msg->type = COMMIT_PRIM_ACK;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    } else {
      bpf_xdp_adjust_tail(ctx, sizeof(struct ext_message)-sizeof(struct message));
      data_end = (void *)(long)ctx->data_end;
      data = (void *)(long)ctx->data;

      eth = data;
      if (eth + 1 > data_end) return XDP_PASS;

      ip = data + sizeof(*eth);
      if (ip + 1 > data_end) return XDP_PASS;

      transp = data + sizeof(*eth) + sizeof(*ip);
      udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
      if (udp + 1 > data_end) return XDP_PASS;

      adjust_packet_len(ip, udp, (int)(sizeof(struct ext_message))-(int)(sizeof(struct message)));

      payload = transp + sizeof(*udp);
      struct ext_message *ext_msg = (struct ext_message *)payload;
      if (ext_msg + 1 > data_end) return XDP_PASS;

      int idx;
      for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
        if (e->valid[idx] == 0) break;
      }
      if (idx == KEYS_PER_ENTRY) {
        for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
          if (e->dirty[idx] == 0) break;
        }
      }
      if (idx == KEYS_PER_ENTRY) idx = 0;
      ext_msg->idx = idx;

      if (e->valid[idx] == 1 && e->dirty[idx] == 1) {
        ext_msg->key2 = e->key[idx];
        memcpy(ext_msg->val2, e->val[idx], VAL_SIZE);
        ext_msg->ver2 = e->ver[idx];
        ext_msg->ver1 = 1;
      } else ext_msg->ver1 = 0;

      e->key[idx] = ext_msg->key1;
      memcpy(e->val[idx], ext_msg->val1, VAL_SIZE);
      e->dirty[idx] = 0;
      return XDP_PASS;
    }
  }

  else if (msg->type == INSERT_PRIM) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_COMMIT;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    int bf_hash = (int)((hash & 0xfc00000000000000UL) >> 58);
    e->bloom_filter |= (1UL << bf_hash);

    int idx;
    for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
      if (e->valid[idx] == 0) break;
    }
    if (idx == KEYS_PER_ENTRY) {
      for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
        if (e->dirty[idx] == 0) break;
      }
    }
    if (idx == KEYS_PER_ENTRY) idx = 0;

    if (e->valid[idx] == 1 && e->dirty[idx] == 1) {
      // evict, insert and set in user space
      bpf_xdp_adjust_tail(ctx, sizeof(struct ext_message)-sizeof(struct message));
      data_end = (void *)(long)ctx->data_end;
      data = (void *)(long)ctx->data;

      eth = data;
      if (eth + 1 > data_end) return XDP_PASS;

      ip = data + sizeof(*eth);
      if (ip + 1 > data_end) return XDP_PASS;

      transp = data + sizeof(*eth) + sizeof(*ip);
      udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
      if (udp + 1 > data_end) return XDP_PASS;

      adjust_packet_len(ip, udp, (int)(sizeof(struct ext_message))-(int)(sizeof(struct message)));

      payload = transp + sizeof(*udp);
      struct ext_message *ext_msg = (struct ext_message *)payload;
      if (ext_msg + 1 > data_end) return XDP_PASS;

      ext_msg->key2 = e->key[idx];
      memcpy(ext_msg->val2, e->val[idx], VAL_SIZE);
      ext_msg->ver2 = e->ver[idx];
      ext_msg->idx = idx;

      e->key[idx] = ext_msg->key1;
      memcpy(e->val[idx], ext_msg->val1, VAL_SIZE);
      e->ver[idx] = 0;
      e->dirty[idx] = 0;
      return XDP_PASS;
    } else {
      // no evict, update cache and set dirty bit
      e->key[idx] = msg->key;
      memcpy(e->val[idx], msg->val, VAL_SIZE);
      e->ver[idx] = 0;
      e->valid[idx] = 1;
      e->dirty[idx] = 1;

      uint64_t *lock;
      uint32_t lock_hash;
      switch (msg->table) {
        case SUBSCRIBER:
          lock_hash = (uint32_t)(hash % (uint64_t)(SUB_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_sub, &lock_hash);
          if (!lock) return TC_ACT_OK;
          break;
        case SECOND_SUBSCRIBER:
          lock_hash = (uint32_t)(hash % (uint64_t)(SEC_SUB_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_sec_sub, &lock_hash);
          if (!lock) return TC_ACT_OK;
          break;
        case ACCESS_INFO:
          lock_hash = (uint32_t)(hash % (uint64_t)(AI_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_ai, &lock_hash);
          if (!lock) return TC_ACT_OK;
          break;
        case SPECIAL_FACILITY:
          lock_hash = (uint32_t)(hash % (uint64_t)(SF_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_sf, &lock_hash);
          if (!lock) return TC_ACT_OK;
          break;
        case CALL_FORWARDING:
          lock_hash = (uint32_t)(hash % (uint64_t)(CF_HASH_SIZE*KEYS_PER_ENTRY));
          lock = bpf_map_lookup_elem(&map_locks_cf, &lock_hash);
          if (!lock) return TC_ACT_OK;
          break;
        default:
          return TC_ACT_OK;
      }

      __sync_val_compare_and_swap(lock, 1, 0);
      __sync_val_compare_and_swap(&e->lock, 1, 0);
      msg->type = INSERT_PRIM_ACK;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }
  }

  else if (msg->type == DELETE_PRIM) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_COMMIT;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    for (int i = 0; i < KEYS_PER_ENTRY; i++) {
      if (e->key[i] == msg->key && e->valid[i] == 1) {
        e->valid[i] = 0;
        break;
      }
    }
    return XDP_PASS;
  }

  else if (msg->type == COMMIT_BCK) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_COMMIT;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    int idx;
    for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
      if (e->key[idx] == msg->key && e->valid[idx] == 1) break;
    }
    
    if (idx < KEYS_PER_ENTRY) {
      // using memcpy here would cause exceeded stack space
      // this happens only with VAL_SIZE >= 64
      memcpy(e->val[idx], msg->val, VAL_SIZE);

      e->ver[idx]++;
      e->dirty[idx] = 1;
      __sync_val_compare_and_swap(&e->lock, 1, 0);

      msg->type = COMMIT_BCK_ACK;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    } else {
      bpf_xdp_adjust_tail(ctx, sizeof(struct ext_message)-sizeof(struct message));
      data_end = (void *)(long)ctx->data_end;
      data = (void *)(long)ctx->data;

      eth = data;
      if (eth + 1 > data_end) return XDP_PASS;

      ip = data + sizeof(*eth);
      if (ip + 1 > data_end) return XDP_PASS;

      transp = data + sizeof(*eth) + sizeof(*ip);
      udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
      if (udp + 1 > data_end) return XDP_PASS;

      adjust_packet_len(ip, udp, (int)(sizeof(struct ext_message))-(int)(sizeof(struct message)));

      payload = transp + sizeof(*udp);
      struct ext_message *ext_msg = (struct ext_message *)payload;
      if (ext_msg + 1 > data_end) return XDP_PASS;

      int idx;
      for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
        if (e->valid[idx] == 0) break;
      }
      if (idx == KEYS_PER_ENTRY) {
        for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
          if (e->dirty[idx] == 0) break;
        }
      }
      if (idx == KEYS_PER_ENTRY) idx = 0;
      ext_msg->idx = idx;

      if (e->valid[idx] == 1 && e->dirty[idx] == 1) {
        ext_msg->key2 = e->key[idx];
        memcpy(ext_msg->val2, e->val[idx], VAL_SIZE);
        ext_msg->ver2 = e->ver[idx];
        ext_msg->ver1 = 1;
      } else ext_msg->ver1 = 0;

      e->key[idx] = ext_msg->key1;
      memcpy(e->val[idx], ext_msg->val1, VAL_SIZE);
      e->dirty[idx] = 0;
      return XDP_PASS;
    }
  }

  else if (msg->type == INSERT_BCK) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_COMMIT;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    int bf_hash = (int)((hash & 0xfc00000000000000UL) >> 58);
    e->bloom_filter |= (1UL << bf_hash);

    int idx;
    for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
      if (e->valid[idx] == 0) break;
    }
    if (idx == KEYS_PER_ENTRY) {
      for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
        if (e->dirty[idx] == 0) break;
      }
    }
    if (idx == KEYS_PER_ENTRY) idx = 0;

    if (e->valid[idx] == 1 && e->dirty[idx] == 1) {
      // evict, insert and set in user space
      bpf_xdp_adjust_tail(ctx, sizeof(struct ext_message)-sizeof(struct message));
      data_end = (void *)(long)ctx->data_end;
      data = (void *)(long)ctx->data;

      eth = data;
      if (eth + 1 > data_end) return XDP_PASS;

      ip = data + sizeof(*eth);
      if (ip + 1 > data_end) return XDP_PASS;

      transp = data + sizeof(*eth) + sizeof(*ip);
      udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
      if (udp + 1 > data_end) return XDP_PASS;

      adjust_packet_len(ip, udp, (int)(sizeof(struct ext_message))-(int)(sizeof(struct message)));

      payload = transp + sizeof(*udp);
      struct ext_message *ext_msg = (struct ext_message *)payload;
      if (ext_msg + 1 > data_end) return XDP_PASS;

      ext_msg->key2 = e->key[idx];
      memcpy(ext_msg->val2, e->val[idx], VAL_SIZE);
      ext_msg->ver2 = e->ver[idx];
      ext_msg->idx = idx;

      e->key[idx] = ext_msg->key1;
      memcpy(e->val[idx], ext_msg->val1, VAL_SIZE);
      e->ver[idx] = 0;
      e->dirty[idx] = 0;
      return XDP_PASS;
    } else {
      // no evict, update cache and set dirty bit
      e->key[idx] = msg->key;
      memcpy(e->val[idx], msg->val, VAL_SIZE);
      e->ver[idx] = 0;
      e->valid[idx] = 1;
      e->dirty[idx] = 1;

      __sync_val_compare_and_swap(&e->lock, 1, 0);
      msg->type = INSERT_BCK_ACK;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }
    return XDP_PASS;
  }

  else if (msg->type == DELETE_BCK) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return XDP_PASS;
        break;
      default:
        return XDP_PASS;
    }

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_COMMIT;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    for (int i = 0; i < KEYS_PER_ENTRY; ++i) {
      if (e->key[i] == msg->key && e->valid[i] == 1) {
        e->valid[i] = 0;
        break;
      }
    }
    return XDP_PASS;
  }
  
  else if (msg->type == COMMIT_LOG || msg->type == DELETE_LOG) {
    uint32_t *log_cnt = bpf_map_lookup_elem(&map_log_cnt, &zero);
    if (!log_cnt) return XDP_PASS;
    struct log_entry *log_entry = bpf_map_lookup_elem(&map_log, log_cnt);
    if (!log_entry) return XDP_PASS;

    if (msg->type == COMMIT_LOG) log_entry->is_del = 0;
    else log_entry->is_del = 1;

    log_entry->table = msg->table;
    log_entry->key = msg->key;
    if (msg->type == COMMIT_LOG) memcpy(log_entry->val, msg->val, VAL_SIZE);
    log_entry->ver = msg->ver;

    (*log_cnt)++;
    if (*log_cnt == MAX_LOG_ENTRY_NUM) *log_cnt = 0;

    if (msg->type == COMMIT_LOG) msg->type = COMMIT_LOG_ACK;
    else msg->type = DELETE_LOG_ACK;

    prepare_packet(eth, ip, udp);
    return XDP_TX;
  }

  return XDP_PASS;
}

SEC("tps_prim_tc")
int tps_prim_tc_main(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  if (eth + 1 > data_end) return TC_ACT_OK;

  struct iphdr *ip = data + sizeof(*eth);
  if (ip + 1 > data_end) return TC_ACT_OK;

  void *transp = data + sizeof(*eth) + sizeof(*ip);
  struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
  if (udp + 1 > data_end) return TC_ACT_OK;

  __be16 sport = udp->source;
  if (sport != htons(FASST_PORT)) return TC_ACT_OK;

  char *payload = transp + sizeof(*udp);
  struct ext_message *ext_msg = (struct ext_message *)payload;
  if (ext_msg + 1 > data_end) return TC_ACT_OK;

  uint64_t hash = fasthash64(&ext_msg->key1, sizeof(ext_msg->key1), 0xdeadbeef);

  if (ext_msg->type == GRANT_READ) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }
    
    int idx = ext_msg->idx;
    if (idx >= KEYS_PER_ENTRY) return TC_ACT_OK;
    e->key[idx] = ext_msg->key1;
    memcpy(e->val[idx], ext_msg->val1, VAL_SIZE);
    e->ver[idx] = ext_msg->ver1;
    e->dirty[idx] = 0;
    e->valid[idx] = 1;

    // update bloom filter
    int bf_hash = (int)((hash & 0xfc00000000000000UL) >> 58);
    e->bloom_filter |= (1UL << bf_hash);

    __sync_val_compare_and_swap(&e->lock, 1, 0);
  }

  else if (ext_msg->type == NOT_EXIST) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }
    __sync_val_compare_and_swap(&e->lock, 1, 0);
  }
  
  else if (ext_msg->type == COMMIT_PRIM_ACK) {
    uint64_t *lock;
    uint32_t lock_hash;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sub, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SEC_SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sec_sub, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        lock_hash = (uint32_t)(hash % (uint64_t)(AI_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_ai, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        lock_hash = (uint32_t)(hash % (uint64_t)(SF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sf, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        lock_hash = (uint32_t)(hash % (uint64_t)(CF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_cf, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }
    
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }

    __sync_val_compare_and_swap(lock, 1, 0);

    int idx = ext_msg->idx;
    if (idx >= KEYS_PER_ENTRY) return TC_ACT_OK;
    e->ver[idx] = ext_msg->ver1;
    e->valid[idx] = 1;
    __sync_val_compare_and_swap(&e->lock, 1, 0);
  }

  else if (ext_msg->type == INSERT_PRIM_ACK || ext_msg->type == DELETE_PRIM_ACK) {
    uint64_t *lock;
    uint32_t lock_hash;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sub, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        lock_hash = (uint32_t)(hash % (uint64_t)(SEC_SUB_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sec_sub, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        lock_hash = (uint32_t)(hash % (uint64_t)(AI_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_ai, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        lock_hash = (uint32_t)(hash % (uint64_t)(SF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_sf, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        lock_hash = (uint32_t)(hash % (uint64_t)(CF_HASH_SIZE*KEYS_PER_ENTRY));
        lock = bpf_map_lookup_elem(&map_locks_cf, &lock_hash);
        if (!lock) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }

    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }

    if (ext_msg->type == DELETE_PRIM_ACK)
      e->bloom_filter = *(uint64_t *)ext_msg->val1;

    __sync_val_compare_and_swap(lock, 1, 0);
    __sync_val_compare_and_swap(&e->lock, 1, 0);
  }

  else if (ext_msg->type == COMMIT_BCK_ACK) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }

    int idx = ext_msg->idx;
    if (idx >= KEYS_PER_ENTRY) return TC_ACT_OK;
    e->ver[idx] = ext_msg->ver1;
    e->valid[idx] = 1;
    __sync_val_compare_and_swap(&e->lock, 1, 0);
    return TC_ACT_OK;
  }

  else if (ext_msg->type == INSERT_BCK_ACK || ext_msg->type == DELETE_BCK_ACK) {
    uint32_t kvs_hash;
    struct cache_entry *e;
    switch (ext_msg->table) {
      case SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SECOND_SUBSCRIBER:
        kvs_hash = (uint32_t)(hash % (uint64_t)SEC_SUB_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sec_sub, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case ACCESS_INFO:
        kvs_hash = (uint32_t)(hash % (uint64_t)AI_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_ai, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case SPECIAL_FACILITY:
        kvs_hash = (uint32_t)(hash % (uint64_t)SF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_sf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      case CALL_FORWARDING:
        kvs_hash = (uint32_t)(hash % (uint64_t)CF_HASH_SIZE);
        e = bpf_map_lookup_elem(&map_cache_cf, &kvs_hash);
        if (!e) return TC_ACT_OK;
        break;
      default:
        return TC_ACT_OK;
    }

    if (ext_msg->type == DELETE_BCK_ACK)
      e->bloom_filter = *(uint64_t *)ext_msg->val1;

    __sync_val_compare_and_swap(&e->lock, 1, 0);
  }

  bpf_skb_change_tail(skb, skb->len + sizeof(struct message)-sizeof(struct ext_message), 0);

  data_end = (void *)(long)skb->data_end;
  data = (void *)(long)skb->data;
  eth = data;
  if (eth + 1 > data_end) return TC_ACT_OK;

  ip = data + sizeof(*eth);
  if (ip + 1 > data_end) return TC_ACT_OK;

  transp = data + sizeof(*eth) + sizeof(*ip);
  udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
  if (udp + 1 > data_end) return TC_ACT_OK;

  adjust_packet_len(ip, udp, (int)(sizeof(struct message))-(int)(sizeof(struct ext_message)));
  return TC_ACT_OK;
}