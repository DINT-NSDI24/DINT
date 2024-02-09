#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "linux/tools/lib/bpf/bpf_helpers.h"

#include "utils.h"

char LICENSE[] SEC("license") = "GPL";

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
  __type(value, struct cache_entry);
  __uint(max_entries, KVS_HASH_SIZE);
} map_cache SEC(".maps");

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
  if (msg->type != READ && msg->type != SET && msg->type != INSERT) 
    return XDP_PASS;

  uint64_t hash = fasthash64(&msg->key, sizeof(msg->key), 0xdeadbeef);

  if (msg->type == READ) {
    uint32_t kvs_hash = (uint32_t)(hash % (uint64_t)KVS_HASH_SIZE);
    struct cache_entry *e = bpf_map_lookup_elem(&map_cache, &kvs_hash);
    if (!e) return XDP_PASS;

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

      __sync_val_compare_and_swap(&e->lock, 1, 0);

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
      if (idx == KEYS_PER_ENTRY) idx = 0;
      ext_msg->idx = idx;

      return XDP_PASS;
    }
  }

  else if (msg->type == SET) {
    uint32_t kvs_hash = (uint32_t)(hash % (uint64_t)KVS_HASH_SIZE);
    struct cache_entry *e = bpf_map_lookup_elem(&map_cache, &kvs_hash);
    if (!e) return XDP_PASS;

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_SET;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    int idx;
    for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
      if (e->key[idx] == msg->key && e->valid[idx] == 1) break;
    }
    
    if (idx < KEYS_PER_ENTRY) e->valid[idx] = 0;

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

    return XDP_PASS;
  }

  else if (msg->type == INSERT) {
    uint32_t kvs_hash = (uint32_t)(hash % (uint64_t)KVS_HASH_SIZE);
    struct cache_entry *e = bpf_map_lookup_elem(&map_cache, &kvs_hash);
    if (!e) return XDP_PASS;

    uint64_t ret = __sync_val_compare_and_swap(&e->lock, 0, 1);
    if (ret == 1) {
      msg->type = REJECT_SET;
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }

    int idx;
    for (idx = 0; idx < KEYS_PER_ENTRY; idx++) {
      if (e->valid[idx] == 0) break;
    }

    if (idx < KEYS_PER_ENTRY) {
      e->key[idx] = msg->key;
      memcpy(e->val[idx], msg->val, VAL_SIZE);
      e->ver[idx] = msg->ver;
      e->dirty[idx] = 0;
      e->valid[idx] = 1;
    }

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

    return XDP_PASS;
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
  if (ext_msg + 1 > data_end) return TC_ACT_OK; // INSERT_ACK passed through

  uint64_t hash = fasthash64(&ext_msg->key1, sizeof(ext_msg->key1), 0xdeadbeef);

  if (ext_msg->type == GRANT_READ) {
    uint32_t kvs_hash = (uint32_t)(hash % (uint64_t)KVS_HASH_SIZE);
    struct cache_entry *e = bpf_map_lookup_elem(&map_cache, &kvs_hash);
    if (!e) return TC_ACT_OK;
    
    int idx = ext_msg->idx;
    if (idx >= KEYS_PER_ENTRY) return TC_ACT_OK;
    e->key[idx] = ext_msg->key1;
    memcpy(e->val[idx], ext_msg->val1, VAL_SIZE);
    e->ver[idx] = ext_msg->ver1;
    e->valid[idx] = 1;

    __sync_val_compare_and_swap(&e->lock, 1, 0);
  }

  else if (ext_msg->type == SET_ACK || ext_msg->type == NOT_EXIST || ext_msg->type == INSERT_ACK) {
    uint32_t kvs_hash = (uint32_t)(hash % (uint64_t)KVS_HASH_SIZE);
    struct cache_entry *e = bpf_map_lookup_elem(&map_cache, &kvs_hash);
    if (!e) return TC_ACT_OK;

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