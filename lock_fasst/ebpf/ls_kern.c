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
  __type(value, struct lock_unit);
  __uint(max_entries, LOCK_HASH_SIZE);
} map_lock_units SEC(".maps");

SEC("ls_xdp")
int ls_xdp_main(struct xdp_md *ctx) {
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

  uint64_t hash = fasthash64(&msg->lid, sizeof(msg->lid), 0xdeadbeef);
  uint32_t lock_hash = (uint32_t)(hash % (uint64_t)LOCK_HASH_SIZE);
  struct lock_unit *lu = bpf_map_lookup_elem(&map_lock_units, &lock_hash);
  if (!lu) return XDP_PASS;

  if (msg->type == READ) {
    msg->type = GRANT_READ;
    msg->ver = lu->ver;
    
    prepare_packet(eth, ip, udp);
    return XDP_TX;
  }

  else if (msg->type == ACQUIRE_LOCK) {
    uint64_t ret = __sync_val_compare_and_swap(&lu->lock, 0, 1);

    if (ret == 0) {
      msg->type = GRANT_LOCK;
      
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    } else if (ret == 1) {
      msg->type = REJECT_LOCK;
      
      prepare_packet(eth, ip, udp);
      return XDP_TX;
    }
    return XDP_PASS;
  }


  else if (msg->type == ABORT) {
    __sync_val_compare_and_swap(&lu->lock, 1, 0);
    msg->type = ABORT_ACK;
    prepare_packet(eth, ip, udp);
    return XDP_TX;
  }

  else if (msg->type == COMMIT) {
    lu->ver++;
    __sync_val_compare_and_swap(&lu->lock, 1, 0);
    msg->type = COMMIT_ACK;
    prepare_packet(eth, ip, udp);
    return XDP_TX;
  }

  return XDP_PASS;
}
