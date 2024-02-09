// #include <stdint.h>
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

  if (udp->dest != htons(MAGIC_PORT)) return XDP_PASS;

  uint64_t hash = fasthash64(&msg->lid, sizeof(msg->lid), 0xdeadbeef);
  uint32_t lock_hash = (uint32_t)(hash % (uint64_t)LOCK_HASH_SIZE);
  struct lock_unit *lu = bpf_map_lookup_elem(&map_lock_units, &lock_hash);
  if (!lu) return XDP_PASS;

  uint64_t ret = __sync_val_compare_and_swap(&lu->lock, 0, 1);
  if (ret == 1) {
    msg->action = RETRY;
    prepare_packet(eth, ip, udp);
    return XDP_TX;
  }

  if (msg->action == ACQUIRE_LOCK) {
    if (msg->type == SHARED_LOCK) {
      if (lu->num_ex > 0) {
        __sync_val_compare_and_swap(&lu->lock, 1, 0);
        msg->action = REJECT_LOCK;
        prepare_packet(eth, ip, udp);
        return XDP_TX;
      } else {
        lu->num_sh++;
        __sync_val_compare_and_swap(&lu->lock, 1, 0);
        msg->action = GRANT_LOCK;
        prepare_packet(eth, ip, udp);
        return XDP_TX;
      }
    }

    else if (msg->type == EXCLUSIVE_LOCK) {
      if (lu->num_ex > 0 || lu->num_sh > 0) {
        __sync_val_compare_and_swap(&lu->lock, 1, 0);
        msg->action = REJECT_LOCK;
        prepare_packet(eth, ip, udp);
        return XDP_TX;
      }
      else {
        lu->num_ex++;
        __sync_val_compare_and_swap(&lu->lock, 1, 0);
        msg->action = GRANT_LOCK;
        prepare_packet(eth, ip, udp);
        return XDP_TX;
      }
    }
  }

  else if (msg->action == RELEASE_LOCK) {
    if (msg->type == SHARED_LOCK) lu->num_sh--;
    else if (msg->type == EXCLUSIVE_LOCK) lu->num_ex--;
    __sync_val_compare_and_swap(&lu->lock, 1, 0);

    msg->action = RELEASE_ACK;
    prepare_packet(eth, ip, udp);
    return XDP_TX;
  }

  return XDP_PASS;
}
