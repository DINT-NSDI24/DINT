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

SEC("log")
int log_main(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if (eth + 1 > data_end) return XDP_PASS;

  struct iphdr *ip = data + sizeof(*eth);
  if (ip + 1 > data_end) return XDP_PASS;

  void *transp = data + sizeof(*eth) + sizeof(*ip);
  struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
  if (udp + 1 > data_end) return XDP_PASS;

  if (udp->dest != htons(FASST_PORT)) return XDP_PASS;

  char *payload = transp + sizeof(*udp);
  struct message *msg = (struct message *)payload;
  if (msg + 1 > data_end) return XDP_PASS;

  if (msg->type != COMMIT) return XDP_PASS;

  uint32_t *log_cnt = bpf_map_lookup_elem(&map_log_cnt, &zero);
  if (!log_cnt) return XDP_PASS;
  struct log_entry *log_entry = bpf_map_lookup_elem(&map_log, log_cnt);
  if (!log_entry) return XDP_PASS;

  log_entry->key = msg->key;
  memcpy(log_entry->val, msg->val, VAL_SIZE);
  log_entry->ver = msg->ver;

  (*log_cnt)++;
  if (*log_cnt == MAX_LOG_ENTRY_NUM) *log_cnt = 0;

  msg->type = ACK;
  prepare_packet(eth, ip, udp);
  return XDP_TX;
}
