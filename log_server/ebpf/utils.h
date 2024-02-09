// some common definitions

#ifndef _UTILS_H_
#define _UTILS_H_

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define COMMIT 0
#define ACK 1

#define VAL_SIZE 40
#define MAX_LOG_ENTRY_NUM 1000000

#define MAX_LCORE_NUM 128
#define MAX_PROG_NUM 1

#define FASST_PORT 20230

#define panic(fmt, ...)					\
  do {fprintf(stderr, fmt, ##__VA_ARGS__);	\
      quit = 1;} while (0)

struct message {
  uint8_t type;            // type
  uint64_t key;            // key
  uint8_t val[VAL_SIZE];   // value
  uint32_t ver;            // version
} __attribute__((packed));

struct log_entry {
  uint64_t key;
  uint8_t val[VAL_SIZE];
  uint32_t ver;
};

static inline uint16_t compute_ip_checksum(struct iphdr *ip) {
  uint32_t csum = 0;
  uint16_t *next_ip_u16 = (uint16_t *)ip;

  ip->check = 0;

  for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
    csum += *next_ip_u16++;
  }

  return ~((csum & 0xffff) + (csum >> 16));
}

static inline void prepare_packet(struct ethhdr *eth, 
                                  struct iphdr *ip, 
                                  struct udphdr *udp) {
  unsigned char tmp_mac[ETH_ALEN];
  __be32 tmp_ip;
  __be16 tmp_port;

  memcpy(tmp_mac, eth->h_source, ETH_ALEN);
  memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

  tmp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp_ip;

  tmp_port = udp->source;
  udp->source = udp->dest;
  udp->dest = tmp_port;

  udp->check = 0;
  ip->check = compute_ip_checksum(ip);
}

#endif // _UTILS_H_
