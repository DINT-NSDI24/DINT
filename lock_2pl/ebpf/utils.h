#ifndef _UTIL_H_
#define _UTIL_H_

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define ACQUIRE_LOCK 0
#define RELEASE_LOCK 1
#define GRANT_LOCK 2
#define REJECT_LOCK 3
#define RETRY 4
#define RELEASE_ACK 5

#define SHARED_LOCK 0
#define EXCLUSIVE_LOCK 1

#define LOCK_HASH_SIZE 36000000
#define MAX_QUEUE_LEN 100
#define MAX_PROG_NUM 5

#define MAGIC_PORT 20230

#define MAX_LCORE_NUM 128

enum {
  PROG_XDP_MAIN = 0,
  PROG_XDP_MAX
};

struct lock_unit {
  uint64_t lock;
  int num_ex;
  int num_sh;
};

struct message {
  uint8_t action;
  uint32_t lid;
  uint8_t type;
} __attribute__((__packed__));

static inline uint16_t compute_ip_checksum(struct iphdr *ip)
{
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

// Compression function for Merkle-Damgard construction.
// This function is generated using the framework provided.
static inline uint64_t fasthash_mix(uint64_t h) {
  h ^= h >> 23;
  h *= 0x2127599bf4325c37ULL;
  h ^= h >> 47;
  return h;
}

static inline uint64_t fasthash64(const void *buf, uint64_t len, uint64_t seed) {
  const uint64_t m = 0x880355f21e6d1965ULL;
  const uint64_t *pos = (const uint64_t *)buf;
  const uint64_t *end = pos + (len / 8);
  const unsigned char *pos2;
  uint64_t h = seed ^ (len * m);
  uint64_t v;

  while (pos != end) {
    v  = *pos++;
    h ^= fasthash_mix(v);
    h *= m;
  }

  pos2 = (const unsigned char*)pos;
  v = 0;

  switch (len & 7) {
  case 7: v ^= (uint64_t)pos2[6] << 48;
  case 6: v ^= (uint64_t)pos2[5] << 40;
  case 5: v ^= (uint64_t)pos2[4] << 32;
  case 4: v ^= (uint64_t)pos2[3] << 24;
  case 3: v ^= (uint64_t)pos2[2] << 16;
  case 2: v ^= (uint64_t)pos2[1] << 8;
  case 1: v ^= (uint64_t)pos2[0];
    h ^= fasthash_mix(v);
    h *= m;
  }

  return fasthash_mix(h);
}

static inline uint32_t fasthash32(const void *buf, uint64_t len, uint32_t seed)
{
  // the following trick converts the 64-bit hashcode to Fermat
  // residue, which shall retain information from both the higher
  // and lower parts of hashcode.
  uint64_t h = fasthash64(buf, len, seed);
  return h - (h >> 32);
}

#endif // _UTIL_H_
