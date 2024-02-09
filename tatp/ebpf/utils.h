// some common definitions

#ifndef _UTILS_H_
#define _UTILS_H_

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define VAL_SIZE 40
#define SUBSCRIBER_NUM 7000000
#define KEYS_PER_ENTRY 4
#define MAX_LOG_ENTRY_NUM 1000000
#define CACHE_FACTOR 1

#define SUB_HASH_SIZE ((SUBSCRIBER_NUM*3/2/KEYS_PER_ENTRY)*CACHE_FACTOR)
#define SEC_SUB_HASH_SIZE ((SUBSCRIBER_NUM*3/2/KEYS_PER_ENTRY)*CACHE_FACTOR)
#define AI_HASH_SIZE ((SUBSCRIBER_NUM*15/4/KEYS_PER_ENTRY)*CACHE_FACTOR)
#define SF_HASH_SIZE ((SUBSCRIBER_NUM*15/4/KEYS_PER_ENTRY)*CACHE_FACTOR)
#define CF_HASH_SIZE ((SUBSCRIBER_NUM*15/4/KEYS_PER_ENTRY)*CACHE_FACTOR)

// table types
enum {
  SUBSCRIBER = 0,
  SECOND_SUBSCRIBER = 1,
  ACCESS_INFO = 2,
  SPECIAL_FACILITY = 3,
  CALL_FORWARDING = 4,
  TABLE_NUM = 5,
};

#define MAX_LCORE_NUM 128
#define MAX_PROG_NUM 1

#define FASST_PORT 20230

// packet types
#define READ 0
#define ACQUIRE_LOCK 1
#define ABORT 2
#define COMMIT 3

#define GRANT_READ 4
#define REJECT_READ 5
#define NOT_EXIST 6
#define GRANT_LOCK 7
#define REJECT_LOCK 8
#define ABORT_ACK 9
#define COMMIT_ACK 10
#define REJECT_COMMIT 11

// only used in sharding
#define COMMIT_PRIM 12
#define COMMIT_BCK 13
#define COMMIT_LOG 14
#define COMMIT_PRIM_ACK 15
#define COMMIT_BCK_ACK 16
#define COMMIT_LOG_ACK 17

// only used in tatp
#define INSERT_PRIM 18
#define INSERT_BCK 19
#define INSERT_PRIM_ACK 20
#define INSERT_BCK_ACK 21
#define DELETE_PRIM 22
#define DELETE_BCK 23
#define DELETE_LOG 24
#define DELETE_PRIM_ACK 25
#define DELETE_BCK_ACK 26
#define DELETE_LOG_ACK 27

#define REJECT_LOCK_SAME_KEY 28

#define SOCKET_BUF_SIZE 67108864

#define panic(fmt, ...)					\
	do {fprintf(stderr, fmt, ##__VA_ARGS__);	\
	    quit = 1;} while (0)

struct message {
  uint8_t ord;             // order
  uint8_t type;            // packet type
  uint8_t table;           // table id
  uint64_t key;            // key
  uint8_t val[VAL_SIZE];   // value
  uint32_t ver;            // version
} __attribute__((packed));

struct ext_message {
  uint8_t ord;              // order
  uint8_t type;             // packet type
  uint8_t table;            // table id
  uint64_t key1;            // key
  uint8_t val1[VAL_SIZE];   // value1, also used to store new bloom filter
  uint32_t ver1;            // version1, also used to indicate eviction
  uint64_t key2;            // key
  uint8_t val2[VAL_SIZE];   // value2
  uint32_t ver2;            // version2
  uint8_t idx;             // key slot idx
} __attribute__((packed));

struct cache_entry {
  uint64_t key[KEYS_PER_ENTRY];
  uint8_t val[KEYS_PER_ENTRY][VAL_SIZE];
  uint32_t ver[KEYS_PER_ENTRY];
  uint8_t valid[KEYS_PER_ENTRY];
  uint8_t dirty[KEYS_PER_ENTRY];
  uint64_t bloom_filter;
  uint64_t lock;
};

struct log_entry {
  uint8_t is_del;
  uint8_t table;
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

static inline void adjust_packet_len(struct iphdr *ip, 
                                     struct udphdr *udp,
                                     int16_t len) {
  if (len < 0) {
    uint16_t dec_len = (uint16_t)(-len);
    ip->tot_len = htons(ntohs(ip->tot_len) - dec_len);
    udp->len = htons(ntohs(udp->len) - dec_len);
  } else {
    ip->tot_len = htons(ntohs(ip->tot_len) + (uint16_t)len);
    udp->len = htons(ntohs(udp->len) + (uint16_t)len);
  }

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

#endif // _UTILS_H_
