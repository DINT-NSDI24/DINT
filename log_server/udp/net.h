// networking

#pragma once

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "utils.h"

// magic port
constexpr int kFasstPort = 20230;

// packet types
enum PktType {
  kCommit = 0,
  kAck = 1,
};

// for adjusting server socket buffer size
constexpr int kSocketBufSize = 10485760;

#pragma pack(push, 1)
struct message {
  uint8_t type;            // packet type
  uint64_t key;            // key
  uint8_t val[kValSize];   // value
  uint32_t ver;            // version
};
#pragma pack(pop)

constexpr char ip_list[][32] = {
  // clients
  "10.10.1.2",
  "10.10.1.3",
  "10.10.1.4"
  "10.10.1.5",
  "10.10.1.6",
  "10.10.1.7",
  "10.10.1.8",
  "10.10.1.9",
  "10.10.1.10",
  "10.10.1.11",
  "10.10.1.12",

  // server
  "10.10.1.1",
};

static inline void net_send(int sockfd, message *msg, 
                    const sockaddr_in *addr, int worker_id) {
  auto ret = sendto(sockfd, msg, sizeof(struct message), 
                   0, (const sockaddr *)addr, sizeof(*addr));
  // fprintf(stderr, "worker %d: send type %u, key %lu\n", worker_id, msg->type, msg->key);
  if (ret < 0) panic("worker %u: send error", worker_id);
}

static inline void net_recv(int sockfd, message *msg,
                    sockaddr_in *addr, int worker_id) {
  socklen_t len = sizeof(*addr);
  auto ret = recvfrom(sockfd, msg, sizeof(struct message), 0, 
                     (sockaddr *)addr, &len);
  // fprintf(stderr, "worker %d: recv type %u, key %lu\n", worker_id, msg->type, msg->key);
  if (ret < 0) panic("worker %u: recv error", worker_id);
}
