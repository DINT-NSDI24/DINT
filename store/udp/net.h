// networking

#pragma once

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "kvs.h"

// magic port
constexpr int kFasstPort = 20230;

// packet types
enum PktType {
  // client
  kRead = 0,
  kSet = 1,
  kInsert = 2,

  // server
  kGrantRead = 3,
  kRejectRead = 4,
  kSetAck = 5,
  kRejectSet = 6,
  kNotExist = 7,
  kInsertAck = 8,
  kRejectInsert = 9,
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
