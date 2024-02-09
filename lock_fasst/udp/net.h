// networking

#pragma once

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

constexpr int kFasstPort = 20230;

enum PktType {
  kRead = 0,
  kAcquireLock = 1,
  kAbort = 2,
  kCommit = 3,
  kGrantRead = 4,
  kGrantLock = 5,
  kRejectLock = 6,
  kAbortAck = 7,
  kCommitAck = 8,
};

constexpr int kSocketBufSize = 10485760;

#pragma pack(push, 1)
struct message {
  uint8_t type;
  uint32_t lid;
  uint32_t ver;
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
