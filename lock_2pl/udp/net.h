// networking

#pragma once

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

constexpr int kMagicPort = 20230;

enum PktType {
  kAcquireLock = 0,
  kReleaseLock = 1,
  kGrantLock = 2,
  kRejectLock = 3,
  kRetry = 4,
  kReleaseAck = 5,
};

enum LockType {
  kShared = 0,
  kExclusive = 1,
};

#pragma pack(push, 1)
struct message {
  uint8_t action;
  uint32_t lid;
  uint8_t type;
};
#pragma pack(pop)

static inline int net_send(int sockfd, struct message *msg, 
                    const sockaddr_in *addr, uint32_t worker_id) {
  auto ret = sendto(sockfd, msg, sizeof(struct message), 
                   0, (const sockaddr *)addr, sizeof(*addr));
  // fprintf(stderr, "worker %u : send type %u, key %u\n", worker_id, msg->type, msg->key);
  return ret;
}

static inline int net_recv(int sockfd, struct message *msg,
                    sockaddr_in *addr, uint32_t worker_id) {
  socklen_t len = sizeof(*addr);
  auto ret = recvfrom(sockfd, msg, sizeof(struct message), 0, 
                     (sockaddr *)addr, &len);
  // fprintf(stderr, "worker %u : recv type %u, key %u\n", worker_id, msg->type, msg->key);
  return ret;
}
