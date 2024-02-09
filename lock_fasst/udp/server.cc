#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <iostream>
#include <thread>

#include "utils.h"
#include "net.h"

namespace {

// number of threads
int threads;

// number of cores
int n_lcores;

// network address of server
sockaddr_in servaddr;

// transaction locks
volatile int locks[kLockHashSize];

// version table
uint32_t ver_table[kLockHashSize];

// initialize network address
void net_init() {
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(kFasstPort);
  inet_pton(AF_INET, "10.10.1.1", &servaddr.sin_addr);
}

// main processing loop
void server_loop(int worker_id) {
  std::cout << "worker " << worker_id << " started" << std::endl;

  int sockfd, optval = 1;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    panic("socket creation failed");

  setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, 
         (const void *)&optval, sizeof(int));

  // optval = SOCKET_BUF_SIZE;
  // if (setsockopt(sockfd, SOL_SOCKET,
  //                SO_RCVBUF, (const void *)&optval, sizeof(optval)) < 0) {
  //     fprintf(stderr, "Failed to set SO_RCVBUF on socket");
  //     exit(EXIT_FAILURE);
  // }
  // if (setsockopt(sockfd, SOL_SOCKET,
  //                SO_SNDBUF, (const void *)&optval, sizeof(optval)) < 0) {
  //     fprintf(stderr, "Failed to set SO_SNDBUF on socket");
  //     exit(EXIT_FAILURE);
  // }

  if (bind(sockfd, (const sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    panic("bind failed");

  message msg;
  sockaddr_in client_addr;

  while (1) {
    net_recv(sockfd, &msg, &client_addr, worker_id);

    uint64_t hash = fasthash64(&msg.lid, sizeof(msg.lid), 0xdeadbeef);
    uint32_t lock_hash = (uint32_t)(hash % (uint64_t)kLockHashSize);

    int ret;
    switch (msg.type) {
      case PktType::kRead:
        msg.type = PktType::kGrantRead;
        msg.ver = ver_table[lock_hash];
        net_send(sockfd, &msg, &client_addr, worker_id);
        break;

      case PktType::kAcquireLock:
        ret = __sync_val_compare_and_swap(&locks[lock_hash], 0, 1);
        if (ret == 0) {
          msg.type = PktType::kGrantLock;
          net_send(sockfd, &msg, &client_addr, worker_id);
        } else if (ret == 1) {
          msg.type = PktType::kRejectLock;
          net_send(sockfd, &msg, &client_addr, worker_id);
        } else panic("unknown lock state");
        break;

      case PktType::kAbort:
        __sync_val_compare_and_swap(&locks[lock_hash], 1, 0);
        msg.type = PktType::kAbortAck;
        net_send(sockfd, &msg, &client_addr, worker_id);
        break;
      
      case PktType::kCommit:
        ver_table[lock_hash]++;
        __sync_val_compare_and_swap(&locks[lock_hash], 1, 0);
        msg.type = PktType::kCommitAck;
        net_send(sockfd, &msg, &client_addr, worker_id);
        break;

      default:
        panic("unknown packet type %d", msg.type);
    }
  }
}

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: [#threads]" << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[1], nullptr, 0);
  n_lcores = get_nprocs();
  net_init();

  std::cout << "finish initialization" << std::endl;

  auto thread_arr = new std::thread[threads];
  for (int i = 0; i < threads; i++) {
    thread_arr[i] = std::thread(server_loop, i);
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((i * 2 + 3) % n_lcores, &cpuset);
    int rc = pthread_setaffinity_np(thread_arr[i].native_handle(),
      sizeof(cpu_set_t), &cpuset);
    if (rc != 0) panic("pthread_setaffinity_np error: %d", rc);
  }
  for (int i = 0; i < threads; i++)
    thread_arr[i].join();

  return 0;
}
