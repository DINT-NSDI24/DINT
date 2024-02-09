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
#include <thread>
#include <iostream>
#include <vector>
#include <deque>

#include "utils.h"
#include "net.h"

namespace {

// number of threads
int threads;

// number of cores
int n_lcores;

// network address of server
sockaddr_in servaddr;

// exclusive lock counter
uint32_t num_ex[kLockHashSize];

// shared lock counter
uint32_t num_sh[kLockHashSize];

// spin locks, one for each lock
volatile int spin_locks[kLockHashSize];

// initialize network address
void net_init() {
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(kMagicPort);
  inet_pton(AF_INET, "10.10.1.1", &servaddr.sin_addr);
}

// main processing loop for server
void server_loop(int worker_id) {
  std::cout << "worker " << worker_id << " started" << std::endl;

  int sockfd, optval = 1;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    panic("socket creation failed");

  setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const void *)&optval, sizeof(int));

  if (bind(sockfd, (const sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    panic("bind failed");

  message msg;
  sockaddr_in client_addr;

  while (1) {
    net_recv(sockfd, &msg, &client_addr, worker_id);
    uint64_t hash = fasthash64(&msg.lid, sizeof(msg.lid), 0xdeadbeef);
    uint32_t lock_hash = (uint32_t)(hash % (uint64_t)kLockHashSize);

    int ret = __sync_val_compare_and_swap(&spin_locks[lock_hash], 0, 1);
    if (ret == 1) {
      msg.action = PktType::kRetry;
      net_send(sockfd, &msg, &client_addr, worker_id);
      continue;
    }
  
    if (msg.action == PktType::kAcquireLock) {
      if (msg.type == LockType::kShared) {
        if (num_ex[lock_hash] == 0) {
          num_sh[lock_hash]++;
          __sync_val_compare_and_swap(&spin_locks[lock_hash], 1, 0);
          msg.action = PktType::kGrantLock;
          net_send(sockfd, &msg, &client_addr, worker_id);
        } else {
          __sync_val_compare_and_swap(&spin_locks[lock_hash], 1, 0);
          msg.action = PktType::kRejectLock;
          net_send(sockfd, &msg, &client_addr, worker_id);
        }
      } 
      
      else if (msg.type == LockType::kExclusive) {
        if (num_ex[lock_hash] == 0 && num_sh[lock_hash] == 0) {
          num_ex[lock_hash]++;
          __sync_val_compare_and_swap(&spin_locks[lock_hash], 1, 0);
          msg.action = PktType::kGrantLock;
          net_send(sockfd, &msg, &client_addr, worker_id);
        } else {
          __sync_val_compare_and_swap(&spin_locks[lock_hash], 1, 0);
          msg.action = PktType::kRejectLock;
          net_send(sockfd, &msg, &client_addr, worker_id);
        }
      }

      else panic("invalid lock type");
    } 
    
    else if (msg.action == PktType::kReleaseLock) {
      if (msg.type == LockType::kShared) num_sh[lock_hash]--;
      else if (msg.type == LockType::kExclusive) num_ex[lock_hash]--;
      __sync_val_compare_and_swap(&spin_locks[lock_hash], 1, 0);

      msg.action = PktType::kReleaseAck;
      net_send(sockfd, &msg, &client_addr, worker_id);
    }

    else panic("invalid action");
  }
}

}

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
