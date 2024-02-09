#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
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
#include <vector>
#include <thread>

#include "utils.h"
#include "net.h"

namespace {

// number of cores on machine
int n_lcores;

// number of worker threads per machine
int threads;

// network address of server
sockaddr_in servaddr;

// log
log_entry *txn_log[16];
thread_local uint32_t log_entry_cnt = 0;

inline void net_init() {
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(kFasstPort);
  inet_pton(AF_INET, ip_list[11], &servaddr.sin_addr);
}

// main processing loop for server
void server_handler(int worker_id) {
  std::cout << "worker " << worker_id << " started" << std::endl;

  int sockfd, optval = 1;
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    panic("worker %u: socket creation failed", worker_id);
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

    if (msg.type != PktType::kCommit)
      panic("unknown operation");

    int cpu_id = sched_getcpu();
    int log_id = (cpu_id - 3) / 2;
    txn_log[log_id][log_entry_cnt].key = msg.key;
    memcpy(txn_log[log_id][log_entry_cnt].val, msg.val, kValSize);
    txn_log[log_id][log_entry_cnt].ver = msg.ver;
    log_entry_cnt = (log_entry_cnt + 1) % kMaxLogEntryNum;

    msg.type = PktType::kAck;
    net_send(sockfd, &msg, &client_addr, worker_id);
  }
}

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: [threads]" << std::endl;
    return -EINVAL;
  }

  threads = std::stoul(argv[1], nullptr, 0);
  n_lcores = get_nprocs();
  net_init();

  for (int i = 0; i < 16; ++i)
    txn_log[i] = new log_entry[kMaxLogEntryNum];

  std::cout << "finish initialization" << std::endl;

  auto thread_arr = new std::thread[threads];
  for (int i = 0; i < threads; i++) {
    thread_arr[i] = std::thread(server_handler, i);
    
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
