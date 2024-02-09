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
#include "kvs.h"
#include "tatp.h"

namespace {

// number of cores on machine
int n_lcores;

// number of worker threads per machine
int n_wthreads;

// network address of server
sockaddr_in servaddr;

// the main table
kvs *table;

// initialize server addresses
inline void net_init() {
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(kFasstPort);
  inet_pton(AF_INET, "10.10.1.1", &servaddr.sin_addr);
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
    panic("worker %u: bind failed", worker_id);

  message msg;
  sockaddr_in client_addr;

  while (1) {
    net_recv(sockfd, &msg, &client_addr, worker_id);

    int ret;
    switch (msg.type) {
      case PktType::kRead:
        ret = kvs_get(table, msg.key, msg.val, &msg.ver);
        if (ret == 0) msg.type = PktType::kGrantRead;
        else msg.type = PktType::kNotExist;
        net_send(sockfd, &msg, &client_addr, worker_id);
        break;

      case PktType::kSet:
        ret = kvs_set(table, msg.key, msg.val);
        if (ret == 0) msg.type = PktType::kSetAck;
        else msg.type = PktType::kNotExist;
        net_send(sockfd, &msg, &client_addr, worker_id);
        break;

      default:
        panic("unknown operation %d", msg.type);
    }
  }
}

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: [n_wthreads]" << std::endl;
    return -EINVAL;
  }

  n_wthreads = std::stoul(argv[1], nullptr, 0);
  n_lcores = get_nprocs();
  net_init();

  table = new kvs();
  kvs_init(table, kSubscriberNum * 18 / kKeysPerEntry);
  populate_table(table);

  std::cout << "finish initialization" << std::endl;

  auto thread_arr = new std::thread[n_wthreads];
  for (int i = 0; i < n_wthreads; i++) {
    thread_arr[i] = std::thread(server_handler, i);
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((i * 2 + 3) % n_lcores, &cpuset);
    int rc = pthread_setaffinity_np(thread_arr[i].native_handle(),
      sizeof(cpu_set_t), &cpuset);
    if (rc != 0) panic("pthread_setaffinity_np error: %d", rc);
  }
  for (int i = 0; i < n_wthreads; i++)
    thread_arr[i].join();

  return 0;
}
