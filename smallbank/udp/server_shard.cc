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
#include "smallbank.h"
#include "../cpu_util.h"
static pthread_t cpu_mon_tid, cpu_mon_handler_tid;
static volatile double user_used_cores; 
static volatile double kern_used_cores; 

namespace {

// shard id
int shard_id;

// number of cores on machine
int n_lcores;

// number of worker threads per machine
int n_wthreads;

// network address of server
sockaddr_in servaddr;

// the smallbank tables
// tables[0]: saving
// tables[1]: checking
kvs *tables[kTableNum];

// transaction locks
volatile int txn_locks[kTableNum][kLockNum];

// exclusive lock counter
uint32_t num_ex[kTableNum][kLockNum];

// shared lock counter
uint32_t num_sh[kTableNum][kLockNum];

// log
log_entry *txn_log[16];
thread_local uint32_t log_entry_cnt = 0;

// initialize server addresses
inline void net_init() {
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(kFasstPort);
  inet_pton(AF_INET, ip_list[shard_id - 1], &servaddr.sin_addr);
}

void populate_tables() {
  for (int i = 0; i < kTableNum; i++) 
    tables[i] = new kvs();

  kvs_init(tables[TableType::kSaving], kAccountNum * 3/2 / kKeysPerEntry);
  kvs_init(tables[TableType::kChecking], kAccountNum * 3/2 / kKeysPerEntry);

  populate_saving_and_checking_tables(tables[TableType::kSaving], tables[TableType::kChecking]);
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
    uint64_t lh = lock_hash(tables[msg.table], msg.key);

    if (msg.type == PktType::kAcquireShared || msg.type == PktType::kAcquireExclusive ||
        msg.type == PktType::kReleaseShared || msg.type == PktType::kReleaseExclusive) {
      int ret = __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 0, 1);
      if (ret == 1) {
        msg.type = PktType::kRetry;
        net_send(sockfd, &msg, &client_addr, worker_id);
        continue;
      }
    }

    if (msg.type == PktType::kAcquireShared) {
      if (num_ex[msg.table][lh] == 0) {
        num_sh[msg.table][lh]++;
        kvs_get(tables[msg.table], msg.key, msg.val, &msg.ver);
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kGrantShared;
        net_send(sockfd, &msg, &client_addr, worker_id);
      } else {
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kRejectShared;
        net_send(sockfd, &msg, &client_addr, worker_id);
      }
    }

    else if (msg.type == PktType::kAcquireExclusive) {
      if (num_ex[msg.table][lh] == 0 && num_sh[msg.table][lh] == 0) {
        num_ex[msg.table][lh]++;
        kvs_get(tables[msg.table], msg.key, msg.val, &msg.ver);
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kGrantExclusive;
        net_send(sockfd, &msg, &client_addr, worker_id);
      } else {
        __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
        msg.type = PktType::kRejectExclusive;
        net_send(sockfd, &msg, &client_addr, worker_id);
      }
    }

    else if (msg.type == PktType::kReleaseShared) {
      num_sh[msg.table][lh]--;
      __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
      msg.type = PktType::kReleaseSharedAck;
      net_send(sockfd, &msg, &client_addr, worker_id);
    }

    else if (msg.type == PktType::kReleaseExclusive) {
      num_ex[msg.table][lh]--;
      __sync_val_compare_and_swap(&txn_locks[msg.table][lh], 1, 0);
      msg.type = PktType::kReleaseExclusiveAck;
      net_send(sockfd, &msg, &client_addr, worker_id);
    }

    else if (msg.type == PktType::kCommitPrim) {
      kvs_set(tables[msg.table], msg.key, msg.val);
      msg.type = PktType::kCommitPrimAck;
      net_send(sockfd, &msg, &client_addr, worker_id);
    }

    else if (msg.type == PktType::kCommitBck) {
      kvs_set(tables[msg.table], msg.key, msg.val);
      msg.type = PktType::kCommitBckAck;
      net_send(sockfd, &msg, &client_addr, worker_id);
    }
    
    else if (msg.type == PktType::kCommitLog) {
      int cpu_id = sched_getcpu();
      int log_id = (cpu_id - 3) / 2;
      txn_log[log_id][log_entry_cnt].table = msg.table;
      txn_log[log_id][log_entry_cnt].key = msg.key;
      memcpy(txn_log[log_id][log_entry_cnt].val, msg.val, kValSize);
      txn_log[log_id][log_entry_cnt].ver = msg.ver;
      log_entry_cnt = (log_entry_cnt + 1) % kMaxLogEntryNum;

      msg.type = PktType::kCommitLogAck;
      net_send(sockfd, &msg, &client_addr, worker_id);
    }

    else panic("unknown operation %d", msg.type);
  }
}

void *cpu_mon_func(void *arg) {
#define num_cpus 16
  int cpu_ids[num_cpus] = {3,  5,  7,  9,  11, 13, 15, 17,
                           19, 21, 23, 25, 27, 29, 31, 33};

  struct cpuusage last_usage, cur_usage;
  double utime_pct, ktime_pct;

  get_cpu_usage(cpu_ids, num_cpus, &last_usage);

  while (true) {
    usleep(1000000);
    get_cpu_usage(cpu_ids, num_cpus, &cur_usage);

    cpuusage_get_diff(&cur_usage, &last_usage, &utime_pct, &ktime_pct);

    user_used_cores = num_cpus * utime_pct;
    kern_used_cores = num_cpus * ktime_pct;

    fprintf(stderr, "user_used_cores = %lf, kern_used_cores = %lf\n",
            user_used_cores, kern_used_cores);

    last_usage = cur_usage;
  }

  return NULL;
}

void *cpu_mon_handler(void *arg) {
#define CPU_MON_PORT 20231
  static struct sockaddr_in mon_addr;
  memset(&mon_addr, 0, sizeof(mon_addr));
  mon_addr.sin_family = AF_INET;
  mon_addr.sin_port = htons(CPU_MON_PORT);
  inet_pton(AF_INET, "10.10.1.1", &mon_addr.sin_addr);

  int sockfd, optval = 1;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    panic("cpu_mon: socket creation failed");

  if (bind(sockfd, (const struct sockaddr *)&mon_addr, sizeof(mon_addr)) < 0)
    panic("cpu_mon: bind failed");

  struct cpu_mon_message {
    double ucores;
    double kcores;
  } msg;
  struct sockaddr_in client_addr;

  while (1) {
    socklen_t len = sizeof(client_addr);
    int ret = recvfrom(sockfd, &msg, sizeof(struct cpu_mon_message), 0,
                       (struct sockaddr *)&client_addr, &len);
    msg.ucores = user_used_cores;
    msg.kcores = kern_used_cores;
    sendto(sockfd, &msg, sizeof(struct cpu_mon_message), 0,
           (const struct sockaddr *)&client_addr, sizeof(client_addr));
  }

  return NULL;
}

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: [shard_id] [n_wthreads]" << std::endl;
    return -EINVAL;
  }

  shard_id = std::stoi(argv[1], nullptr, 0);
  n_wthreads = std::stoi(argv[2], nullptr, 0);
  n_lcores = get_nprocs();
  net_init();

  populate_tables();

  for (int i = 0; i < 16; ++i)
    txn_log[i] = new log_entry[kMaxLogEntryNum];

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

  if (shard_id == 1) {
    pthread_create(&cpu_mon_tid, NULL, cpu_mon_func, NULL);
    pthread_create(&cpu_mon_handler_tid, NULL, cpu_mon_handler, NULL);
  }

  for (int i = 0; i < n_wthreads; i++)
    thread_arr[i].join();

  return 0;
}
