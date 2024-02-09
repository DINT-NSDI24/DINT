#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <asm-generic/posix_types.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "utils.h"
#include "kvs.h"
#include "smallbank.h"
#include "../cpu_util.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

struct bpf_progs_desc {
  char name[256];
  enum bpf_prog_type type;
  unsigned char pin;
  int map_prog_idx;
  struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
  {"tps_prim_xdp_main", BPF_PROG_TYPE_XDP, 0, -1, NULL},
  {"tps_prim_tc_main", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL}
};

static char filename[PATH_MAX];
static char command[PATH_MAX];
static int interface_count = 0;
static int *interfaces_idx;

volatile int quit = 0;

void sigint_handler(int signum) { quit = 1; }

static int shard_id = 0;
static int n_wthreads;
static pthread_t tids[MAX_LCORE_NUM];
static pthread_t cpu_mon_tid, cpu_mon_handler_tid;
static volatile double user_used_cores; 
static volatile double kern_used_cores; 

// network address of server
static struct sockaddr_in servaddr;

// the smallbank tables
// tables[0]: saving
// tables[1]: checking
static struct kvs *tables[TABLE_NUM];

void init_tables() {
  for (int i = 0; i < TABLE_NUM; i++) 
    tables[i] = calloc(1, sizeof(struct kvs));

  kvs_init(tables[SAVING], SAV_HASH_SIZE);
  kvs_init(tables[CHECKING], CHK_HASH_SIZE);

  populate_saving_and_checking_tables(tables[SAVING], tables[CHECKING]);
}

static int print_bpf_verifier(enum libbpf_print_level level,
                              const char *format, va_list args) {
  return vfprintf(stdout, format, args);
}

static void parse_args(int argc, char *argv[]) {
  snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

  if (argc < 4) {
    fprintf(stderr, "usage: [shard_id] [n_wthreads] [interface1] [interface2] ...\n");
    exit(EXIT_FAILURE);
  }

  shard_id = atoi(argv[1]);
  n_wthreads = atoi(argv[2]);

  interface_count = argc - 3;
  interfaces_idx = calloc(interface_count, sizeof(int));
  if (interfaces_idx == NULL) {
    fprintf(stderr, "Error: failed to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < interface_count; i++) {
    interfaces_idx[i] = if_nametoindex(argv[i + 3]);
  }
}

void *server_handler(void *arg) {
  int worker_id = *(int *)arg;
  free(arg);

  fprintf(stderr, "worker %d started\n", worker_id);

  int sockfd, optval = 1;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    panic("socket creation failed");

  setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, 
         (const void *)&optval, sizeof(int));

  optval = SOCKET_BUF_SIZE;
  if (setsockopt(sockfd, SOL_SOCKET,
                 SO_RCVBUF, (const void *)&optval, sizeof(optval)) < 0) {
      fprintf(stderr, "Failed to set SO_RCVBUF on socket");
      exit(EXIT_FAILURE);
  }
  if (setsockopt(sockfd, SOL_SOCKET,
                 SO_SNDBUF, (const void *)&optval, sizeof(optval)) < 0) {
      fprintf(stderr, "Failed to set SO_SNDBUF on socket");
      exit(EXIT_FAILURE);
  }

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    panic("bind failed");

  struct ext_message msg;
  struct sockaddr_in client_addr;

  while (1) {
    socklen_t len = sizeof(client_addr);
    int ret = recvfrom(sockfd, &msg, sizeof(struct ext_message), 0, (struct sockaddr *)&client_addr, &len);
    if (ret != sizeof(struct ext_message)) panic("wrong packet size");

    if (msg.type == ACQUIRE_SHARED) {
      if (msg.ver1 == 1) kvs_set(tables[msg.table], msg.key2, msg.val2, msg.ver2);

      kvs_get(tables[msg.table], msg.key1, msg.val1, &msg.ver1);
      msg.type = GRANT_SHARED;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    }

    else if (msg.type == ACQUIRE_EXCLUSIVE) {
      if (msg.ver1 == 1) kvs_set(tables[msg.table], msg.key2, msg.val2, msg.ver2);

      kvs_get(tables[msg.table], msg.key1, msg.val1, &msg.ver1);
      msg.type = GRANT_EXCLUSIVE;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    }
    
    else if (msg.type == COMMIT_PRIM) {
      if (msg.ver1 == 1) kvs_set(tables[msg.table], msg.key2, msg.val2, msg.ver2);

      msg.ver1 = kvs_set(tables[msg.table], msg.key1, msg.val1, 0);
      msg.type = COMMIT_PRIM_ACK;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    }
  
    else if (msg.type == COMMIT_BCK) {
      if (msg.ver1 == 1) kvs_set(tables[msg.table], msg.key2, msg.val2, msg.ver2);
      msg.ver1 = kvs_set(tables[msg.table], msg.key1, msg.val1, 0);
      msg.type = COMMIT_BCK_ACK;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    }

    else if (msg.type == WARMUP_READ) {
      if (msg.ver1 == 1) kvs_set(tables[msg.table], msg.key2, msg.val2, msg.ver2);

      kvs_get(tables[msg.table], msg.key1, msg.val1, &msg.ver1);
      msg.type = WARMUP_READ_ACK;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    }

    else panic("unknown operation");
  }

  return NULL;
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

int main(int argc, char *argv[]) {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  __u32 xdp_flags;
  int map_progs_xdp_fd, xdp_main_prog_fd, map_progs_tc_fd, map_progs_fd;
  struct bpf_object *obj;
  int prog_count;

  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit failed");
    return 1;
  }

  init_tables();

  parse_args(argc, argv);

  libbpf_set_print(print_bpf_verifier);
  xdp_flags = XDP_FLAGS_DRV_MODE;

  obj = bpf_object__open(filename);
  if (!obj) {
    fprintf(stderr, "Error: bpf_object__open failed\n");
    return 1;
  }

  prog_count = sizeof(progs) / sizeof(progs[0]);

  for (int i = 0; i < prog_count; i++) {
    progs[i].prog = bpf_object__find_program_by_name(obj, progs[i].name);
    if (!progs[i].prog) {
      fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
      return 1;
    }
    bpf_program__set_type(progs[i].prog, progs[i].type);
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "Error: bpf_object__load_xattr failed\n");
    return 1;
  }

  map_progs_xdp_fd = bpf_object__find_map_fd_by_name(obj, "map_progs_xdp");
  if (map_progs_xdp_fd < 0) {
    fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
    return 1;
  }

  map_progs_tc_fd = bpf_object__find_map_fd_by_name(obj, "map_progs_tc");
  if (map_progs_tc_fd < 0) {
    fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
    return 1;
  }

  for (int i = 0; i < prog_count; i++) {
    int prog_fd = bpf_program__fd(progs[i].prog);

    if (prog_fd < 0) {
      fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
      return 1;
    }

    if (progs[i].map_prog_idx != -1) {
      unsigned int map_prog_idx = progs[i].map_prog_idx;
      if (map_prog_idx < 0) {
        fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
        return 1;
      }

      switch (progs[i].type) {
      case BPF_PROG_TYPE_XDP:
        map_progs_fd = map_progs_xdp_fd;
        break;
      case BPF_PROG_TYPE_SCHED_CLS:
        map_progs_fd = map_progs_tc_fd;
        break;
      default:
        fprintf(stderr, "Error: Program type doesn't correspond to any prog array map\n");
        return 1;
      }

      if (bpf_map_update_elem(map_progs_fd, &map_prog_idx, &prog_fd, 0)) {
        fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
        return 1;
      }
    }

    if (progs[i].pin) {
      int len = snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, progs[i].name);
      if (len < 0) {
        fprintf(stderr, "Error: Program name '%s' is invalid\n", progs[i].name);
        return -1;
      } else if (len >= PATH_MAX) {
        fprintf(stderr, "Error: Program name '%s' is too long\n", progs[i].name);
        return -1;
      }
retry:
      if (bpf_program__pin(progs[i].prog, filename)) {
        fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n", progs[i].name, filename);
        if (errno == EEXIST) {
          fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", progs[i].name);
          if (bpf_program__unpin(progs[i].prog, filename)) {
            fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n", progs[i].name, filename);
            return -1;
          }
          goto retry;
        }
        return -1;
      }
    }
  }

  xdp_main_prog_fd = bpf_program__fd(progs[0].prog);
  if (xdp_main_prog_fd < 0) {
    fprintf(stderr, "Error: bpf_program__fd failed\n");
    return 1;
  }

  for (int i = 0; i < interface_count; i++) {
    if (bpf_xdp_attach(interfaces_idx[i], xdp_main_prog_fd, xdp_flags, NULL) < 0) {
      fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n", interfaces_idx[i]);
      return 1;
    } else {
      fprintf(stderr, "Main BPF program attached to XDP on interface %d\n", interfaces_idx[i]);
    }
  }

  for (int i = 0; i < interface_count; i++) {
    snprintf(command, PATH_MAX, "tc qdisc add dev %s clsact", argv[3 + i]);
    assert(system(command) == 0);
    snprintf(command, PATH_MAX, "tc filter add dev %s egress bpf object-pinned /sys/fs/bpf/tps_prim_tc_main", argv[3 + i]);
    assert(system(command) == 0);
    fprintf(stderr, "Main BPF program attached to TC on interface %d\n", interfaces_idx[i]);
  }

  signal(SIGINT, sigint_handler);
  signal(SIGTERM, sigint_handler);

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(FASST_PORT);
  switch (shard_id) {
    case 1: inet_pton(AF_INET, "10.10.1.1", &servaddr.sin_addr); break;
    case 2: inet_pton(AF_INET, "10.10.1.2", &servaddr.sin_addr); break;
    case 3: inet_pton(AF_INET, "10.10.1.3", &servaddr.sin_addr); break;
    default: panic("unknown shard id");
  }

  // do not join threads, just wait for signal and exit
  for (int i = 0; i < n_wthreads; i++)  {
    int *worker_id = malloc(sizeof(int));
    *worker_id = i;
    pthread_create(&tids[i], NULL, server_handler, worker_id);
  }

  if (shard_id == 1) {
    pthread_create(&cpu_mon_tid, NULL, cpu_mon_func, NULL);
    pthread_create(&cpu_mon_handler_tid, NULL, cpu_mon_handler, NULL);
  }

  fprintf(stderr, "all workers started\n");

  while (!quit) sleep(1);

  for (int i = 0; i < interface_count; i++) 
    bpf_xdp_detach(interfaces_idx[i], xdp_flags, NULL);

  for (int i = 0; i < interface_count; i++) {
		snprintf(command, PATH_MAX, "tc filter del dev %s egress", argv[3 + i]);
		assert(system(command) == 0);
		snprintf(command, PATH_MAX, "tc qdisc del dev %s clsact", argv[3 + i]);
		assert(system(command) == 0);
	}

  assert(system("rm -f /sys/fs/bpf/tps_prim_tc_main") == 0);

  return 0;
}
