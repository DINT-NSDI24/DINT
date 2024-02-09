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

static volatile int quit = 0;

void sigint_handler(int signum) { quit = 1; }

static uint32_t n_wthreads = 0;
static pthread_t tids[MAX_LCORE_NUM];

static uint64_t pkt_cnt[MAX_LCORE_NUM];

void sigalrm_handler(int signum) {
  static uint64_t last_pkt_cnt;
  uint64_t total_pkt_cnt = 0;
  for (int i = 0; i < n_wthreads; i++) total_pkt_cnt += pkt_cnt[i];
  fprintf(stderr, "pps = %lu\n", total_pkt_cnt - last_pkt_cnt);
  last_pkt_cnt = total_pkt_cnt;
  alarm(1);
}

// network address of server
static struct sockaddr_in primaddr;

// the main table
static struct kvs *table;

static int print_bpf_verifier(enum libbpf_print_level level,
                              const char *format, va_list args) {
  return vfprintf(stdout, format, args);
}

static void parse_args(int argc, char *argv[]) {
  snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

  if (argc < 3) {
    fprintf(stderr, "usage: [n_wthreads] [interface1] [interface2] ...\n");
    exit(EXIT_FAILURE);
  }

  n_wthreads = atoi(argv[1]);

  interface_count = argc - 2;
  interfaces_idx = calloc(interface_count, sizeof(int));
  if (interfaces_idx == NULL) {
    fprintf(stderr, "Error: failed to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < interface_count; i++) {
    interfaces_idx[i] = if_nametoindex(argv[i + 2]);
  }
}

void *server_handler(void *arg) {
  uint32_t worker_id = *(uint32_t *)arg;
  free(arg);

  fprintf(stderr, "worker %u started\n", worker_id);

  int sockfd, optval = 1;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    panic("socket creation failed");

  setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, 
         (const void *)&optval, sizeof(int));

  optval = SOCKET_BUF_SIZE;
  if (setsockopt(sockfd, SOL_SOCKET,
                 SO_RCVBUF, (const void *)&optval, sizeof(optval)) < 0)
    panic("failed to set so_rcvbuf on socket");
  if (setsockopt(sockfd, SOL_SOCKET,
                 SO_SNDBUF, (const void *)&optval, sizeof(optval)) < 0)
    panic("failed to set so_sndbuf on socket");

  if (bind(sockfd, (const struct sockaddr *)&primaddr, sizeof(primaddr)) < 0)
    panic("bind failed");

  struct ext_message msg;
  struct sockaddr_in client_addr;

  while (1) {
    socklen_t len = sizeof(client_addr);
    int ret = recvfrom(sockfd, &msg, sizeof(struct ext_message), 0, (struct sockaddr *)&client_addr, &len);

    pkt_cnt[worker_id]++;

    if (msg.type == READ) {
      if (ret != sizeof(struct ext_message)) panic("recvfrom read failed");
      if (msg.ver1 == 1) kvs_set_evict(table, msg.key2, msg.val2, msg.ver2);

      int res = kvs_get(table, msg.key1, msg.val1, &msg.ver1);
      if (res == 0) msg.type = GRANT_READ;
      else msg.type = NOT_EXIST;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    } 
    
    else if (msg.type == SET) {
      if (ret != sizeof(struct ext_message)) panic("recvfrom commit failed");
      if (msg.ver1 == 1) kvs_set_evict(table, msg.key2, msg.val2, msg.ver2);

      kvs_set(table, msg.key1, msg.val1, &msg.ver1);
      if (msg.ver1 != 0) msg.type = SET_ACK;
      else msg.type = NOT_EXIST;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    } 
    
    else if (msg.type == INSERT) {
      if (ret != sizeof(struct ext_message)) panic("recvfrom insert failed");
      kvs_insert(table, msg.key1, msg.val1);
      kvs_set_evict(table, msg.key2, msg.val2, msg.ver2);
      msg.type = INSERT_ACK;
      sendto(sockfd, &msg, sizeof(struct ext_message), 
              0, (const struct sockaddr *)&client_addr, sizeof(client_addr));
    }

    else panic("unknown operation");
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

  table = calloc(1, sizeof(struct kvs));
  kvs_init(table, KVS_HASH_SIZE);

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
    snprintf(command, PATH_MAX, "tc qdisc add dev %s clsact", argv[2 + i]);
    assert(system(command) == 0);
    snprintf(command, PATH_MAX, "tc filter add dev %s egress bpf object-pinned /sys/fs/bpf/tps_prim_tc_main", argv[2 + i]);
    assert(system(command) == 0);
    fprintf(stderr, "Main BPF program attached to TC on interface %d\n", interfaces_idx[i]);
  }

  signal(SIGINT, sigint_handler);
  signal(SIGTERM, sigint_handler);
  signal(SIGALRM, sigalrm_handler);

  memset(&primaddr, 0, sizeof(primaddr));
  primaddr.sin_family = AF_INET;
  primaddr.sin_port = htons(FASST_PORT);
  inet_pton(AF_INET, "10.10.1.1", &primaddr.sin_addr);

  // do not join threads, just wait for signal and exit
  for (uint32_t i = 0; i < n_wthreads; i++)  {
    uint32_t *worker_id = malloc(sizeof(uint32_t));
    *worker_id = i;
    pthread_create(&tids[i], NULL, server_handler, worker_id);
  }

  alarm(1);

  fprintf(stderr, "all workers started\n");

  while (!quit) sleep(1);

  for (int i = 0; i < interface_count; i++) 
    bpf_xdp_detach(interfaces_idx[i], xdp_flags, NULL);

  for (int i = 0; i < interface_count; i++) {
		snprintf(command, PATH_MAX, "tc filter del dev %s egress", argv[2 + i]);
		assert(system(command) == 0);
		snprintf(command, PATH_MAX, "tc qdisc del dev %s clsact", argv[2 + i]);
		assert(system(command) == 0);
	}

  assert(system("rm -f /sys/fs/bpf/tps_prim_tc_main") == 0);

  return 0;
}
