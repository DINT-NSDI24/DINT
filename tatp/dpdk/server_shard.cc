#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vect.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <vector>

#include "dpdk.h"
#include "kvs.h"
#include "net.h"
#include "tatp.h"
#include "utils.h"

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_LCORE
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

/* Global variables. */

static int numa_on = 1;   /**< NUMA is enabled by default. */
static int per_port_pool; /**< Use separate buffer pools per port; disabled */
                          /**< by default */

volatile bool force_quit;

/* ethernet addresses of ports */
struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct lcore_params {
  uint16_t port_id;
  uint8_t queue_id;
  uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {2, 0, 3}, {2, 1, 5},  {2, 2, 7},  {2, 3, 9},
    {2, 4, 11}, {2, 5, 13}, {2, 6, 15}, {2, 7, 17},
};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params =
    sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);

static struct rte_eth_conf port_conf = {
    .rxmode =
        {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
            .split_hdr_size = 0,
            .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
        },
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    .rx_adv_conf =
        {
            .rss_conf =
                {
                    .rss_key = NULL,
                    .rss_hf = RTE_ETH_RSS_UDP,
                },
        },
};

static uint32_t max_pkt_len;

static struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][NB_SOCKETS];

thread_local uint64_t prev_tsc, cur_tsc, drain_tsc;

// map 0-999 to 12b, 4b/digit decimal representation
uint16_t *map_1000;

// the tatp tables
// tables[0]: subscriber
// tables[1]: second_subscriber
// tables[2]: access_info
// tables[3]: special_facility
// tables[4]: call_forwarding
static kvs *tables[kTableNum];

// transaction locks
static volatile int txn_locks[kTableNum][kLockNum];

// log
static log_entry *txn_log[64];
static thread_local uint32_t log_entry_cnt = 0;

void populate_tables() {
  for (int i = 0; i < kTableNum; i++) tables[i] = new kvs();

  kvs_init(tables[TableType::kSubscriber],
           kSubscriberNum * 3 / 2 / kKeysPerEntry);
  kvs_init(tables[TableType::kSecondSubscriber],
           kSubscriberNum * 3 / 2 / kKeysPerEntry);
  kvs_init(tables[TableType::kAccessInfo],
           kSubscriberNum * 15 / 4 / kKeysPerEntry);
  kvs_init(tables[TableType::kSpecialFacility],
           kSubscriberNum * 15 / 4 / kKeysPerEntry);
  kvs_init(tables[TableType::kCallForwarding],
           kSubscriberNum * 45 / 8 / kKeysPerEntry);

  populate_subscriber_table(tables[TableType::kSubscriber]);
  populate_second_subscriber_table(tables[TableType::kSecondSubscriber]);
  populate_access_info_table(tables[TableType::kAccessInfo]);
  populate_specfac_and_callfwd_table(tables[TableType::kSpecialFacility],
                                     tables[TableType::kCallForwarding]);
}

static int check_lcore_params(void) {
  uint8_t queue, lcore;
  uint16_t i;
  int socketid;

  for (i = 0; i < nb_lcore_params; ++i) {
    queue = lcore_params[i].queue_id;
    if (queue >= MAX_RX_QUEUE_PER_PORT) {
      printf("invalid queue number: %hhu\n", queue);
      return -1;
    }
    lcore = lcore_params[i].lcore_id;
    if (!rte_lcore_is_enabled(lcore)) {
      printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
      return -1;
    }
    if ((socketid = rte_lcore_to_socket_id(lcore) != 0) && (numa_on == 0)) {
      printf("warning: lcore %hhu is on socket %d with numa off \n", lcore,
             socketid);
    }
  }
  return 0;
}

static int check_port_config(void) {
  uint16_t portid;
  uint16_t i;

  for (i = 0; i < nb_lcore_params; ++i) {
    portid = lcore_params[i].port_id;
    if ((enabled_port_mask & (1 << portid)) == 0) {
      printf("port %u is not enabled in port mask\n", portid);
      return -1;
    }
    if (!rte_eth_dev_is_valid_port(portid)) {
      printf("port %u is not present on the board\n", portid);
      return -1;
    }
  }
  return 0;
}

static uint8_t get_port_n_rx_queues(const uint16_t port) {
  int queue = -1;
  uint16_t i;

  for (i = 0; i < nb_lcore_params; ++i) {
    if (lcore_params[i].port_id == port) {
      if (lcore_params[i].queue_id == queue + 1)
        queue = lcore_params[i].queue_id;
      else
        rte_exit(EXIT_FAILURE,
                 "queue ids of the port %d must be"
                 " in sequence and must start with 0\n",
                 lcore_params[i].port_id);
    }
  }
  return (uint8_t)(++queue);
}

static int init_lcore_rx_queues(void) {
  uint16_t i, nb_rx_queue;
  uint8_t lcore;

  for (i = 0; i < nb_lcore_params; ++i) {
    lcore = lcore_params[i].lcore_id;
    nb_rx_queue = lcore_conf[lcore].n_rx_queue;
    if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
      printf("error: too many queues (%u) for lcore: %u\n",
             (unsigned)nb_rx_queue + 1, (unsigned)lcore);
      return -1;
    } else {
      lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
          lcore_params[i].port_id;
      lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
          lcore_params[i].queue_id;
      lcore_conf[lcore].n_rx_queue++;
    }
  }
  return 0;
}

/* display usage */
static void print_usage(const char *prgname) {
  fprintf(stderr,
          "%s [EAL options] --"
          " -p PORTMASK"
          " [-P]"
          " --config (port,queue,lcore)[,(port,queue,lcore)]"
          " [--rx-queue-size NPKTS]"
          " [--tx-queue-size NPKTS]"
          " [--max-pkt-len PKTLEN]"
          " [--no-numa]"
          " [--per-port-pool]\n\n"

          "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
          "  -P : Enable promiscuous mode\n"
          "  --config (port,queue,lcore): Rx queue configuration\n"
          "  --rx-queue-size NPKTS: Rx queue size in decimal\n"
          "            Default: %d\n"
          "  --tx-queue-size NPKTS: Tx queue size in decimal\n"
          "            Default: %d\n"
          "  --max-pkt-len PKTLEN: maximum packet length in decimal (64-9600)\n"
          "  --no-numa: Disable numa awareness\n"
          "  --per-port-pool: Use separate buffer pool per port\n\n",
          prgname, RTE_TEST_RX_DESC_DEFAULT, RTE_TEST_TX_DESC_DEFAULT);
}

static int parse_max_pkt_len(const char *pktlen) {
  char *end = NULL;
  unsigned long len;

  /* parse decimal string */
  len = strtoul(pktlen, &end, 10);
  if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0')) return -1;

  if (len == 0) return -1;

  return len;
}

static int parse_portmask(const char *portmask) {
  char *end = NULL;
  unsigned long pm;

  /* parse hexadecimal string */
  pm = strtoul(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0')) return 0;

  return pm;
}

static int parse_config(const char *q_arg) {
  char s[256];
  const char *p, *p0 = q_arg;
  char *end;
  enum fieldnames { FLD_PORT = 0, FLD_QUEUE, FLD_LCORE, _NUM_FLD };
  unsigned long int_fld[_NUM_FLD];
  char *str_fld[_NUM_FLD];
  int i;
  unsigned size;

  nb_lcore_params = 0;

  while ((p = strchr(p0, '(')) != NULL) {
    ++p;
    if ((p0 = strchr(p, ')')) == NULL) return -1;

    size = p0 - p;
    if (size >= sizeof(s)) return -1;

    snprintf(s, sizeof(s), "%.*s", size, p);
    if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
      return -1;
    for (i = 0; i < _NUM_FLD; i++) {
      errno = 0;
      int_fld[i] = strtoul(str_fld[i], &end, 0);
      if (errno != 0 || end == str_fld[i] || int_fld[i] > 255) return -1;
    }
    if (nb_lcore_params >= MAX_LCORE_PARAMS) {
      printf("exceeded max number of lcore params: %hu\n", nb_lcore_params);
      return -1;
    }
    lcore_params_array[nb_lcore_params].port_id = (uint8_t)int_fld[FLD_PORT];
    lcore_params_array[nb_lcore_params].queue_id = (uint8_t)int_fld[FLD_QUEUE];
    lcore_params_array[nb_lcore_params].lcore_id = (uint8_t)int_fld[FLD_LCORE];
    ++nb_lcore_params;
  }
  lcore_params = lcore_params_array;
  return 0;
}

static void parse_queue_size(const char *queue_size_arg, uint16_t *queue_size,
                             int rx) {
  char *end = NULL;
  unsigned long value;

  /* parse decimal string */
  value = strtoul(queue_size_arg, &end, 10);
  if ((queue_size_arg[0] == '\0') || (end == NULL) || (*end != '\0') ||
      (value == 0)) {
    if (rx == 1)
      rte_exit(EXIT_FAILURE, "Invalid rx-queue-size\n");
    else
      rte_exit(EXIT_FAILURE, "Invalid tx-queue-size\n");

    return;
  }

  if (value > UINT16_MAX) {
    if (rx == 1)
      rte_exit(EXIT_FAILURE, "rx-queue-size %lu > %d\n", value, UINT16_MAX);
    else
      rte_exit(EXIT_FAILURE, "tx-queue-size %lu > %d\n", value, UINT16_MAX);

    return;
  }

  *queue_size = value;
}

#define MAX_JUMBO_PKT_LEN 9600

static const char short_options[] =
    "p:" /* portmask */
    "P"  /* promiscuous */
    ;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_RX_QUEUE_SIZE "rx-queue-size"
#define CMD_LINE_OPT_TX_QUEUE_SIZE "tx-queue-size"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_MAX_PKT_LEN "max-pkt-len"
#define CMD_LINE_OPT_PER_PORT_POOL "per-port-pool"

enum {
  /* long options mapped to a short option */

  /* first long only option value must be >= 256, so that we won't
   * conflict with short options */
  CMD_LINE_OPT_MIN_NUM = 256,
  CMD_LINE_OPT_CONFIG_NUM,
  CMD_LINE_OPT_RX_QUEUE_SIZE_NUM,
  CMD_LINE_OPT_TX_QUEUE_SIZE_NUM,
  CMD_LINE_OPT_NO_NUMA_NUM,
  CMD_LINE_OPT_MAX_PKT_LEN_NUM,
  CMD_LINE_OPT_PARSE_PER_PORT_POOL,
};

static const struct option lgopts[] = {
    {CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
    {CMD_LINE_OPT_RX_QUEUE_SIZE, 1, 0, CMD_LINE_OPT_RX_QUEUE_SIZE_NUM},
    {CMD_LINE_OPT_TX_QUEUE_SIZE, 1, 0, CMD_LINE_OPT_TX_QUEUE_SIZE_NUM},
    {CMD_LINE_OPT_NO_NUMA, 0, 0, CMD_LINE_OPT_NO_NUMA_NUM},
    {CMD_LINE_OPT_MAX_PKT_LEN, 1, 0, CMD_LINE_OPT_MAX_PKT_LEN_NUM},
    {CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
    {NULL, 0, 0, 0}};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports)                                                     \
  RTE_MAX(                                                                  \
      (nports * nb_rx_queue * nb_rxd + nports * nb_lcores * MAX_PKT_BURST + \
       nports * n_tx_queue * nb_txd + nb_lcores * MEMPOOL_CACHE_SIZE),      \
      (unsigned)8192)

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv) {
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];

  argvopt = argv;

  /* Error or normal output strings. */
  while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
                            &option_index)) != EOF) {
    switch (opt) {
      /* portmask */
      case 'p':
        enabled_port_mask = parse_portmask(optarg);
        if (enabled_port_mask == 0) {
          fprintf(stderr, "Invalid portmask\n");
          print_usage(prgname);
          return -1;
        }
        break;

      case 'P':
        promiscuous_on = 1;
        break;

      /* long options */
      case CMD_LINE_OPT_CONFIG_NUM:
        ret = parse_config(optarg);
        if (ret) {
          fprintf(stderr, "Invalid config\n");
          print_usage(prgname);
          return -1;
        }
        // lcore_params = 1;
        break;

      case CMD_LINE_OPT_RX_QUEUE_SIZE_NUM:
        parse_queue_size(optarg, &nb_rxd, 1);
        break;

      case CMD_LINE_OPT_TX_QUEUE_SIZE_NUM:
        parse_queue_size(optarg, &nb_txd, 0);
        break;

      case CMD_LINE_OPT_NO_NUMA_NUM:
        numa_on = 0;
        break;

      case CMD_LINE_OPT_MAX_PKT_LEN_NUM:
        max_pkt_len = parse_max_pkt_len(optarg);
        break;

      case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
        printf("per port buffer pool is enabled\n");
        per_port_pool = 1;
        break;

      default:
        print_usage(prgname);
        return -1;
    }
  }

  if (optind >= 0) argv[optind - 1] = prgname;

  ret = optind - 1;
  optind = 1; /* reset getopt lib */
  return ret;
}

static void print_ethaddr(const char *name,
                          const struct rte_ether_addr *eth_addr) {
  char buf[RTE_ETHER_ADDR_FMT_SIZE];
  rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
  printf("%s%s", name, buf);
}

int init_mem(uint16_t portid, unsigned int nb_mbuf) {
  int socketid;
  unsigned lcore_id;
  char s[64];

  for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
    if (rte_lcore_is_enabled(lcore_id) == 0) continue;

    if (numa_on)
      socketid = rte_lcore_to_socket_id(lcore_id);
    else
      socketid = 0;

    if (socketid >= NB_SOCKETS) {
      rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
               socketid, lcore_id, NB_SOCKETS);
    }

    if (pktmbuf_pool[portid][socketid] == NULL) {
      snprintf(s, sizeof(s), "mbuf_pool_%d:%d", portid, socketid);
      pktmbuf_pool[portid][socketid] =
          rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
                                  RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
      if (pktmbuf_pool[portid][socketid] == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n",
                 socketid);
      else
        printf("Allocated mbuf pool on socket %d\n", socketid);
    }
  }
  return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
  uint16_t portid;
  uint8_t count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;
  int ret;
  char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

  printf("\nChecking link status");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    if (force_quit) return;
    all_ports_up = 1;
    RTE_ETH_FOREACH_DEV(portid) {
      if (force_quit) return;
      if ((port_mask & (1 << portid)) == 0) continue;
      memset(&link, 0, sizeof(link));
      ret = rte_eth_link_get_nowait(portid, &link);
      if (ret < 0) {
        all_ports_up = 0;
        if (print_flag == 1)
          printf("Port %u link get failed: %s\n", portid, rte_strerror(-ret));
        continue;
      }
      /* print link status if flag set */
      if (print_flag == 1) {
        rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
        printf("Port %d %s\n", portid, link_status_text);
        continue;
      }
      /* clear all_ports_up flag if any link down */
      if (link.link_status == RTE_ETH_LINK_DOWN) {
        all_ports_up = 0;
        break;
      }
    }
    /* after finally printing all link status, get out */
    if (print_flag == 1) break;

    if (all_ports_up == 0) {
      printf(".");
      fflush(stdout);
      rte_delay_ms(CHECK_INTERVAL);
    }

    /* set the print_flag if all ports up or timeout */
    if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
      print_flag = 1;
      printf("done\n");
    }
  }
}

static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    force_quit = true;
  }
}

static uint32_t eth_dev_get_overhead_len(uint32_t max_rx_pktlen,
                                         uint16_t max_mtu) {
  uint32_t overhead_len;

  if (max_mtu != UINT16_MAX && max_rx_pktlen > max_mtu)
    overhead_len = max_rx_pktlen - max_mtu;
  else
    overhead_len = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

  return overhead_len;
}

static int config_port_max_pkt_len(struct rte_eth_conf *conf,
                                   struct rte_eth_dev_info *dev_info) {
  uint32_t overhead_len;

  if (max_pkt_len == 0) return 0;

  if (max_pkt_len < RTE_ETHER_MIN_LEN || max_pkt_len > MAX_JUMBO_PKT_LEN)
    return -1;

  overhead_len =
      eth_dev_get_overhead_len(dev_info->max_rx_pktlen, dev_info->max_mtu);
  conf->rxmode.mtu = max_pkt_len - overhead_len;

  if (conf->rxmode.mtu > RTE_ETHER_MTU)
    conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

  return 0;
}

static void l3fwd_poll_resource_setup(void) {
  uint8_t nb_rx_queue, queue, socketid;
  struct rte_eth_dev_info dev_info;
  uint32_t n_tx_queue, nb_lcores;
  struct rte_eth_txconf *txconf;
  struct lcore_conf *qconf;
  uint16_t queueid, portid;
  unsigned int nb_ports;
  unsigned int lcore_id;
  int ret;

  if (check_lcore_params() < 0)
    rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

  ret = init_lcore_rx_queues();
  if (ret < 0) rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

  nb_ports = rte_eth_dev_count_avail();

  if (check_port_config() < 0)
    rte_exit(EXIT_FAILURE, "check_port_config failed\n");

  nb_lcores = rte_lcore_count();

  /* initialize all ports */
  RTE_ETH_FOREACH_DEV(portid) {
    struct rte_eth_conf local_port_conf = port_conf;

    /* skip ports that are not enabled */
    if ((enabled_port_mask & (1 << portid)) == 0) {
      printf("\nSkipping disabled port %d\n", portid);
      continue;
    }

    /* init port */
    printf("Initializing port %d ... ", portid);
    fflush(stdout);

    nb_rx_queue = get_port_n_rx_queues(portid);
    n_tx_queue = nb_lcores;
    if (n_tx_queue > MAX_TX_QUEUE_PER_PORT) n_tx_queue = MAX_TX_QUEUE_PER_PORT;
    printf("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue,
           (unsigned)n_tx_queue);

    ret = rte_eth_dev_info_get(portid, &dev_info);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
               portid, strerror(-ret));

    ret = config_port_max_pkt_len(&local_port_conf, &dev_info);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, "Invalid max packet length: %u (port %u)\n",
               max_pkt_len, portid);

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
      local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    if (!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) ||
        !(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)) {
      rte_panic("checksum offload not supported\n");
    } else
      local_port_conf.txmode.offloads |=
          (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM);

    local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
        dev_info.flow_type_rss_offloads;

    if (dev_info.max_rx_queues == 1)
      local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
        port_conf.rx_adv_conf.rss_conf.rss_hf) {
      printf(
          "Port %u modified RSS hash function based on hardware support,"
          "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
          portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
          local_port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

    ret = rte_eth_dev_configure(portid, nb_rx_queue, (uint16_t)n_tx_queue,
                                &local_port_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret,
               portid);

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
    if (ret < 0)
      rte_exit(EXIT_FAILURE,
               "Cannot adjust number of descriptors: err=%d, "
               "port=%d\n",
               ret, portid);

    ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%d\n", ret,
               portid);

    print_ethaddr(" Address:", &ports_eth_addr[portid]);
    printf(", ");

    /* init memory */
    if (!per_port_pool) {
      /* portid = 0; this is *not* signifying the first port,
       * rather, it signifies that portid is ignored.
       */
      ret = init_mem(0, NB_MBUF(nb_ports));
    } else {
      ret = init_mem(portid, NB_MBUF(1));
    }
    if (ret < 0) rte_exit(EXIT_FAILURE, "init_mem failed\n");

    /* init one TX queue per couple (lcore,port) */
    queueid = 0;
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
      if (rte_lcore_is_enabled(lcore_id) == 0) continue;

      if (numa_on)
        socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
      else
        socketid = 0;

      printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
      fflush(stdout);

      txconf = &dev_info.default_txconf;
      txconf->offloads = local_port_conf.txmode.offloads;
      ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid, txconf);
      if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "rte_eth_tx_queue_setup: err=%d, "
                 "port=%d\n",
                 ret, portid);

      qconf = &lcore_conf[lcore_id];
      qconf->tx_queue_id[portid] = queueid;
      queueid++;

      qconf->tx_port_id[qconf->n_tx_port] = portid;
      qconf->n_tx_port++;
    }
    printf("\n");
  }

  for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
    if (rte_lcore_is_enabled(lcore_id) == 0) continue;
    qconf = &lcore_conf[lcore_id];
    printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
    fflush(stdout);
    /* init RX queues */
    for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
      struct rte_eth_rxconf rxq_conf;

      portid = qconf->rx_queue_list[queue].port_id;
      queueid = qconf->rx_queue_list[queue].queue_id;

      if (numa_on)
        socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
      else
        socketid = 0;

      printf("rxq=%d,%d,%d ", portid, queueid, socketid);
      fflush(stdout);

      ret = rte_eth_dev_info_get(portid, &dev_info);
      if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "Error during getting device (port %u) info: %s\n", portid,
                 strerror(-ret));

      rxq_conf = dev_info.default_rxconf;
      rxq_conf.offloads = port_conf.rxmode.offloads;
      if (!per_port_pool)
        ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid,
                                     &rxq_conf, pktmbuf_pool[0][socketid]);
      else
        ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid,
                                     &rxq_conf, pktmbuf_pool[portid][socketid]);
      if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret,
                 portid);
    }
  }
}

/* Send burst of packets on an output interface */
static inline int send_burst(struct lcore_conf *qconf, uint16_t n,
                             uint16_t port) {
  struct rte_mbuf **m_table;
  int ret;
  uint16_t queueid;

  queueid = qconf->tx_queue_id[port];
  m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

  ret = rte_eth_tx_burst(port, queueid, m_table, n);
  if (unlikely(ret < n)) {
    do {
      rte_pktmbuf_free(m_table[ret]);
    } while (++ret < n);
  }

  return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int send_single_packet(struct lcore_conf *qconf,
                                     struct rte_mbuf *m, uint16_t port) {
  uint16_t len;
  // uint64_t diff_tsc;

  len = qconf->tx_mbufs[port].len;
  qconf->tx_mbufs[port].m_table[len] = m;
  len++;

  // cur_tsc = rte_rdtsc();
  // diff_tsc = cur_tsc - prev_tsc;

  // if (unlikely(diff_tsc > drain_tsc)) {
  //   send_burst(qconf, len, port);
  //   len = 0;
  //   prev_tsc = cur_tsc;
  // }

  // if (unlikely(len == MAX_PKT_BURST)) {
  //   send_burst(qconf, len, port);
  //   len = 0;
  // }

  qconf->tx_mbufs[port].len = len;
  return 0;
}

static void update_addr(struct rte_mbuf *m, struct rte_ether_hdr *eth_h,
                        struct rte_ipv4_hdr *ip_h, struct rte_udp_hdr *udp_h) {
  struct rte_ether_addr eth_addr;
  uint32_t ip_addr;
  uint16_t udp_port;

  // swap the source and destination addresses/ports
  rte_ether_addr_copy(&eth_h->src_addr, &eth_addr);
  rte_ether_addr_copy(&eth_h->dst_addr, &eth_h->src_addr);
  rte_ether_addr_copy(&eth_addr, &eth_h->dst_addr);
  ip_addr = ip_h->src_addr;
  ip_h->src_addr = ip_h->dst_addr;
  ip_h->dst_addr = ip_addr;
  udp_port = udp_h->src_port;
  udp_h->src_port = udp_h->dst_port;
  udp_h->dst_port = udp_port;

  /* set checksum parameters for HW offload */
  m->ol_flags |=
      (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM);
  m->l2_len = sizeof(struct rte_ether_hdr);
  m->l3_len = sizeof(struct rte_ipv4_hdr);
  ip_h->hdr_checksum = 0;
  udp_h->dgram_cksum = rte_ipv4_phdr_cksum(ip_h, m->ol_flags);
}

static inline void process_one_packet(struct rte_mbuf *m, uint16_t portid,
                                      struct lcore_conf *qconf) {
  struct rte_udp_hdr *udp_h;
  struct rte_ipv4_hdr *ip_h;
  struct rte_ether_hdr *eth_h;

  eth_h = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  ip_h = (struct rte_ipv4_hdr *)(eth_h + 1);
  udp_h = (struct rte_udp_hdr *)(ip_h + 1);

  message *msg = (message *)(udp_h + 1);

  if (msg->type == PktType::kRead) {
    int ret = kvs_get(tables[msg->table], msg->key, msg->val, &msg->ver);
    if (ret == 0)
      msg->type = PktType::kGrantRead;
    else
      msg->type = PktType::kNotExist;

    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kAcquireLock) {
    int ret = __sync_val_compare_and_swap(
        &txn_locks[msg->table][lock_hash(tables[msg->table], msg->key)], 0, 1);
    if (ret == 0) {
      msg->type = PktType::kGrantLock;
      update_addr(m, eth_h, ip_h, udp_h);
      send_single_packet(qconf, m, portid);
    } else if (ret == 1) {
      msg->type = PktType::kRejectLock;
      update_addr(m, eth_h, ip_h, udp_h);
      send_single_packet(qconf, m, portid);
    } else
      panic("unknown lock state");
  }

  else if (msg->type == PktType::kAbort) {
    __sync_val_compare_and_swap(
        &txn_locks[msg->table][lock_hash(tables[msg->table], msg->key)], 1, 0);
    msg->type = PktType::kAbortAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kCommitPrim) {
    kvs_set(tables[msg->table], msg->key, msg->val);
    __sync_val_compare_and_swap(
        &txn_locks[msg->table][lock_hash(tables[msg->table], msg->key)], 1, 0);

    msg->type = PktType::kCommitPrimAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kInsertPrim) {
    kvs_insert(tables[msg->table], msg->key, msg->val);
    __sync_val_compare_and_swap(
        &txn_locks[msg->table][lock_hash(tables[msg->table], msg->key)], 1, 0);

    msg->type = PktType::kInsertPrimAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kDeletePrim) {
    kvs_delete(tables[msg->table], msg->key);
    __sync_val_compare_and_swap(
        &txn_locks[msg->table][lock_hash(tables[msg->table], msg->key)], 1, 0);

    msg->type = PktType::kDeletePrimAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kCommitBck) {
    kvs_set(tables[msg->table], msg->key, msg->val);
    msg->type = PktType::kCommitBckAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kInsertBck) {
    kvs_insert(tables[msg->table], msg->key, msg->val);
    msg->type = PktType::kInsertBckAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kDeleteBck) {
    kvs_delete(tables[msg->table], msg->key);
    msg->type = PktType::kDeleteBckAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kCommitLog) {
    int cpu_id = rte_lcore_id();
    int log_id = cpu_id;
    txn_log[log_id][log_entry_cnt].is_del = 0;
    txn_log[log_id][log_entry_cnt].table = msg->table;
    txn_log[log_id][log_entry_cnt].key = msg->key;
    memcpy(txn_log[log_id][log_entry_cnt].val, msg->val, kValSize);
    txn_log[log_id][log_entry_cnt].ver = msg->ver;
    log_entry_cnt = (log_entry_cnt + 1) % kMaxLogEntryNum;

    msg->type = PktType::kCommitLogAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }

  else if (msg->type == PktType::kDeleteLog) {
    int cpu_id = rte_lcore_id();
    int log_id = cpu_id;
    txn_log[log_id][log_entry_cnt].is_del = 1;
    txn_log[log_id][log_entry_cnt].table = msg->table;
    txn_log[log_id][log_entry_cnt].key = msg->key;
    txn_log[log_id][log_entry_cnt].ver = msg->ver;
    log_entry_cnt = (log_entry_cnt + 1) % kMaxLogEntryNum;

    msg->type = PktType::kDeleteLogAck;
    update_addr(m, eth_h, ip_h, udp_h);
    send_single_packet(qconf, m, portid);
  }
}

static inline void process_packets(int nb_rx, struct rte_mbuf **pkts_burst,
                                   uint16_t portid, struct lcore_conf *qconf) {
  int32_t j;

  /* Prefetch first packets */
  for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
    rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));

  /* Prefetch and forward already prefetched packets. */
  for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
    rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));
    process_one_packet(pkts_burst[j], portid, qconf);
  }

  /* Forward remaining prefetched packets */
  for (; j < nb_rx; j++) process_one_packet(pkts_burst[j], portid, qconf);
}

/* main processing loop */
int main_loop(__rte_unused void *dummy) {
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
  unsigned lcore_id;
  uint64_t diff_tsc;
  int i, nb_rx;
  uint16_t portid;
  uint8_t queueid;
  struct lcore_conf *qconf;
  // uint64_t pkt_cnt = 0;
  // uint64_t log_tsc = rte_get_tsc_hz();
  // drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

  lcore_id = rte_lcore_id();
  qconf = &lcore_conf[lcore_id];

  const uint16_t n_rx_q = qconf->n_rx_queue;
  const uint16_t n_tx_p = qconf->n_tx_port;
  if (n_rx_q == 0) {
    RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
    return 0;
  }

  RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

  for (i = 0; i < n_rx_q; i++) {
    portid = qconf->rx_queue_list[i].port_id;
    queueid = qconf->rx_queue_list[i].queue_id;
    RTE_LOG(INFO, L3FWD, " -- lcoreid=%u portid=%u rxqueueid=%hhu\n", lcore_id,
            portid, queueid);
  }

  cur_tsc = rte_rdtsc();
  prev_tsc = cur_tsc;

  while (!force_quit) {
    /*
     * TX burst queue drain
     */
    // diff_tsc = cur_tsc - prev_tsc;
    // if (unlikely(diff_tsc > drain_tsc)) {
    //   for (i = 0; i < n_tx_p; ++i) {
    //     portid = qconf->tx_port_id[i];
    //     if (qconf->tx_mbufs[portid].len == 0) continue;
    //     send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
    //     qconf->tx_mbufs[portid].len = 0;
    //   }

    //   prev_tsc = cur_tsc;
    // }

    // if (unlikely(diff_tsc > log_tsc)) {
    //   printf("pkt for lcore %u: %lu\n", lcore_id, pkt_cnt);
    //   pkt_cnt = 0;
    //   prev_tsc = cur_tsc;
    // }

    for (i = 0; i < n_tx_p; ++i) {
      portid = qconf->tx_port_id[i];
      if (qconf->tx_mbufs[portid].len == 0) continue;
      send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
      qconf->tx_mbufs[portid].len = 0;
    }

    /*
     * Read packet from RX queues
     */
    for (i = 0; i < n_rx_q; ++i) {
      portid = qconf->rx_queue_list[i].port_id;
      queueid = qconf->rx_queue_list[i].queue_id;
      nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
      if (nb_rx == 0) continue;
      // pkt_cnt += nb_rx;

      process_packets(nb_rx, pkts_burst, portid, qconf);
    }

    // cur_tsc = rte_rdtsc();
  }

  return 0;
}

int main(int argc, char **argv) {
  create_map1000();
  populate_tables();

  for (int i = 0; i < 64; ++i) txn_log[i] = new log_entry[kMaxLogEntryNum];

  RTE_LOG(INFO, L3FWD, "finish txn init\n");

  int ret;
  uint16_t portid;

  /* init EAL */
  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
  argc -= ret;
  argv += ret;

  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* parse application arguments (after the EAL ones) */
  ret = parse_args(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

  l3fwd_poll_resource_setup();

  /* start ports */
  RTE_ETH_FOREACH_DEV(portid) {
    if ((enabled_port_mask & (1 << portid)) == 0) {
      continue;
    }
    /* Start device */
    ret = rte_eth_dev_start(portid);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret,
               portid);

    /*
     * If enabled, put device in promiscuous mode.
     * This allows IO forwarding mode to forward packets
     * to itself through 2 cross-connected  ports of the
     * target machine.
     */
    if (promiscuous_on) {
      ret = rte_eth_promiscuous_enable(portid);
      if (ret != 0)
        rte_exit(EXIT_FAILURE, "rte_eth_promiscuous_enable: err=%s, port=%u\n",
                 rte_strerror(-ret), portid);
    }
  }

  printf("\n");

  check_all_ports_link_status(enabled_port_mask);

  ret = 0;
  /* launch per-lcore init on every lcore */
  rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);

  rte_eal_mp_wait_lcore();

  RTE_ETH_FOREACH_DEV(portid) {
    if ((enabled_port_mask & (1 << portid)) == 0) continue;
    printf("Closing port %d...", portid);
    ret = rte_eth_dev_stop(portid);
    if (ret != 0) printf("rte_eth_dev_stop: err=%d, port=%u\n", ret, portid);
    rte_eth_dev_close(portid);
    printf(" Done\n");
  }

  /* clean up the EAL */
  rte_eal_cleanup();

  printf("Bye...\n");

  return ret;
}
