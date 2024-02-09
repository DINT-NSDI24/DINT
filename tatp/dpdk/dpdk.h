// dpdk utilities

#pragma once

#include <rte_ethdev.h>
#include <rte_vect.h>

#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_PKT_BURST     64
#define BURST_TX_DRAIN_US 20

#define MEMPOOL_CACHE_SIZE 256
#define MAX_RX_QUEUE_PER_LCORE 16

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define	MAX_TX_BURST	  (MAX_PKT_BURST / 2)

#define NB_SOCKETS        8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	  3

/* Used to mark destination port as 'invalid'. */
#define	BAD_PORT ((uint16_t)-1)

#define FWDSTEP	4

/* replace first 12B of the ethernet header. */
#define	MASK_ETH 0x3f

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
	uint16_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;
