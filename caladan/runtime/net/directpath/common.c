
#include <base/kref.h>
#include <base/mempool.h>
#include <runtime/sync.h>
#include <base/log.h>
#include "defs.h"

#ifdef DIRECTPATH

static struct hardware_q *rxq_out[NCPU];
static struct direct_txq *txq_out[NCPU];

/* configuration options */
struct pci_addr nic_pci_addr;
bool cfg_pci_addr_specified;
bool cfg_directpath_enabled;
char directpath_arg[128];

enum {
	RX_MODE_FLOW_STEERING = 0,
	RX_MODE_QUEUE_STEERING,
};

int directpath_mode;

struct mempool directpath_buf_mp;
struct tcache *directpath_buf_tcache;
DEFINE_PERTHREAD(struct tcache_perthread, directpath_buf_pt);

static int parse_directpath_pci(const char *name, const char *val)
{
	int ret;

	ret = pci_str_to_addr(val, &nic_pci_addr);
	if (ret)
		return ret;

	log_info("directpath: specified pci address %s", val);
	cfg_pci_addr_specified = true;
	return 0;
}

static struct cfg_handler directpath_pci_handler = {
	.name = "directpath_pci",
	.fn = parse_directpath_pci,
	.required = false,
};

REGISTER_CFG(directpath_pci_handler);

size_t directpath_rx_buf_pool_sz(unsigned int nrqs)
{
	size_t buflen = MBUF_DEFAULT_LEN;
	buflen *= MAX(24, guaranteedks) * (16 * RQ_NUM_DESC) * 2UL;
	return align_up(buflen, PGSIZE_2MB);
}

void directpath_rx_completion(struct mbuf *m)
{
	preempt_disable();
	tcache_free(&perthread_get(directpath_buf_pt), (void *)m);
	preempt_enable();
}

static int rx_memory_init(void)
{
	int ret;
	size_t rx_len;
	void *rx_buf;

	rx_len = directpath_rx_buf_pool_sz(maxks);
	rx_buf = mem_map_anom(NULL, rx_len, PGSIZE_2MB, 0);
	if (rx_buf == MAP_FAILED)
		return -ENOMEM;

	ret = mempool_create(&directpath_buf_mp, rx_buf, rx_len, PGSIZE_2MB,
			     directpath_get_buf_size());
	if (ret)
		return ret;

	directpath_buf_tcache = mempool_create_tcache(&directpath_buf_mp,
		"runtime_rx_bufs", TCACHE_DEFAULT_MAG_SIZE);
	if (!directpath_buf_tcache)
		return -ENOMEM;

	return 0;
}

static void directpath_softirq_one(struct kthread *k)
{
	struct mbuf *ms[RUNTIME_RX_BATCH_SIZE];
	int cnt;

	cnt = net_ops.rx_batch(k->directpath_rxq, ms, RUNTIME_RX_BATCH_SIZE);
	net_rx_batch(ms, cnt);
}

static void directpath_softirq(void *arg)
{
	struct kthread *k = arg;

	while (true) {
		directpath_softirq_one(k);
		preempt_disable();
		k->directpath_busy = false;
		thread_park_and_preempt_enable();
	}
}

int directpath_init(void)
{
	int ret;

	if (!cfg_directpath_enabled)
		return 0;

	ret = rx_memory_init();
	if (ret)
		return ret;

	/* initialize mlx5 */
	if (strncmp("qs", directpath_arg, 2) != 0) {
		directpath_mode = RX_MODE_FLOW_STEERING;
		ret = mlx5_init_flow_steering(rxq_out, txq_out, maxks, maxks);
		if (ret == 0) {
			log_err("directpath_init: selected flow steering mode");
			return 0;
		}
	}

	if (strncmp("fs", directpath_arg, 2) != 0) {
		directpath_mode = RX_MODE_QUEUE_STEERING;
		ret = mlx5_init_queue_steering(rxq_out, txq_out, maxks, maxks);
		if (ret == 0) {
			log_err("directpath_init: selected queue steering mode");
			return 0;
		}
	}

	if (getuid() != 0)
		log_err("Could not initialize directpath. Please try again as root.");
	else
		log_err("Could not initialize directpath, ret = %d", ret);

	return ret ? ret : -EINVAL;
}

int directpath_init_thread(void)
{
	struct kthread *k = myk();
	struct hardware_queue_spec *hs;
	struct hardware_q *rxq = rxq_out[k->kthread_idx];
	thread_t *th;

	if (!cfg_directpath_enabled)
		return 0;

	th = thread_create(directpath_softirq, k);
	if (!th)
		return -ENOMEM;

	k->directpath_softirq = th;
	rxq->shadow_tail = &k->q_ptrs->directpath_rx_tail;
	hs = &iok.threads[k->kthread_idx].direct_rxq;

	hs->descriptor_log_size = rxq->descriptor_log_size;
	hs->nr_descriptors = rxq->nr_descriptors;
	hs->descriptor_table = ptr_to_shmptr(&netcfg.tx_region,
		rxq->descriptor_table, (1 << hs->descriptor_log_size) * hs->nr_descriptors);
	hs->parity_byte_offset = rxq->parity_byte_offset;
	hs->parity_bit_mask = rxq->parity_bit_mask;
	hs->hwq_type = (directpath_mode == RX_MODE_FLOW_STEERING) ? HWQ_MLX5 : HWQ_MLX5_QSTEERING;
	hs->consumer_idx = ptr_to_shmptr(&netcfg.tx_region, rxq->shadow_tail, sizeof(uint32_t));

	k->directpath_rxq = rxq;
	k->directpath_txq = txq_out[k->kthread_idx];

	tcache_init_perthread(directpath_buf_tcache, &perthread_get(directpath_buf_pt));

	return 0;
}

static DEFINE_SPINLOCK(flow_worker_lock);
static thread_t *flow_worker_th;
static LIST_HEAD(flow_to_register);
static LIST_HEAD(flow_to_deregister);

static void flow_registration_worker(void *arg)
{
	int ret;
	struct flow_registration *f;

	while (true) {
		spin_lock_np(&flow_worker_lock);
		f = list_pop(&flow_to_register, struct flow_registration, flow_reg_link);
		if (f) {
			spin_unlock_np(&flow_worker_lock);
			ret = net_ops.register_flow(f->kthread_affinity, f->e, &f->hw_flow_handle);
			WARN_ON(ret);
			continue;
		}

		f = list_pop(&flow_to_deregister, struct flow_registration, flow_dereg_link);
		if (f) {
			spin_unlock_np(&flow_worker_lock);
			ret = net_ops.deregister_flow(f->e, f->hw_flow_handle);
			WARN_ON(ret);
			kref_put(f->ref, f->release);
			continue;
		}

		flow_worker_th = thread_self();
		thread_park_and_unlock_np(&flow_worker_lock);
	}
}

void register_flow(struct flow_registration *f)
{
	if (!cfg_directpath_enabled)
		return;

	/* take a reference for the hardware flow table */
	kref_get(f->ref);

	spin_lock_np(&flow_worker_lock);
	list_add(&flow_to_register, &f->flow_reg_link);
	if (flow_worker_th) {
		thread_ready(flow_worker_th);
		flow_worker_th = NULL;
	}
	spin_unlock_np(&flow_worker_lock);

}

void deregister_flow(struct flow_registration *f)
{
	if (!cfg_directpath_enabled)
		return;

	spin_lock_np(&flow_worker_lock);
	list_add(&flow_to_deregister, &f->flow_dereg_link);
	if (flow_worker_th) {
		thread_ready(flow_worker_th);
		flow_worker_th = NULL;
	}
	spin_unlock_np(&flow_worker_lock);
}

int directpath_init_late(void)
{
	if (!cfg_directpath_enabled)
		return 0;

	return thread_spawn(flow_registration_worker, NULL);
}

#else

int directpath_init(void)
{
	return 0;
}

int directpath_init_thread(void)
{
	return 0;
}

int directpath_init_late(void)
{
	return 0;
}


#endif
