/*
 * ksched.c - an interface to the ksched kernel module
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <base/log.h>

#include "ksched.h"

/* a file descriptor handle to the ksched kernel module */
int ksched_fd;
/* the number of pending interrupts */
int ksched_count;
/* the shared memory region with the kernel module */
struct ksched_shm_cpu *ksched_shm;
/* the set of pending cores to send interrupts to */
cpu_set_t ksched_set;
/* the generation number for each core */
unsigned int ksched_gens[NCPU];


/**
 * ksched_init - initializes the ksched kernel module interface
 *
 * Returns 0 if successful.
 */
int ksched_init(void)
{
	char *ksched_addr;
	int i;

	/* first open the file descriptor */
	ksched_fd = open("/dev/ksched", O_RDWR);
	if (ksched_fd < 0) {
		log_err("Could not find ksched kernel module (%s). Please ensure that "
			    "ksched is compiled and inserted (see README for more details)",
			    strerror(errno));
		return -errno;
	}

	/* then map the shared memory region with the kernel */
	ksched_addr = mmap(NULL, sizeof(struct ksched_shm_cpu) * NCPU,
		    PROT_READ | PROT_WRITE, MAP_SHARED, ksched_fd, 0);
	if (ksched_addr == MAP_FAILED)
		return -errno;

	/* then initialize the generation numbers */
	ksched_shm = (struct ksched_shm_cpu *)ksched_addr;
	for (i = 0; i < NCPU; i++) {
		ksched_gens[i] = load_acquire(&ksched_shm[i].last_gen);
		ksched_idle_hint(i, 0);
	}

        return 0;
}
