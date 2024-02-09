/*
 * ksched.h - the UAPI for ksched and its ioctl's
 */

#pragma once

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * NOTE: normally character devices are dynamically allocated, but for
 * convenience we use 280.
 */
#define KSCHED_MAJOR		280
#define KSCHED_MINOR		0

struct ksched_intr_req {
	size_t			len;
	const void __user	*mask;
};

struct ksched_shm_cpu {
	/* written by userspace */
	unsigned int		gen;
	pid_t			tid;
	unsigned int		mwait_hint;
	unsigned int		sig;
	unsigned int		signum;
	unsigned int		pmc;
	__u64			pmcsel;

	/* written by kernelspace */
	unsigned int		busy;
	unsigned int		last_gen;
	__u64			pmcval;
	__u64			pmctsc;

	/* extra space for future features (and cache alignment) */
	unsigned long		rsv[1];
};

#define KSCHED_MAGIC		0xF0
#define KSCHED_IOC_MAXNR	3

#define KSCHED_IOC_START	_IO(KSCHED_MAGIC, 1)
#define KSCHED_IOC_PARK		_IO(KSCHED_MAGIC, 2)
#define KSCHED_IOC_INTR		_IOW(KSCHED_MAGIC, 3, struct ksched_intr_req)
