// some common definitions

#pragma once

#include <stdint.h>
#include <linux/types.h>
#include <stddef.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define panic(fmt, ...)					\
do {fprintf(stderr, fmt, ##__VA_ARGS__);	\
  exit(EXIT_FAILURE);} while (0)

constexpr int kMaxLogEntryNum = 1000000;
constexpr int kValSize = 40;

struct log_entry {
  uint64_t key;            // key
  uint8_t val[kValSize];   // value
  uint32_t ver;            // version
};
