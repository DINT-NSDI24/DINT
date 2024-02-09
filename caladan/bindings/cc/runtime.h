// the main header for Shenango's runtime

#pragma once

extern "C" {
#include <runtime/runtime.h>
}

#include <functional>
#include <string>

namespace rt {

// The highest number of cores supported.
constexpr unsigned int kCoreLimit = NCPU;

// Initializes the runtime. If successful, calls @main_func and does not return.
int RuntimeInit(std::string cfg_path, std::function<void()> main_func);

// Gets the queueing delay of runqueue (thread queue) + packet queue
inline uint64_t RuntimeQueueUS() { return runtime_queue_us(); }

// Gets an estimate of the instantanious load as measured by the IOKernel.
inline float RuntimeLoad() { return runtime_load(); }

// Gets the current number of active cores
inline unsigned int RuntimeActiveCores() { return runtime_active_cores(); }

// Gets the maximum number of cores the runtime could run on.
inline unsigned int RuntimeMaxCores() { return runtime_max_cores(); }

// Gets the guaranteed number of cores the runtime will at least get.
inline unsigned int RuntimeGuaranteedCores() {
  return runtime_guaranteed_cores();
}

};  // namespace rt
