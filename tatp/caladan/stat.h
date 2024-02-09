// statistics

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

constexpr uint32_t kStatsPollIntv = 1;

template <class T>
T Percentile(std::vector<T> &vectorIn, double percent) {
  if (vectorIn.size() == 0) return (T)0;
  auto nth = vectorIn.begin() + (percent * vectorIn.size()) / 100;
  std::nth_element(vectorIn.begin(), nth, vectorIn.end());
  return *nth;
}