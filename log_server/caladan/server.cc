extern "C" {
#include <base/log.h>
#include <net/ip.h>
}

#include "base/init.h"
#include "runtime.h"
#include "thread.h"
#include "sync.h"
#include "base/time.h"
#include "timer.h"
#include "net.h"
#include "proto.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <utility>
#include <memory>
#include <chrono>
#include <vector>
#include <algorithm>
#include <numeric>
#include <random>

namespace {

// log
log_entry *txn_log[16];
thread_local uint32_t log_entry_cnt = 0;

// main processing loop for server
void ServerLoop(int worker_id, rt::UdpConn *c) {
  log_emerg("worker %d started", worker_id);

  message msg;
  netaddr cliaddr;

  while (1) {
    ssize_t ret = c->ReadFrom(&msg, sizeof(msg), &cliaddr);
    if (ret != sizeof(msg)) panic("read error");

    if (msg.type != PktType::kCommit) panic("unknown packet type");

    int cpu_id = rt::read_once(kthread_idx);

    txn_log[cpu_id][log_entry_cnt].key = msg.key;
    memcpy(txn_log[cpu_id][log_entry_cnt].val, msg.val, kValSize);
    txn_log[cpu_id][log_entry_cnt].ver = msg.ver;
    log_entry_cnt = (log_entry_cnt + 1) % kMaxLogEntryNum;

    msg.type = PktType::kAck;

    ret = c->WriteTo(&msg, sizeof(msg), &cliaddr);
    if (ret != sizeof(msg)) panic("couldn't send message");
  }
}

void ServerHandler(void *arg) {
  std::unique_ptr<rt::UdpConn> c(rt::UdpConn::Listen({0, kFasstPort}));
  if (unlikely(c == nullptr)) panic("couldn't listen for control connections");

  while (true) {
    net_req req;
    netaddr raddr;
    ssize_t ret = c->ReadFrom(&req, sizeof(req), &raddr);
    if (ret != sizeof(req)) panic("couldn't read request");

    rt::Spawn([=, &c]{
      union {
        net_resp resp;
        char buf[rt::UdpConn::kMaxPayloadSize];
      };
      resp.nports = req.nports;

      std::vector<rt::Thread> th;

      // Create the worker threads.
      for (int i = 0; i < req.nports; ++i) {
        std::unique_ptr<rt::UdpConn> cin(rt::UdpConn::Listen({0, 0}));
        if (unlikely(cin == nullptr)) panic("couldn't dial data connection");
        resp.ports[i] = cin->LocalAddr().port;
        th.emplace_back(rt::Thread(std::bind(ServerLoop, i, cin.release())));
      }

      // Send the port numbers to the client.
      ssize_t len = sizeof(net_resp) + sizeof(uint16_t) * req.nports;
      if (len > static_cast<ssize_t>(rt::UdpConn::kMaxPayloadSize))
        panic("too big");
      ssize_t ret = c->WriteTo(&resp, len, &raddr);
      if (ret != len) 
        panic("udp write failed, ret = %ld", ret);

      for (auto &t: th)
        t.Join();
    });
  }
}

} // annonymous namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: [cfg_file]" << std::endl;
    return -EINVAL;
  }

  for (int i = 0; i < 16; ++i)
    txn_log[i] = new log_entry[kMaxLogEntryNum];

  log_emerg("finish initialization");

  int ret = runtime_init(argv[1], ServerHandler, NULL);
  if (ret) {
    printf("failed to start client runtime\n");
    return ret;
  }

  return 0;
}
