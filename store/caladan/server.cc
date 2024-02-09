extern "C" {
#include <base/log.h>
#include <net/ip.h>
}

#include "base/init.h"
#include "runtime.h"
#include "thread.h"
#include "sync.h"
#include "timer.h"
#include "net.h"
#include "utils.h"
#include "tatp.h"
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

// the main table
kvs *table;

// main processing loop for server
void ServerLoop(int worker_id, rt::UdpConn *c) {
  log_emerg("worker %d started", worker_id);

  message msg;
  netaddr cliaddr;

  while (1) {
    ssize_t _ret = c->ReadFrom(&msg, sizeof(message), &cliaddr);
    if (_ret != sizeof(message)) panic("couldn't receive message");

    int ret;
    switch (msg.type) {
      case PktType::kRead:
        ret = kvs_get(table, msg.key, msg.val, &msg.ver);
        if (ret == 0) msg.type = PktType::kGrantRead;
        else msg.type = PktType::kNotExist;
        ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
        if (ret != sizeof(message)) panic("couldn't send message");
        break;

      case PktType::kSet:
        ret = kvs_set(table, msg.key, msg.val);
        if (ret == 0) msg.type = PktType::kSetAck;
        else msg.type = PktType::kNotExist;
        ret = c->WriteTo(&msg, sizeof(message), &cliaddr);
        if (ret != sizeof(message)) panic("couldn't send message");
        break;

      default:
        panic("unknown operation %d", msg.type);
    }
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

  table = new kvs();
  kvs_init(table, kSubscriberNum * 18 / kKeysPerEntry);
  populate_table(table);

  log_emerg("finish initialization");

  int ret = runtime_init(argv[1], ServerHandler, NULL);
  if (ret) {
    printf("failed to start client runtime\n");
    return ret;
  }

  return 0;
}