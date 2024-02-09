#!/usr/bin/python3

import subprocess
import os
from time import sleep
import sys

servers = ['clnode257.clemson.cloudlab.us', 'clnode280.clemson.cloudlab.us', 'clnode255.clemson.cloudlab.us']
clients = ['clnode254.clemson.cloudlab.us', 'clnode274.clemson.cloudlab.us', 'clnode275.clemson.cloudlab.us', 'clnode281.clemson.cloudlab.us', 'clnode261.clemson.cloudlab.us', 'clnode272.clemson.cloudlab.us', 'clnode256.clemson.cloudlab.us', 'clnode270.clemson.cloudlab.us', 'clnode283.clemson.cloudlab.us', 'clnode260.clemson.cloudlab.us']

def run_expr(num_of_uthreads):
  for machine in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, "sudo ./dev/ebpf-txn/caladan/iokerneld"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(10)

  for i, server in enumerate(servers):
    sleep(0.1)
    cpu_set_cmd = 'cd dev/ebpf-txn && ./cpu_setup.sh 8'
    subprocess.call(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', server, cpu_set_cmd], shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa',
             server, f"cd dev/ebpf-txn/tatp/ebpf && sudo taskset -c 3,5,7,9,11,13,15,17 ./shard {i+1} 16 ens2f0np0"], shell=False, stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(10)

  executors = []
  for i, client in enumerate(clients):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, f"cd dev/ebpf-txn/tatp/caladan && sudo stdbuf -o0 ./client_ebpf_shard ../../lock_2pl/caladan/client.config {i+1} {len(clients)} {num_of_uthreads} 0 expr"],
               shell=False,
               stdout=subprocess.PIPE,
               stderr=subprocess.DEVNULL)
    executors.append(e)

  # get output
  outputs = []
  for e in executors:
    out, _err = e.communicate()
    out = out.decode('utf-8').splitlines()[-200:]
    outputs.append(out)

  # write output
  with open(f"results/tatp_colocate_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

if __name__ == "__main__":
  if (len(sys.argv) < 2):
    print("Usage: ./run_tatp.sh [command]")
    exit(1)

  if (sys.argv[1] == "run"):
    if (len(sys.argv) != 3):
      print("Usage: ./run_tatp.sh run [#uthreads_per_machine]")
      exit(1)

    nu = int(sys.argv[2])
    run_expr(nu)

  else:
    print("unknown command")
    exit(1)
