#!/usr/bin/python3

import subprocess
import os
from time import sleep
import sys

dir_path = os.path.dirname(os.path.realpath(__file__))

servers = ["clnode262.clemson.cloudlab.us",
       "clnode273.clemson.cloudlab.us", "clnode255.clemson.cloudlab.us"]
clients = ["clnode276.clemson.cloudlab.us",
       "clnode277.clemson.cloudlab.us", "clnode279.clemson.cloudlab.us"]


def kill_all():
  for machine in servers + clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, "sudo pkill iokerneld; sudo pkill server_; sudo pkill client_; sudo pkill shard; sudo tc filter del dev ens2f0np0 egress; sudo tc qdisc del dev ens2f0np0 clsact"], shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(2)


def prepare_binaries():
  for machine in servers:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"cd {dir_path}/../tatp/ebpf && make clean && make -j"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"cd {dir_path}/../tatp/udp && make clean && make -j"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"cd {dir_path}/../tatp/caladan && make clean && make -j"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)

  for machine in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"cd {dir_path}/../tatp/caladan && make clean && make -j"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)

  sleep(5)

def set_cpu(num_cpus):
  for machine in servers:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"sudo {dir_path}/../cpu_setup.sh {num_cpus}"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(1)

def run_ebpf_expr(num_of_uthreads, target_rate):
  set_cpu(15)
  
  print('kill_all')
  kill_all()

  print('start iokerneld')
  for machine in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"sudo {dir_path}/../caladan/iokerneld"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(3)

  print('start server')
  for i, server in enumerate(servers):
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa',
             server, f"cd {dir_path}/../tatp/ebpf && sudo taskset -c 33 ./shard 16 ens2f0np0"], shell=False, stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(10)

  print('start clients')
  executors = []
  for i, client in enumerate(clients):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, f"cd {dir_path}/../tatp/caladan && sudo stdbuf -o0 ./client_ebpf ../../lock_2pl/caladan/client.config {i+1} {len(clients)} {num_of_uthreads} {target_rate} expr"],
               shell=False,
               stdout=subprocess.PIPE,
               stderr=subprocess.DEVNULL)
    executors.append(e)

  # get output
  outputs = []
  for e in executors:
    out, _err = e.communicate()
    out = out.decode('utf-8').splitlines()[-20:]
    outputs.append(out)

  # write output
  with open(f"results/tatp_bench_{target_rate}_ebpf_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  print('kill_all')
  kill_all()

def run_udp_expr(num_of_uthreads, target_rate):
  set_cpu(16)
  
  print('kill_all')
  kill_all()

  print('start iokerneld')
  for machine in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"sudo {dir_path}/../caladan/iokerneld"],
             shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(3)

  print('start server')
  for i, server in enumerate(servers):
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', server, f"cd {dir_path}/../tatp/udp && sudo ./server_shard 16"], shell=False,
             stdout=subprocess.DEVNULL,
             stderr=subprocess.DEVNULL)
  sleep(30)

  print('start clients')
  executors = []
  for i, client in enumerate(clients):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, f"cd {dir_path}/../tatp/caladan && sudo stdbuf -o0 ./client_udp ../../lock_2pl/caladan/client.config {i+1} {len(clients)} {num_of_uthreads} {target_rate} expr"],
               shell=False,
               stdout=subprocess.PIPE,
               stderr=subprocess.DEVNULL)
    executors.append(e)

  # get output
  outputs = []
  for e in executors:
    out, _err = e.communicate()
    out = out.decode('utf-8').splitlines()[-20:]
    outputs.append(out)

  # write output
  with open(f"results/tatp_bench_{target_rate}_udp_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  print('kill_all')
  kill_all()

def run_caladan_expr(num_of_uthreads, target_rate):
  print('kill_all')
  kill_all()
  
  print('start iokerneld')
  for machine in servers + clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', machine, f"sudo {dir_path}/../caladan/iokerneld"], 
                     shell=False, 
                     stdout=subprocess.DEVNULL, 
                     stderr=subprocess.DEVNULL)
  sleep(3)

  print('start server')
  for i, server in enumerate(servers):
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', server, f"cd {dir_path}/../tatp/caladan && sudo ./server_shard server.config"], shell=False, 
                      stdout=subprocess.DEVNULL, 
                      stderr=subprocess.DEVNULL)
  sleep(30)

  print('start clients')
  executors = []
  for i, client in enumerate(clients):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, f"cd {dir_path}/../tatp/caladan && sudo stdbuf -o0 ./client_caladan ../../lock_2pl/client.config {i+1} {len(clients)} {num_of_uthreads} {target_rate} expr"], 
                         shell=False, 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.DEVNULL)
    executors.append(e)

  # get output
  outputs = []
  for e in executors:
    out, _err = e.communicate()
    out = out.decode('utf-8').splitlines()[-20:]
    outputs.append(out)
  
  # write output
  with open(f"results/tatp_bench_{target_rate}_caladan_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  print('kill_all')
  kill_all()

if __name__ == "__main__":
  if (len(sys.argv) < 2):
    print("Usage: ./run_tatp_cpu.sh [command]")
    exit(1)

  if (sys.argv[1] == "binary"):
    prepare_binaries()
  elif (sys.argv[1] == "run"):
    if (len(sys.argv) != 5):
      print(
        "Usage: ./run_tatp_cpu.sh run [artifact] [target_rate] [#uthreads_per_machine]")
      exit(1)

    artifact = sys.argv[2]
    target_rate = int(sys.argv[3])
    nu = int(sys.argv[4])

    if (artifact == "ebpf"):
      run_ebpf_expr(nu, target_rate)
    elif (artifact == "udp"):
      run_udp_expr(nu, target_rate)
    elif (artifact == "caladan"):
      run_caladan_expr(nu, target_rate)
    else:
      print("unknown artifact")
      exit(1)

  else:
    print("unknown command")
    exit(1)
