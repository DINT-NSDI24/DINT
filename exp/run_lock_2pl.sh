#!/usr/bin/python3

import subprocess
import os
from time import sleep
import sys

clients = ['clnode280.clemson.cloudlab.us', 'clnode254.clemson.cloudlab.us', 'clnode269.clemson.cloudlab.us', 'clnode272.clemson.cloudlab.us', 'clnode253.clemson.cloudlab.us', 'clnode261.clemson.cloudlab.us', 'clnode260.clemson.cloudlab.us', 'clnode264.clemson.cloudlab.us', 'clnode275.clemson.cloudlab.us', 'clnode267.clemson.cloudlab.us', 'clnode281.clemson.cloudlab.us', 'clnode265.clemson.cloudlab.us']

def prepare_binaries():
  os.system("cd ../ && ./kernel-src-download.sh lock_2pl 6.1")
  os.system("cd ../ && ./kernel-src-prepare.sh lock_2pl 6.1")
  os.system("cd ../lock_2pl/udp && make clean && make -j")
  os.system("cd ../lock_2pl/ebpf && make clean && make -j")
  os.system("cd ../lock_2pl/caladan && make clean && make -j")

  for client in clients:
    sleep(0.1)
    subprocess.call(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, "cd dev/ebpf-txn/lock_2pl/caladan && make clean && make -j"], 
                    shell=False, 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL)

def prepare_trace():
  executors = []
  for i in range(len(clients)):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', clients[i], f"cd dev/ebpf-txn/lock_2pl/caladan && ./trace_init.sh 24000000 0.8 4800"], 
                         shell=False, 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL)
    executors.append(e)
  
  for e in executors:
    e.wait()

def run_udp_expr(num_of_uthreads):
  # start iokerneld
  for client in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, "sudo ./dev/ebpf-txn/caladan/iokerneld"], 
                     shell=False, 
                     stdout=subprocess.DEVNULL, 
                     stderr=subprocess.DEVNULL)
  sleep(10)

  # start server
  os.system('bash -c "cd ../ && ./cpu_setup.sh 8 &> /dev/null"')
  os.system('sudo bash -c "sudo ../lock_2pl/udp/server 8 &> /dev/null &"')
  sleep(10)

  # start clients
  executors = []
  for i in range(len(clients)):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', clients[i], f"cd dev/ebpf-txn/lock_2pl/caladan && sudo ./client client.config {i+1} {num_of_uthreads} expr"], 
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
  with open(f"results/lock_2pl_udp_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  sleep(3)

def run_ebpf_expr(num_of_uthreads):
  # start iokerneld
  for client in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, "sudo ./dev/ebpf-txn/caladan/iokerneld"], 
                     shell=False, 
                     stdout=subprocess.DEVNULL, 
                     stderr=subprocess.DEVNULL)
  sleep(10)

  # start server
  os.system('bash -c "cd ../ && ./cpu_setup.sh 8 &> /dev/null"')
  os.system('sudo bash -c "sudo ../lock_2pl/ebpf/ls ens2f0np0 &> /dev/null &"')
  sleep(10)

  # start clients
  executors = []
  for i in range(len(clients)):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', clients[i], f"cd dev/ebpf-txn/lock_2pl/caladan && sudo ./client client.config {i+1} {num_of_uthreads} expr"], 
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
  with open(f"results/lock_2pl_ebpf_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  sleep(3)

def run_caladan_expr(num_of_uthreads):
  # start iokerneld
  os.system('sudo bash -c "sudo ../caladan/iokerneld &> /dev/null &"')
  for client in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, "sudo ./dev/ebpf-txn/caladan/iokerneld"], 
                     shell=False, 
                     stdout=subprocess.DEVNULL, 
                     stderr=subprocess.DEVNULL)
  sleep(10)

  # start server
  os.system('sudo bash -c "cd ../lock_2pl/caladan && sudo ./server server.config &> /dev/null &"')
  sleep(10)

  # start clients
  executors = []
  for i in range(len(clients)):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', clients[i], f"cd dev/ebpf-txn/lock_2pl/caladan && sudo ./client_caladan client.config {i+1} {num_of_uthreads} expr"], 
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
  with open(f"results/lock_2pl_caladan_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  sleep(3)

if __name__ == "__main__":
  if (len(sys.argv) < 2):
    print("Usage: ./run_lock_2pl.sh [command]")
    exit(1)
  
  if (sys.argv[1] == "binary"):
    prepare_binaries()
  elif (sys.argv[1] == "trace"):
    prepare_trace()
  elif (sys.argv[1] == "run"):
    if (len(sys.argv) != 4):
      print("Usage: ./run_lock_2pl.sh run [artifact] [#uthreads_per_machine]")
      exit(1)

    artifact = sys.argv[2]
    nu = int(sys.argv[3])

    if (artifact == "ebpf"):
      run_ebpf_expr(nu)
    elif (artifact == "udp"):
      run_udp_expr(nu)
    elif (artifact == "caladan"):
      run_caladan_expr(nu)
    else:
      print("unknown artifact")
      exit(1)

  else:
    print("unknown command")
    exit(1)