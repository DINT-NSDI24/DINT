#!/usr/bin/python3

import subprocess
import os
from time import sleep
import sys

clients = ["clnode274.clemson.cloudlab.us", "clnode273.clemson.cloudlab.us", "clnode257.clemson.cloudlab.us", "clnode262.clemson.cloudlab.us", "clnode277.clemson.cloudlab.us", "clnode282.clemson.cloudlab.us", "clnode276.clemson.cloudlab.us", "clnode279.clemson.cloudlab.us", "clnode278.clemson.cloudlab.us", "clnode266.clemson.cloudlab.us", "clnode283.clemson.cloudlab.us", "clnode263.clemson.cloudlab.us"]

def prepare_binaries():
  os.system("cd ../ && ./kernel-src-download.sh store 6.1")
  os.system("cd ../ && ./kernel-src-prepare.sh store 6.1")
  os.system("cd ../store/udp && make clean && make -j")
  os.system("cd ../store/ebpf && make clean && make -j")
  os.system("cd ../store/caladan && make clean && make -j")

  for client in clients:
    sleep(0.1)
    subprocess.call(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, "cd dev/ebpf-txn/store/caladan && make clean && make -j"], 
                    shell=False, 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL)

def run_udp_expr(num_of_uthreads, benchmark):
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
  os.system(f'sudo bash -c "sudo ../store/udp/server 8 &> /dev/null &"')
  sleep(120)

  # start clients
  executors = []
  for i in range(len(clients)):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', clients[i], f"cd dev/ebpf-txn/store/caladan && sudo ./client_udp ../../lock_2pl/caladan/client.config {i+1} {num_of_uthreads} {benchmark} expr"], 
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
  with open(f"results/store_bench_{benchmark}_udp_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  sleep(3)

def run_ebpf_expr(num_of_uthreads, benchmark):
  # start iokerneld
  for client in clients:
    sleep(0.1)
    subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', client, "sudo ./dev/ebpf-txn/caladan/iokerneld"], 
                     shell=False, 
                     stdout=subprocess.DEVNULL, 
                     stderr=subprocess.DEVNULL)
  sleep(10)

  # start server
  os.system('bash -c "cd ../ && ./cpu_setup.sh 7 &> /dev/null"')
  os.system(f'sudo bash -c "sudo taskset -c 17 ../store/ebpf/store 16 ens2f0np0 &> /dev/null &"')
  sleep(10)

  # start clients
  executors = []
  for i in range(len(clients)):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', clients[i], f"cd dev/ebpf-txn/store/caladan && sudo ./client_ebpf ../../lock_2pl/caladan/client.config {i+1} {len(clients)} {num_of_uthreads} {benchmark} expr"], 
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
  with open(f"results/store_bench_{benchmark}_ebpf_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  sleep(3)

def run_caladan_expr(num_of_uthreads, benchmark):
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
  os.system(f'sudo bash -c "cd ../store/caladan && sudo ./server ../../lock_2pl/caladan/server.config &> /dev/null &"')
  sleep(120)

  # start clients
  executors = []
  for i in range(len(clients)):
    sleep(0.1)
    e = subprocess.Popen(['ssh', '-o', 'StrictHostKeyChecking=no', '-i', '~/.ssh/id_rsa', clients[i], f"cd dev/ebpf-txn/store/caladan && sudo ./client_caladan ../../lock_2pl/caladan/client.config {i+1} {num_of_uthreads} {benchmark} expr"], 
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
  with open(f"results/store_bench_{benchmark}_caladan_nu_{num_of_uthreads}.txt", "w") as f:
    for i in range(len(outputs)):
      f.write(f'result {i}:\n')
      for line in outputs[i]:
        f.write(line + '\n')

  sleep(3)

if __name__ == "__main__":
  if (len(sys.argv) < 2):
    print("Usage: ./run_store.sh [command]")
    exit(1)
  
  if (sys.argv[1] == "binary"):
    prepare_binaries()
  elif (sys.argv[1] == "run"):
    if (len(sys.argv) != 5):
      print("Usage: ./run_store.sh run [benchmark] [artifact] [#uthreads_per_machine]")
      exit(1)

    benchmark = sys.argv[2]
    artifact = sys.argv[3]
    nu = int(sys.argv[4])

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