#!/bin/bash

nu_udp=$(seq 2 2 41)
nu_ebpf=$(seq 10 10 301)
nu_caladan=$(seq 4 4 141)
nu_dpdk=$(seq 10 10 301)
target_rates=$(seq 500000 500000 10000001)

servers='clnode257.clemson.cloudlab.us clnode280.clemson.cloudlab.us clnode255.clemson.cloudlab.us'
clients='clnode254.clemson.cloudlab.us clnode274.clemson.cloudlab.us clnode275.clemson.cloudlab.us clnode281.clemson.cloudlab.us clnode261.clemson.cloudlab.us clnode272.clemson.cloudlab.us clnode256.clemson.cloudlab.us clnode270.clemson.cloudlab.us clnode283.clemson.cloudlab.us clnode260.clemson.cloudlab.us clnode259.clemson.cloudlab.us clnode282.clemson.cloudlab.us clnode253.clemson.cloudlab.us'

alias ssh="sleep 0.1; ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa"

function kill_all() {
  for server in $servers; do
    ssh $server 'sudo pkill -f "run_tatp.sh"'
    ssh $server 'sudo pkill -f "run_tatp_cpu.sh"'
    ssh $server 'sudo pkill -f "run_tatp_colocate.sh"'
    ssh $server "sudo pkill shard"
    ssh $server "sudo pkill server"
    ssh $server "sudo pkill iokerneld"
  done

  for client in $clients; do
    ssh $client "sudo pkill iokerneld"
    ssh $client "sudo pkill client"
  done
}

kill_all

for nu in ${nu_ebpf[@]}; do
  timeout 600s ./run_tatp.sh run ebpf $nu || true
  if [ $? -ne 124 ]; then
    echo "tatp ebpf $nu done"
  fi
  kill_all
done

for nu in ${nu_udp[@]}; do
  timeout 600s ./run_tatp.sh run udp $nu || true
  if [ $? -ne 124 ]; then
    echo "tatp udp $nu done"
  fi
  kill_all
done

for target_rate in ${target_rates[@]}; do
  timeout 600s ./run_tatp_cpu.sh run ebpf $target_rate 300 || true
  if [ $? -ne 124 ]; then
    echo "tatp ebpf $target_rate 300 done"
  fi
done

for target_rate in ${target_rates[@]}; do
  timeout 600s ./run_tatp_cpu.sh run udp $target_rate 300 || true
  if [ $? -ne 124 ]; then
    echo "tatp udp $target_rate 300 done"
  fi
done

for nu in ${nu_ebpf[@]}; do
  timeout 600s ./run_tatp_colocate.sh run $nu || true
  if [ $? -ne 124 ]; then
    echo "tatp colocate $nu done"
  fi
  kill_all
done

# for nu in ${nu_caladan[@]}; do
#   timeout 600s ./run_tatp.sh run caladan $nu || true
#   if [ $? -ne 124 ]; then
#     echo "tatp caladan $nu done"
#   fi
#   kill_all
# done

# for nu in ${nu_dpdk[@]}; do
#   timeout 600s ./run_tatp.sh run dpdk $nu || true
#   if [ $? -ne 124 ]; then
#     echo "tatp dpdk $nu done"
#   fi
#   kill_all
# done

# for target_rate in ${target_rates[@]}; do
#   timeout 600s ./run_tatp_cpu.sh run caladan $target_rate 200 || true
#   if [ $? -ne 124 ]; then
#     echo "tatp caladan $target_rate 200 done"
#   fi
# done
