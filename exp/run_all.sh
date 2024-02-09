#!/bin/bash

nu_udp=$(seq 2 2 41)
nu_ebpf=$(seq 10 10 301)
nu_caladan=$(seq 5 5 151)

clients='clnode280.clemson.cloudlab.us clnode254.clemson.cloudlab.us clnode269.clemson.cloudlab.us clnode272.clemson.cloudlab.us clnode253.clemson.cloudlab.us clnode261.clemson.cloudlab.us clnode260.clemson.cloudlab.us clnode264.clemson.cloudlab.us clnode275.clemson.cloudlab.us clnode267.clemson.cloudlab.us clnode281.clemson.cloudlab.us clnode265.clemson.cloudlab.us'

alias ssh="sleep 0.1; ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa"

function kill_all() {
  sudo pkill -f "run_lock_2pl.sh"
  sudo pkill -f "run_lock_fasst.sh"
  sudo pkill -f "run_store.sh"
  sudo pkill -f "run_log_server.sh"
  sudo pkill ls
  sudo pkill store
  sudo pkill server
  sudo pkill iokerneld
  for client in $clients; do
    ssh $client "sudo pkill iokerneld"
    ssh $client "sudo pkill client"
  done
}

kill_all

for nu in ${nu_ebpf[@]}; do
  timeout 600s ./run_lock_2pl.sh run ebpf $nu || true
  if [ $? -ne 124 ]; then
    echo "lock_2pl ebpf $nu done"
  fi
  kill_all
done

for nu in ${nu_udp[@]}; do
  timeout 600s ./run_lock_2pl.sh run udp $nu || true
  if [ $? -ne 124 ]; then
    echo "lock_2pl udp $nu done"
  fi
  kill_all
done

for nu in ${nu_ebpf[@]}; do
  timeout 600s ./run_lock_fasst.sh run ebpf $nu || true
  if [ $? -ne 124 ]; then
    echo "lock_fasst ebpf $nu done"
  fi
  kill_all
done

for nu in ${nu_udp[@]}; do
  timeout 600s ./run_lock_fasst.sh run udp $nu || true
  if [ $? -ne 124 ]; then
    echo "lock_fasst udp $nu done"
  fi
  kill_all
done

for nu in ${nu_ebpf[@]}; do
  timeout 600s ./run_log_server.sh run ebpf $nu || true
  if [ $? -ne 124 ]; then
    echo "log_server ebpf $nu done"
  fi
  kill_all
done

for nu in ${nu_udp[@]}; do
  timeout 600s ./run_log_server.sh run udp $nu || true
  if [ $? -ne 124 ]; then
    echo "log_server udp $nu done"
  fi
  kill_all
done

for nu in ${nu_ebpf[@]}; do
  timeout 600s ./run_store.sh run parallel ebpf $nu || true
  if [ $? -ne 124 ]; then
    echo "store ebpf $nu done"
  fi
  kill_all
done

for nu in ${nu_udp[@]}; do
  timeout 600s ./run_store.sh run parallel udp $nu || true
  if [ $? -ne 124 ]; then
    echo "store udp $nu done"
  fi
  kill_all
done

# for nu in ${nu_caladan[@]}; do
#   timeout 600s ./run_lock_2pl.sh run caladan $nu || true
#   if [ $? -ne 124 ]; then
#     echo "lock_2pl caladan $nu done"
#   fi
#   kill_all
# done

# for nu in ${nu_caladan[@]}; do
#   timeout 600s ./run_lock_fasst.sh run caladan $nu || true
#   if [ $? -ne 124 ]; then
#     echo "lock_fasst caladan $nu done"
#   fi
#   kill_all
# done

# for nu in ${nu_caladan[@]}; do
#   timeout 600s ./run_log_server.sh run caladan $nu || true
#   if [ $? -ne 124 ]; then
#     echo "log_server caladan $nu done"
#   fi
#   kill_all
# done

# for nu in ${nu_caladan[@]}; do
#   timeout 600s ./run_store.sh run parallel caladan $nu || true
#   if [ $? -ne 124 ]; then
#     echo "store caladan $nu done"
#   fi
#   kill_all
# done
