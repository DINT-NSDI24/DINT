#!/bin/bash

nu_udp=$(seq 2 2 41)
nu_ebpf=$(seq 10 10 201)
nu_caladan=$(seq 4 4 141)

servers='clnode255.clemson.cloudlab.us clnode280.clemson.cloudlab.us clnode254.clemson.cloudlab.us'
clients='clnode269.clemson.cloudlab.us clnode272.clemson.cloudlab.us clnode253.clemson.cloudlab.us clnode261.clemson.cloudlab.us clnode260.clemson.cloudlab.us clnode264.clemson.cloudlab.us clnode275.clemson.cloudlab.us clnode267.clemson.cloudlab.us clnode281.clemson.cloudlab.us clnode265.clemson.cloudlab.us'

alias ssh="sleep 0.1; ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa"

function kill_all() {
  for server in $servers; do
    ssh $server 'sudo pkill -f "run_smallbank.sh"'
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
  timeout 600s ./run_smallbank.sh run ebpf $nu || true
  if [ $? -ne 124 ]; then
    echo "smallbank ebpf $nu done"
  fi
  kill_all
done

for nu in ${nu_udp[@]}; do
  timeout 600s ./run_smallbank.sh run udp $nu || true
  if [ $? -ne 124 ]; then
    echo "smallbank udp $nu done"
  fi
  kill_all
done

# for nu in ${nu_caladan[@]}; do
#   timeout 600s ./run_smallbank.sh run caladan $nu || true
#   if [ $? -ne 124 ]; then
#     echo "smallbank caladan $nu done"
#   fi
#   kill_all
# done