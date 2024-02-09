#!/bin/bash

servers='clnode257.clemson.cloudlab.us clnode280.clemson.cloudlab.us clnode255.clemson.cloudlab.us'
clients='clnode254.clemson.cloudlab.us clnode274.clemson.cloudlab.us clnode275.clemson.cloudlab.us clnode281.clemson.cloudlab.us clnode261.clemson.cloudlab.us clnode272.clemson.cloudlab.us clnode256.clemson.cloudlab.us clnode270.clemson.cloudlab.us clnode283.clemson.cloudlab.us clnode260.clemson.cloudlab.us'

alias ssh="sleep 0.1; ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa"

for server in $servers; do
  ssh $server 'sudo pkill run_'
  ssh $server 'sudo pkill prepare_'
  ssh $server 'sudo pkill make'
  ssh $server "sudo pkill ls"
  ssh $server "sudo pkill store"
  ssh $server "sudo pkill shard"
  ssh $server "sudo pkill server"
  ssh $server 'sudo pkill iokerneld'
done

for client in $clients; do
  ssh $client "sudo pkill iokerneld"
  ssh $client "sudo pkill client"
  ssh $client "sudo pkill trace_"
  ssh $client "sudo pkill make"
done
