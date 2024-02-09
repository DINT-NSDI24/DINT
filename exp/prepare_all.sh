#!/bin/bash

nohup ./run_lock_2pl.sh binary &> /dev/null &
nohup ./run_lock_fasst.sh binary &> /dev/null &
nohup ./run_log_server.sh binary &> /dev/null &
nohup ./run_store.sh binary &> /dev/null &

nohup ./run_lock_2pl.sh trace &> /dev/null &
nohup ./run_lock_fasst.sh trace &> /dev/null &
nohup ./run_log_server.sh trace &> /dev/null &

wait

echo "preparation done"