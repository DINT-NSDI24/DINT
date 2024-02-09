#!/usr/bin/python3

import os, sys
import random

def micro_gen(num_of_locks, r_prop, trace_id_end):
  TXN_NUM = 20000

  def micro_gen_trace(trace_id):
    with open(f'traces/microbenchmarks/lock_{num_of_locks}_r_{r_prop}/trace_{trace_id}.csv', 'w') as f:
      f.write('txn_id,action,lock_id,lock_type\n')
      for txn_id in range(TXN_NUM):
        lock_num = random.randint(5, 10)
        if int(num_of_locks) == 0:
          lock_list = random.sample(range(128*trace_id, 128*trace_id+128), lock_num)
        else:
          lock_list = random.sample(range(0, int(num_of_locks)), lock_num)
        lock_type_list = [(1 if random.randint(0, 99)/100 >= float(r_prop) else 0) for _ in range(lock_num)]
        lock_list = list(zip(lock_list, lock_type_list))
        lock_list.sort(key=lambda tup: tup[0])
        for lock in lock_list:
          f.write(str(txn_id) + ',0,' + str(lock[0]) + ',' + str(lock[1]) + '\n')
        for lock in reversed(lock_list):
          f.write(str(txn_id) + ',1,' + str(lock[0]) + ',' + str(lock[1]) + '\n')
  
  os.system(f'rm -rf traces/microbenchmarks/lock_{num_of_locks}_r_{r_prop}')
  os.system(f'mkdir -p traces/microbenchmarks/lock_{num_of_locks}_r_{r_prop}')

  for i in range(trace_id_end):
    micro_gen_trace(i)
    print('trace ' + str(i) + ' generated')

if __name__ == '__main__':
  if (len(sys.argv) != 4):
    print('usage: [num_of_locks] [r_prop] [trace_id_end]')
    exit(1)

  trace_id_end = int(sys.argv[3])

  if trace_id_end < 0 or trace_id_end > 32768:
    print('trace_id_end must be in [0, 32768]')
    exit(1)
  
  micro_gen(sys.argv[1], sys.argv[2], trace_id_end)
