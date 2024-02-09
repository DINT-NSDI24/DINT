#!/usr/bin/python3

import os, sys
import random

def micro_gen(num_of_keys, r_prop, trace_id_end):
  TXN_NUM = 20000

  def micro_gen_trace(trace_id):
    with open(f'traces/microbenchmarks/lock_{num_of_keys}_r_{r_prop}/trace_{trace_id}.csv', 'w') as f:
      f.write('tid,type,lid\n')
      for txn_id in range(TXN_NUM):
        key_num = random.randint(5, 10)
        if int(num_of_keys) == 0:
          key_list = random.sample(range(128*trace_id, 128*trace_id+128), key_num)
        else:
          key_list = random.sample(range(0, int(num_of_keys)), key_num)
        read_list = key_list.copy()
        read_list.sort()
        write_list = []
        for key in read_list:
          if random.randint(0, 99)/100 >= float(r_prop):
            write_list.append(key)
        for key in read_list:
          f.write(str(txn_id) + ',0,' + str(key) + '\n')
        for key in write_list:
          f.write(str(txn_id) + ',1,' + str(key) + '\n')
  
  os.system(f'rm -rf traces/microbenchmarks/lock_{num_of_keys}_r_{r_prop}')
  os.system(f'mkdir -p traces/microbenchmarks/lock_{num_of_keys}_r_{r_prop}')

  for i in range(trace_id_end):
    micro_gen_trace(i)
    print('trace ' + str(i) + ' generated')

if __name__ == '__main__':
  if (len(sys.argv) != 4):
    print('usage: [num_of_keys] [r_prop] [trace_id_end]')
    exit(1)

  trace_id_end = int(sys.argv[3])

  if trace_id_end < 0 or trace_id_end > 32768:
    print('trace_id_end should be in [0, 32768]')
    exit(1)

  micro_gen(sys.argv[1], sys.argv[2], trace_id_end)
