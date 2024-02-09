#!/usr/bin/python3

import os, sys
import random

def rand_gen(val_size):
  digit = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
  res = ''.join(random.choices(digit, k=val_size*2))
  return res

def micro_gen(trace_id_end):
  VAL_SIZE = 40
  KEYS_PER_TRACE = 10000

  def micro_gen_trace(trace_id):
    with open(f'traces/microbenchmarks/trace_{trace_id}.csv', 'w') as f:
      f.write('key,ver,val\n')
      for i in range(KEYS_PER_TRACE):
        f.write(str(random.randint(0, 7009999)) + ',' + str(random.randint(0, 127)) + ',' + rand_gen(VAL_SIZE) + '\n')
  
  os.system(f'rm -rf traces/microbenchmarks')
  os.system(f'mkdir -p traces/microbenchmarks')

  for i in range(trace_id_end):
    micro_gen_trace(i)
    print('trace ' + str(i) + ' generated')

if __name__ == '__main__':
  if (len(sys.argv) != 2):
    print('usage: [trace_id_end]')
    exit(1)

  trace_id_end = int(sys.argv[1])

  if trace_id_end < 0 or trace_id_end > 32768:
    print('trace_id_end should be in [0, 32768]')
    exit(1)

  micro_gen(trace_id_end)
