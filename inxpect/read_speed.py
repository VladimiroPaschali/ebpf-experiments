#! /bin/python3

import os
import subprocess as sp
import argparse
import re

BASH='sudo -E bash -c "export LD_LIBRARY_PATH=/lib64;'

def count_read(cpu : int, duration : int) -> int:
    cmd = f"{BASH} ./inxpect_tr -n drop_kfunc -e instructions,cycles,cache-misses,L1-dcache-load-misses -C {cpu} -d {duration}\""
    result = sp.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.returncode}")
        return 0
    mean_value = re.search(r"mean:\s+([0-9.]+)", result.stdout)

    if mean_value:
        mean_value = mean_value.group(1)
        print(f"- value: {mean_value}")
        return float(mean_value)
    else:
        print("Mean value not found")
        return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cpu", help="CPU number to monitor", type=int, default=0)
    parser.add_argument("-d", "--duration", help="Duration to monitor", type=int, default=10)
    args = parser.parse_args()
    
    cpu = args.cpu
    duration = args.duration
    
    sum = 0
    run = 10
    for i in range(10):
        sum += count_read(cpu, duration)
    
    print(f"Mean value: {sum/run}")
    pass