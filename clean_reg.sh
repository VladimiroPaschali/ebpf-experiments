#! /bin/bash

cpu=$1

# get the number of logical cores
ncores=$(lscpu | grep "CPU(s):" | head -n 1 | awk '{print $2}')

if [ $cpu -ge $ncores ]; then
    echo "Invalid CPU number"
    exit 1
fi

if [ $cpu -eq -1 ]; then 
    for i in $(seq 0 $((ncores-1))); do
        sudo wrmsr 0x186 0x0 -p $i &&  sudo wrmsr 0x187 0x0 -p $i  &&  sudo wrmsr 0x188 0x0 -p $i  &&  sudo wrmsr 0x189 0x0 -p $i 
    done
    exit 0
fi 

	sudo wrmsr 0x186 0x0 -p $cpu &&  sudo wrmsr 0x187 0x0 -p $cpu  &&  sudo wrmsr 0x188 0x0 -p $cpu  &&  sudo wrmsr 0x189 0x0 -p $cpu 
