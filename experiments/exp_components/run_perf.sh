#!/bin/bash
sudo rm temp
init_run=$(sudo bpftool prog | egrep pass | tr -s ' ' | cut -d" " -f 11)
sudo perf stat -b ${1} -e instructions --timeout ${2} -o temp
end_run=$(sudo bpftool prog | egrep pass | tr -s ' ' | cut -d" " -f 11)
instr=$(cat temp | egrep instructions | tr -s ' ' | cut -d' ' -f2 | sed -e 's/,//g')
echo "$instr/($end_run-$init_run)"
echo "$(bc -l <<< "$instr/($end_run-$init_run)")"
