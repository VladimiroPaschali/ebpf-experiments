#!/bin/bash


while true; do

    start=$(sudo bpftool prog | grep ${2} | awk -F ' ' {'print $NF'} | awk 'NF==1 {print; exit}')
    value=$(sudo perf stat -b ${1} -e ${3} --timeout 20000 2> >(sed -n 's/^\s*\([0-9,]*\)\s*.*/\1/p' | sed 's/,//g'))
    end=$(sudo bpftool prog | grep ${2}| awk -F ' ' {'print $NF'} | awk 'NF==1 {print; exit}')
    result=$(echo "( $value ) / ( $end - $start )" | bc -l)
    # echo $value_start $value_end $start $end $result
    sum=$(echo "( $sum + $result)" | bc -l)
    cnt=$(($cnt + 1))

    avg=$(echo "$sum / $cnt" | bc -l)
    echo -ne "avg: $avg, result: $result\r"

done;