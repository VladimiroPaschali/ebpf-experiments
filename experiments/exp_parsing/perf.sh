#!/bin/bash
sum=0
cnt=0

while true; do

    start=$(sudo bpftool prog | grep ${2} | awk -F ' ' {'print $NF'} | awk 'NF==1 {print; exit}')
    echo start:\ $start
    value=$(sudo perf stat -b ${1} -e ${3} --timeout 2000 2>&1 | tr -s ' ' | awk '{ if (NR==4) {print $1} }' | sed 's/,//g')
    echo value:\ $value
    end=$(sudo bpftool prog | grep ${2}| awk -F ' ' {'print $NF'} | awk 'NF==1 {print; exit}')
    echo end:\ $end
    result=$(echo "( $value ) / ( $end - $start )" | bc -l)
    echo result:\ $result 
    # echo $value_start $value_end $start $end $result
    sum=$(echo "( $sum + $result)" | bc -l)
    cnt=$(($cnt + 1))

    avg=$(echo "$sum / $cnt" | bc -l)
    echo -ne "avg: $avg, result: $result\r"

done;