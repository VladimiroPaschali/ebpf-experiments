#!/bin/bash

t=${1}
prev=0
sum=0
cnt=0

while true; do
    start=$(sudo bpftool prog | grep ${3} | awk -F ' ' {'print $NF'} | awk 'NF==1 {print; exit}')
    value_start=$(sudo bpftool map lookup name out key 00 00 00 00 | grep "${2}," -A 2 | grep value | awk -F ' ' {'print $NF'})
    sleep $t
    value_end=$(sudo bpftool map lookup name out key 00 00 00 00 | grep "${2}," -A 2 | grep value | awk -F ' ' {'print $NF'})
    end=$(sudo bpftool prog | grep ${3}| awk -F ' ' {'print $NF'} | awk 'NF==1 {print; exit}')

    result=$(echo "( $value_end - $value_start ) / ( $end - $start )" | bc -l)
    echo $value_start $value_end $start $end $result
    sum=$(echo "( $sum + $result)" | bc -l)
    cnt=$(($cnt + 1))

    avg=$(echo "$sum / $cnt" | bc -l)
    echo -ne "avg: $avg, result: $result\r"
done;