#!/bin/bash

t=${1}
prev=0
sum=0
cnt=0

start=$(sudo bpftool prog | egrep ${3} | head -n 1)
value_start=$(sudo bpftool map lookup name out key 00 00 00 00 | grep "${2}," -A 2 | grep value | awk -F ' ' {'print $NF'})
sleep $t
end=$(sudo bpftool prog | egrep ${3}| head -n 1)
value_end=$(sudo bpftool map lookup name out key 00 00 00 00 | grep "${2}," -A 2 | grep value | awk -F ' ' {'print $NF'})

start=$(echo "$start" | awk '{print $11}')
end=$(echo $end | awk '{print $11}')
echo $value_start 
echo $value_end 
echo $end 
echo $start
result=$(echo "( $value_end - $value_start ) / ( $end - $start )" | bc -l)
echo $result
