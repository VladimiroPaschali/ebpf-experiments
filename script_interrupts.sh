#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

IFNAME=$1

PCIADDR=$(sudo ethtool -i ${IFNAME} | egrep "bus-info" | cut -d" " -f2)
# setting one queue using ethtool set-indirection
sudo ethtool --set-rxfh-indir $IFNAME equal 1
# getting the irq associated with the first queue
IRQ=$(cat /proc/interrupts | grep $PCIADDR | head -n 1 | awk '{print $1}' | sed 's/://')
AFFINITY=$(cat /proc/irq/$IRQ/smp_affinity_list)
echo $AFFINITY