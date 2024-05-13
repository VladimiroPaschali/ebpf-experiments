#!/bin/bash


sudo bpftool prog | egrep ${2}
sudo perf stat -b ${1} -e L1-dcache-load-misses --timeout 20000
sudo bpftool prog | egrep ${2}

