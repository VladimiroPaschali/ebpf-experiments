#!/bin/bash


sudo bpftool prog | egrep cms
sudo perf stat -b ${1} -e L1-dcache-load-misses --timeout 10000
sudo bpftool prog | egrep cms

