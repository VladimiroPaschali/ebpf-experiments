#!/bin/bash
old=$(sudo bpftool prog | egrep cms | head -n 1 | cut -d" " -f14)
sleep 1
new=$(sudo bpftool prog | egrep cms | head -n 1 | cut -d" " -f14)
echo $(( $new - $old ))
