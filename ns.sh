TIME=10
sudo sysctl kernel.bpf_stats_enabled=1 >/dev/null
prima=$(sudo bpftool prog | egrep "xdp"  | cut -d" " -f12,14)
sleep $TIME;
dopo=$(sudo bpftool prog | egrep "xdp"  | cut -d" " -f12,14)

primans=$(echo $prima |cut -d " " -f1)
primapkt=$(echo $prima |cut -d " " -f2)

dopons=$(echo $dopo |cut -d " " -f1)
dopopkt=$(echo $dopo |cut -d " " -f2)


ris=$(echo "($dopons-$primans)/($dopopkt-$primapkt)"|bc -l )

echo $ris