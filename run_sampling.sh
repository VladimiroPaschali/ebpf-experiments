#!/bin/bash


show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help                                Show this help message"
    echo "  -e, --experiment all,drop,cms,routing     Specify experiment name"
    echo "  -i, --interface enp81s0f0np0                 Specify interface name"
    echo "  -t, --time 10                             Specify time value"
    echo "  -p, --perf perf                           Specify perf path"
    echo "  -l, --libbpf /lib64                       Specify libbpf path"
    echo "  -s, --sampling 1,8,32,128                 Specify sampling values"
    echo "  cloudlab icmp2024 sudo ./run.sh"
    echo "node119 sudo ./run.sh -i enp129s0f0np0 -p /home/guest/linux/tools/perf/perf -l /home/guest/libbpf/src/"
}
#colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Valori predefiniti
EXPERIMENT="all"
INTERFACE="enp81s0f0np0"
TIME="10"
PERF="perf"
LIBBPF="/lib64"
SAMPLING="0,1,2,3,4,5,6,7,8,9"

terminate_experiments() {
    echo -e "${RED}Terminating all experiments ${NC}"
    exit 0
}

trap terminate_experiments SIGINT


#parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -e|--experiment)
            EXPERIMENT="$2"
            shift
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift
            ;;
        -t|--time)
            TIME="$2"
            shift
            ;;
        -p|--perf)
            PERF="$2"
            shift
            ;;
        -l|--libbpf)
            LIBBPF="$2"
            shift
            ;;
        -s|--sampling)
            SAMPLING="$2"
            shift
            ;;
        *)
            echo "Option not valid $1" >&2
            exit 1
            ;;
    esac
    shift
done

echo -e "${GREEN}Disabling forward, MTU 1500, RSS 1${NC}"
sudo sysctl -w net.ipv4.ip_forward=0
sudo ip link set mtu 1500 $INTERFACE
sudo ethtool --set-rxfh-indir $INTERFACE equal 1

case $EXPERIMENT in
    all)
        echo -e "${GREEN}Starting all experiments${NC}"
        echo -e "${GREEN}Starting Drop experiments${NC}"
        cd exp_drop || exit 1
        python run_sampling.py --experiment drop_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result > ../sampling_result
        echo -e "${GREEN}Starting CMS experiments MIANO${NC}"
        cd ../exp_cms_miano || exit 1
        python run_sampling.py --experiment cms_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result >> ../sampling_result
        echo -e "${GREEN}Starting Routing experiments${NC}"
        cd ../exp_routing || exit 1
        python run_sampling.py --experiment lpmtrie_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result >> ../sampling_result
        echo -e "${GREEN}Starting Tunnel experiments${NC}"
        cd ../exp_tunnel || exit 1
        python run_sampling.py --experiment tunnel_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result >> ../sampling_result
        echo -e "${GREEN}Data saved in the sampling_result file${NC}"
        ;;
    drop)
        echo -e "${GREEN}Starting Drop experiments${NC}"
        cd exp_drop || exit 1
        python run_sampling.py --experiment drop_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result > ../sampling_result
        echo -e "${GREEN}Data saved in the sampling_result file${NC}"

        ;;
    cms)
        echo -e "${GREEN}Starting CMS experiments MIANO${NC}"
        cd exp_cms_miano || exit 1
        python run_sampling.py --experiment cms_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result > ../sampling_result
        echo -e "${GREEN}Data saved in the sampling_result file${NC}"
        ;;
    routing)
        echo -e "${GREEN}Starting Routing experiments${NC}"
        cd exp_routing || exit 1
        python run_sampling.py --experiment lpmtrie_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result > ../sampling_result
        echo -e "${GREEN}Data saved in the sampling_result file${NC}"
        ;;
    tunnel)
        echo -e "${GREEN}Starting Tunnel experiments${NC}"
        cd exp_tunnel || exit 1
        python run_sampling.py --experiment tunnel_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result > ../sampling_result
        echo -e "${GREEN}Data saved in the sampling_result file${NC}"
        ;;
    nat)
        echo -e "${GREEN}Starting nat experiments${NC}"
        cd exp_nat || exit 1
        python run_sampling.py --experiment xdp_nat_sr --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF" --sampling "$SAMPLING"
        cat sampling_result > ../sampling_result
        echo -e "${GREEN}Data saved in the sampling_result file${NC}"
        ;;
    *)
        echo "Not a valid Experiment  $EXPERIMENT try all" >&2
        exit 1
        ;;
esac



