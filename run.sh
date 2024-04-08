#!/bin/bash


show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help                                Show this help message"
    echo "  -e, --experiment all,drop,cms,routing     Specify experiment name"
    echo "  -i, --interface enp129s0f0np0             Specify interface name"
    echo "  -t, --time 10                             Specify time value"
    echo "  -p, --perf /home/guest/linux/tools/perf/  Specify perf path"
    echo "  -l, --libbpf /home/guest/libbpf/src/      Specify libbpf path"
}
#colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Valori predefiniti
EXPERIMENT="all"
INTERFACE="enp129s0f0np0"
TIME="10"
PERF="/home/guest/linux/tools/perf/"
LIBBPF="/home/guest/libbpf/src/"

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
        *)
            echo "Option not valid $1" >&2
            exit 1
            ;;
    esac
    shift
done

case $EXPERIMENT in
    all)
        echo -e "${GREEN}Starting all experiments${NC}"
        echo -e "${GREEN}Starting Drop experiments${NC}"
        cd exp_drop || exit 1
        python run_exp.py --experiment drop --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF"
        cat result > ../result
        echo -e "${GREEN}Starting CMS experiments${NC}"
        cd ../exp_cms || exit 1
        python run_exp.py --experiment cms --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF"
        cat result >> ../result
        echo -e "${GREEN}Starting Routing experiments${NC}"
        cd ../exp_routing || exit 1
        python run_exp.py --experiment routing --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF"
        cat result >> ../result
        echo -e "${GREEN}Data saved in the result file${NC}"
        ;;
    drop)
        echo -e "${GREEN}Starting Drop experiments${NC}"
        cd exp_drop || exit 1
        python run_exp.py --experiment drop --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF"
        cat result > ../result
        echo -e "${GREEN}Data saved in the result file${NC}"

        ;;
    cms)
        echo -e "${GREEN}Starting CMS experiments${NC}"
        cd exp_cms || exit 1
        python run_exp.py --experiment cms --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF"
        cat result > ../result
        echo -e "${GREEN}Data saved in the result file${NC}"
        ;;
    routing)
        echo -e "${GREEN}Starting Routing experiments${NC}"
        cd exp_routing || exit 1
        python run_exp.py --experiment routing --interface "$INTERFACE" --time "$TIME" --perf "$PERF" --libbpf "$LIBBPF"
        cat result > ../result
        echo -e "${GREEN}Data saved in the result file${NC}"
        ;;
    *)
        echo "Not a valid Experiment  $EXPERIMENT try all" >&2
        exit 1
        ;;
esac



