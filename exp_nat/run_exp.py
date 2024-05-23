import subprocess as sp
import re
from time import sleep
import argparse
import sys 
import os
sys.path.append(os.path.abspath("/opt/trex-core/scripts/automation/trex_control_plane/interactive"))
from trex_stl_lib.api import * # type: ignore
sys.path.append(os.path.abspath("/opt/trex-core/scripts/stl"))
from rand_upd import register # type: ignore

BASH='sudo -E bash -c "export LD_LIBRARY_PATH=/lib64;'
STATS_PATH='../inxpect/inxpect'
KPERF_PATH = '/opt/ebpf-experiment/inxpect/kperf_'

def init_trex():
    c = STLClient(server = '128.105.146.89') # type: ignore
    c.connect()
    stream = register().get_streams(None,None)
    c.reset(ports = [0])
    c.add_streams(stream, ports=[0])
    return c

def start_trex(c):
    # c.clear_stats(ports=[0])
    # num_mult = int(mult.split("pps")[0])
    c.start(ports = [0],mult="40mpps")

    # c.wait_on_traffic()
    # print(f"Waiting for traffic to reach {mult}")
    # while True:
    #     stats = c.get_stats()
    #     stats = stats['global']
    #     tx_pps = stats['tx_pps']
    #     # print(tx_pps)
    #     if tx_pps >= (num_mult//1.001):
    #         break
    # print(f"Traffic rate reached {mult} waiting for up to {duration} seconds")

    # time.sleep(duration)

    # c.stop(ports=[0])
    # print("Stopped traffic")

    # print(tx_pps)
def stop_trex(c):
    c.stop(ports=[0])
    # print("Stopped traffic")

def pretty_output(output):
    # Extract the two integers from the tuple
    value, run_count = output
    
    # Calculate the "x pkt" value (assuming you mean to multiply the two integers)
    x_pkt = round(value / run_count, 2)
    
    # Define the header and the row data
    header = ["value", "run count", "x pkt"]
    row = [value, run_count, x_pkt]
    
    # Define column widths
    column_widths = [max(len(str(item)) for item in col) for col in zip(header, row)]
    
    # Print the header
    header_row = " | ".join(f"{header[i].ljust(column_widths[i])}" for i in range(len(header)))
    print(header_row)
    
    # Print the separator line
    separator_row = "-+-".join("-" * column_widths[i] for i in range(len(header)))
    print(separator_row)
    
    # Print the row data
    data_row = " | ".join(f"{str(row[i]).ljust(column_widths[i])}" for i in range(len(row)))
    print(data_row)

def enable_event(cpu : int):
    sp.call(['sudo', 'wrmsr', '0x186', '0x5300c0', '-p', str(cpu)])

def csv_output(output):
    print("Value,Run count, x pkt")
    print(f"{output[0]},{output[1]},{output[0]/output[1]}")

def init():    
    # enable bpf-stats
    try: # sysctl -w kernel.bpf_stats_enabled=1
        sp.run(['sudo', 'sysctl', '-w', 'kernel.bpf_stats_enabled=1'], capture_output=True, text=True)

        result = sp.run(['sudo', 'lsmod', '|', 'grep', 'mykperf', '|', 'wc' '-l'], capture_output=True, text=True)
        if not result.communicate()[0]:
            # load module 
            sp.run(['sudo', 'make','-C', KPERF_PATH , 'load'], capture_output=True, text=True)
    except Exception as e:
        print(f"An error occurred during enabling bpf_stats: {e}")
        return 1

def make_all():
    try:
        result = sp.run(['make', 'all'], capture_output=True, text=True)
    except Exception as e:
        print(f"An error occurred during compiling: {e}")
        return 1

def bpftool__get_run_cnt(func_name : str) -> int:
    try:
        result = sp.run(['sudo', 'bpftool', 'p'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("Error running bpftool command")
            return 0
        
        output = result.stdout
        
        pattern = re.compile(rf'\d+: .*name {func_name}.*run_cnt (\d+)')
        
        match = pattern.search(output)
        
        if match:
            # print(f"Run count for program name '{func_name}': {match.group(1)}")
            return int(match.group(1))
        else:
            print(f"No run count found for program name '{func_name}'")
            return 0
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0

def perf__get_event_value(prog_id : int, event_name : str, time : int) -> int:
    try:
        command = ['sudo', 'perf', 'stat', '-e', event_name,'-b', str(prog_id), '--timeout', str(time*1000)] #timeout use ns
        
        result = sp.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            print("Error running perf command")
            return 0
        
        output = result.stderr  # perf output is typically in stderr
        
        pattern = re.compile(rf'^\s*([\d,]+)\s+{event_name}', re.MULTILINE)
        
        match = pattern.search(output)
        
        if match:
            event_value = match.group(1).replace(',', '')
            return int(event_value)
        else:
            print(f"No value found for event '{event_name}'")
            return 0
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0

def inx__get_event_value(prog_name : str, event_name : str, cpu : int, time : int) -> tuple[int, int]:
    try:
        
        command = f"{BASH} {STATS_PATH} -n {prog_name} -C {cpu} -e {event_name} -d {time} -a\""
        # print(command)
        result = sp.run(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, text=True)

    
        if result.returncode != 0:
            print("Error running inxpect command")
            return 0,0
        
        output = result.stdout  # inx output is typically in stdout
        value = re.findall(r".*main: (\d+.*\d).*", output)[0].split(" ")

        if len(value) > 0:
            event_value = value[0]
            run_cnt_value = value[-1]
            return int(event_value), int(run_cnt_value)
        else:
            print(f"No value found for event '{event_name}'")
            return 0,0
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0,0

def kill_background_process(prog_name,trex):
    try:
        stop_trex(trex)
        sleep(1)
        if len(prog_name) > 0:
            sp.run(['sudo', 'pkill', prog_name])
    except Exception as e:
        print(f"An error occurred while killing the process: {e}")
    
def prog__get_id_by_name(prog_name : str) -> int:
    try:
        result = sp.run(['sudo', 'bpftool', 'p'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("Error running bpftool command")
            return 0
        
        output = result.stdout
        
        pattern = re.compile(rf'(\d+): .*name {prog_name}.*tag')
        
        match = pattern.search(output)
        
        if match:
            return int(match.group(1))
        else:
            print(f"No program ID found for program name '{prog_name}'")
            return 0
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0

def prog__load_and_attach(prog_path : str, ifname : str,trex ,cpu : int = None) -> int:


    command = f"{BASH} {prog_path}.o {ifname} {cpu if cpu != None else ''}\""
    process = sp.Popen(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
    sleep(1)

    start_trex(trex)

    return process

def prog_test(prog_path : str, ifname : str, t : int, event : str,trex ,cpu : int = None):
    process = prog__load_and_attach(prog_path, ifname,trex,cpu)
    if process == -1:
        print("Error loading program")
        return None
    
    prog_name = prog_path.split('/')[-1]
    
    prog_id = prog__get_id_by_name(prog_name)

    run_cnt = bpftool__get_run_cnt(prog_name)
    
    value=perf__get_event_value(prog_id, event, t)
    
    run_cnt_new = bpftool__get_run_cnt(prog_name)
    
    kill_background_process(prog_name,trex)
    return value, (run_cnt_new - run_cnt)

def prog_test_kfunc(prog_path : str, ifname : str, t : int, event : str,trex, cpu : int = None):

    process = prog__load_and_attach(prog_path, ifname,trex, cpu)
    if process == -1:
        print("Error loading program")
        return None
    
    prog_name = prog_path.split('/')[-1]
    
    
    value, inx_run_cnt=inx__get_event_value(prog_name, event, cpu, t)
    
    
    kill_background_process(prog_name,trex)
    return value, inx_run_cnt


def do_reps(prog_path : str, ifname : str, t : int, event : str, reps : int, trex,  cpu : int = None, v : bool = False) -> tuple[int, int]:
    output = []
    avgs = []
    throughput = []
    for i in range(reps):
        print(f"{i+1}/{reps}", end='\r')
        output.append(prog_test(prog_path, ifname, t, event,trex, cpu))
        avgs.append(output[-1][0] / output[-1][1])
        throughput.append(output[-1][1] / t)

        sleep(1)
        if v:
            pretty_output(output[-1])
            
                
    total_avg = sum(avgs) / len(avgs)
    throughput_avg = sum(throughput) // len(throughput)
    
    total_avg = sum(avgs) / len(avgs)
    
    # do error
    dev_sum = sum([abs((x - total_avg)) for x in avgs])
    mean_dev = dev_sum / len(avgs)
    
    print(f"PERF avg_avg: {round(total_avg, 2)} ; ERR: {round(mean_dev, 4)} ; Throughput: {throughput_avg}")

    
    return  (total_avg, mean_dev)

def do_reps_kfunc(prog_path : str, ifname : str, t : int, event : str, reps : int,trex, cpu : int = None, v : bool = False) -> tuple[int, int]:

    res = []
    output = []
    avgs = []
    throughput = []

    for i in range(reps):
        # print(f"{i+1}/{reps}" ,end='\r')
        output.append(prog_test_kfunc(prog_path, ifname, t, event,trex, cpu))
        avgs.append(output[-1][0] / output[-1][1])
        throughput.append(output[-1][1] / t)
        sleep(1)
        if v:
            pretty_output(output[-1])
    
    total_avg = sum(avgs) / len(avgs)
    throughput_avg = sum(throughput) // len(throughput)
    
    # do error
    dev_sum = sum([abs((x - total_avg)) for x in avgs])
    mean_dev = dev_sum / len(avgs)

    print(f"INX avg_avg: {round(total_avg, 2)} ; ERR: {round(mean_dev, 4)} ; Throughput: {throughput_avg}")
    sys.stdout.flush()


    res=(total_avg, mean_dev, throughput_avg)

    return  res

def baseline(prog_path : str, ifname : str, t : int, event : str,trex, cpu : int = None, v : bool = False):

    process = prog__load_and_attach(prog_path, ifname,trex, cpu)
    if process == -1:
        print("Error loading program")
        return None
    
    prog_name = prog_path.split('/')[-1]
        
    sleep(t)

    run_cnt = bpftool__get_run_cnt(prog_name)
    
    kill_background_process(prog_name,trex)

    return run_cnt // t

def do_reps_baseline(prog_path : str, ifname : str, t : int, event : str, reps : int,trex, cpu : int = None ,v : bool = False,) -> int:  
    res = []
    for i in range(reps):
        # print(f"{i+1}/{reps}" ,end='\r')
        res.append(baseline(prog_path, ifname, t, event,trex, cpu))
        sleep(1)
        
    print(f"Baseline: {sum(res) // len(res)}")
    sys.stdout.flush()
    return sum(res) // len(res)


def main():
    parser = argparse.ArgumentParser(description = "Performance testing")
    parser.add_argument("-t", "--time", help = "Duration of each test in seconds (default:10)", metavar="10",type=int, required = False, default = 10)
    parser.add_argument("-e", "--event", help = "Name of the event (default:L1-dcache-load-misses)",  metavar="L1-dcache-load-misses",required = False, default = "instructions")
    parser.add_argument("-i", "--interface", help = "Interface name (default:ens2f0np0)",metavar="ens2f0np0", required = False, default = "ens2f0np0")
    parser.add_argument("--csv", help = "Output in CSV format", action="store_true")
    parser.add_argument("-r", "--reps", help = "Number of repetitions", metavar="1", type=int, required = False, default = 10)
    parser.add_argument("-v", "--verbose", help = "Verbose output", action="store_true", required = False, default = False)
    args = parser.parse_args()
    
    try:
        cpu=sp.check_output(f'sudo /opt/ebpf-experiments/script_interrupts.sh {args.interface}',shell=True)
        cpu=int(cpu.decode().strip())
        print(f"> CPU: {cpu}\n > Interface: {args.interface}\n > Event: {args.event}\n > Time: {args.time}s\n > Reps: {args.reps}\n > Verbose: {bool(args.verbose)}\n > CSV: {args.csv}\n")

        trex=init_trex()

        # NAT
        # print("\nRunning nat baseline benchmark\n")
        # output = do_reps_baseline('./xdp_nat', args.interface, args.time, args.event, args.reps,trex,cpu, bool(args.verbose))

        # print("\nRunning nat perf benchmark\n")
        # output=do_reps('./xdp_nat', args.interface, args.time, args.event, args.reps,trex,cpu, bool(args.verbose))
        
        print("\nRunning nat inxpect benchmark\n")
        output=do_reps_kfunc('./xdp_nat_kfunc', args.interface, args.time, args.event, args.reps,trex,cpu, bool(args.verbose))
        
        # print("\nRunning nat better inxpect benchmark\n")
        # output=do_reps_kfunc('./xdp_nat_better', args.interface, args.time, args.event, args.reps,trex,cpu, bool(args.verbose))
                
    except Exception as e:
        print(f"An error occurred: {e}")
        
    return 0

if __name__ == "__main__":
    main()
    pass