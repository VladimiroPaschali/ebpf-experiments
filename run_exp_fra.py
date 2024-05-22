import subprocess as sp
import re
import sys
from time import sleep
import argparse
import os
import signal

BASH='sudo -E bash -c "export LD_LIBRARY_PATH=/lib64;'
STATS_PATH='./inxpect/inxpect'
KPERF_PATH = '/opt/ebpf-experiment/inxpect/kperf_'

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
    
def kill_background_process(prog_name):
    try:
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

def prog__load_and_attach(prog_path : str, ifname : str, cpu : int = None) -> int:
    command = f"{BASH} {prog_path}.o {ifname} {cpu if cpu != None else ''}\""
    process = sp.Popen(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, text=True)

    
    sleep(1)
    return process

def prog_test(prog_path : str, ifname : str, t : int, event : str, cpu : int = None):

    process = prog__load_and_attach(prog_path, ifname, cpu)
    if process == -1:
        print("Error loading program")
        return None
    
    prog_name = prog_path.split('/')[-1]
    
    
    if(prog_name.startswith("fentry")):
        prog_id = prog__get_id_by_name("drop")
    else:
        prog_id = prog__get_id_by_name(prog_name)

    run_cnt = bpftool__get_run_cnt(prog_name)
    
    value=perf__get_event_value(prog_id, event, t)
    
    run_cnt_new = bpftool__get_run_cnt(prog_name)
    
    kill_background_process(prog_name)
    return value, (run_cnt_new - run_cnt) 

def prog_test_kfunc(prog_path : str, ifname : str, t : int, event : str, cpu : int = None):

    process = prog__load_and_attach(prog_path, ifname, cpu)
    if process == -1:
        print("Error loading program")
        return None
    
    prog_name = prog_path.split('/')[-1]
    
    
    value, inx_run_cnt=inx__get_event_value(prog_name, event, cpu, t)
    
    
    kill_background_process(prog_name)
    # return value, (run_cnt_new - run_cnt) 
    return value, inx_run_cnt

def baseline(prog_path : str, ifname : str, t : int, event : str, cpu : int = None, v : bool = False):

    process = prog__load_and_attach(prog_path, ifname, cpu)
    if process == -1:
        print("Error loading program")
        return None
    
    prog_name = prog_path.split('/')[-1]
        
    run_cnt_old = bpftool__get_run_cnt(prog_name)

    sleep(t)
    
    run_cnt_new = bpftool__get_run_cnt(prog_name)
    
    kill_background_process(prog_name)
    # return value, (run_cnt_new - run_cnt) 

    return (run_cnt_new-run_cnt_old) // t

def do_reps_baseline(prog_path : str, ifname : str, t : int, event : str, reps : int, cpu : int = None ,v : bool = False,) -> int:  
    res = []
    for i in range(reps):
        # print(f"{i+1}/{reps}" ,end='\r')
        res.append(baseline(prog_path, ifname, t, event, cpu))
        sleep(1)
        
    print(f"Baseline: {sum(res) // len(res)}")
    sys.stdout.flush()
    return sum(res) // len(res)

def do_reps(prog_path : str, ifname : str, t : int, event : str, reps : int, cpu : int = None, v : bool = False) -> tuple[int, int]:
    res = []
    output = []
    avgs = []
    throughput = []
    for i in range(reps):
        # print(f"{i+1}/{reps}" ,end='\r')
        output.append(prog_test(prog_path, ifname, t, event, cpu))
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

    print(f"PERF avg_avg: {round(total_avg, 2)} ; ERR: {round(mean_dev, 4)} ; Throughput: {throughput_avg}")
    sys.stdout.flush()
    res=(total_avg, mean_dev, throughput_avg)
    return res

def do_reps_kfunc(prog_path : str, ifname : str, t : int, event : str, reps : int, cpu : int = None, v : bool = False) -> tuple[int, int]:

    res = []
    output = []
    avgs = []
    throughput = []

    for i in range(reps):
        # print(f"{i+1}/{reps}" ,end='\r')
        output.append(prog_test_kfunc(prog_path, ifname, t, event, cpu))
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
    

def main():
    parser = argparse.ArgumentParser(description = "Performance testing")
    parser.add_argument("-t", "--time", help = "Duration of each test in seconds (default:10)", metavar="10",type=int, required = False, default = 10)
    parser.add_argument("-e", "--event", help = "Name of the event (default:L1-dcache-load-misses)",  metavar="L1-dcache-load-misses",required = False, default = "L1-dcache-load-misses")
    parser.add_argument("-i", "--interface", help = "Interface name (default:ens2f0np0)",metavar="ens2f0np0", required = False, default = "ens2f0np0")
    parser.add_argument("--csv", help = "Output in CSV format", action="store_true")
    parser.add_argument("-r", "--reps", help = "Number of repetitions", metavar="1", type=int, required = False, default = 1)
    parser.add_argument("-v", "--verbose", help = "Verbose output", action="store_true", required = False, default = False)
    args = parser.parse_args()

    
    try:
        # init()
        cpu=sp.check_output(f'sudo /opt/ebpf-experiments/script_interrupts.sh {args.interface}',shell=True)
        cpu=int(cpu.decode().strip())
        print(f" > CPU: {cpu}\n > Interface: {args.interface}\n > Event: {args.event}\n > Time: {args.time}s\n > Reps: {args.reps}\n > Verbose: {bool(args.verbose)}\n > CSV: {args.csv}\n")
        

        print("\nRunning drop baseline benchmark\n")
        output = do_reps_baseline('./exp_drop/drop', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        print("\nRunning drop benchmark\n")
        output = do_reps('./exp_drop/drop', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        sleep(1)
        print("\nRunning drop KFUNC benchmark\n")
        output = do_reps_kfunc('./exp_drop/drop_kfunc', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))

        print("\nRunning cms baseline benchmark\n")
        output = do_reps_baseline('./exp_cms/cms', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        print("\nRunning cms miano benchmark\n")
        output = do_reps('./exp_cms_miano/cms', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        sleep(1)
        print("\nRunning cms miano KFUNC benchmark\n")
        output = do_reps_kfunc('./exp_cms_miano/cms_kfunc', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))

        print("\nRunning routing baseline benchmark\n")
        output = do_reps_baseline('./exp_routing/lpmtrie', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        print("\nRunning routing benchmark\n")
        output = do_reps('./exp_routing/lpmtrie', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        sleep(1)
        print("\nRunning routing KFUNC benchmark\n")
        output = do_reps_kfunc('./exp_routing/lpmtrie_kfunc', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))

        print("\nRunning tunnel baseline benchmark\n")
        output = do_reps_baseline('./exp_tunnel/tunnel', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        print("\nRunning tunnel benchmark\n")
        output = do_reps('./exp_tunnel/tunnel', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        sleep(1)
        print("\nRunning tunnel KFUNC benchmark\n")
        output = do_reps_kfunc('./exp_tunnel/tunnel_kfunc', args.interface, args.time, args.event, args.reps,cpu, bool(args.verbose))
        
        sleep(1)
        
                
    except Exception as e:
        print(f"An error occurred: {e}")
        
    return 0

if __name__ == "__main__":
    main()
    pass