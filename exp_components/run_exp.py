import subprocess as sp
import re
from time import sleep
import argparse
import os
import signal

BASH='sudo -E bash -c "export LD_LIBRARY_PATH=/lib64;'
STATS_PATH='../inxpect/inxpect'
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
            print(f"Run count for program name '{func_name}': {match.group(1)}")
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
        print(output)
        
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

def prog__load_and_attach(prog_path : str, ifname : str) -> int:
    command = f"{BASH} {prog_path}.o {ifname}\""
    process = sp.Popen(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, text=True)

    
    sleep(1)
    return process

def prog_test(prog_path : str, ifname : str, t : int, event : str):
    process = prog__load_and_attach(prog_path, ifname)
    if process == -1:
        print("Error loading program")
        return None
    
    prog_name = prog_path.split('/')[-1]
    
    prog_id = prog__get_id_by_name(prog_name)

    run_cnt = bpftool__get_run_cnt(prog_name)
    
    value=perf__get_event_value(prog_id, event, t)
    
    run_cnt_new = bpftool__get_run_cnt(prog_name)
    
    kill_background_process(prog_name)
    return value, (run_cnt_new - run_cnt)

def do_reps(prog_path : str, ifname : str, t : int, event : str, reps : int, v : bool = False):
    output = []
    
    for _ in range(reps):
        output.append(prog_test(prog_path, ifname, t, event))
        sleep(0.5)
        if v:
            pretty_output(output[-1])
    
    # do avg
    
    
    return output
    

def main():
    parser = argparse.ArgumentParser(description = "Performance testing")
    parser.add_argument("-t", "--time", help = "Duration of each test in seconds (default:10)", metavar="10",type=int, required = False, default = 10)
    parser.add_argument("-e", "--event", help = "Name of the event (default:instructions)",  metavar="instructions",required = False, default = "instructions")
    parser.add_argument("-i", "--interface", help = "Interface name (default:ens2f1np1)",metavar="ens2f1np1", required = False, default = "ens2f1np1")
    parser.add_argument("-c", "--cpu", help = "CPU number (default:21)", metavar="21", type=int, required = False, default = 21)
    parser.add_argument("--csv", help = "Output in CSV format", action="store_true")
    parser.add_argument("-r", "--reps", help = "Number of repetitions", metavar="1", type=int, required = False, default = 1)
    args = parser.parse_args()

    print(f"CPU: {args.cpu}\n, Interface: {args.interface}\n, Event: {args.event}\n, Time: {args.time}s\n")
    
    try:
        # init()
        
        
        print("\nCompiling all programs\n")
        # make_all()
        
        # BASELINE
        print("\nRunning baseline benchmark\n")
        output = prog_test('./drop', args.interface, args.time, args.event)
        if output:
            if args.csv:
                csv_output(output)
            else: 
                pretty_output(output)
            
        sleep(1)
        
        # # MACRO
        # print("\nRunning macro benchmark\n")
        # enable_event(args.cpu)
        # output=prog_test('./macro', args.interface, args.time, args.event)
        # if output:
        #     if args.csv:
        #         csv_output(output)
        #     else: 
        #         pretty_output(output)
            
        # sleep(1)

        # KFUNC
        print("\nRunning kfunc benchmark\n")
        output=prog_test('./kfunc', args.interface, args.time, args.event)
        if output:
            if args.csv:
                csv_output(output)
            else: 
                pretty_output(output)
        
        sleep(1)
        
        # # FENTRY READ
        # print("\nRunning fentry_read benchmark\n")
        # output=prog_test('./fentry_read', args.interface, args.time, args.event)
        # if output:
        #     if args.csv:
        #         csv_output(output)
        #     else: 
        #         pretty_output(output)
                
        # sleep(1)
        
        # # FENTRY UPDATE
        # print("\nRunning fentry_update benchmark\n")
        # output=prog_test('./fentry_update', args.interface, args.time, args.event)
        # if output:
        #     if args.csv:
        #         csv_output(output)
        #     else: 
        #         pretty_output(output)
                
    except Exception as e:
        print(f"An error occurred: {e}")
        
    return 0

if __name__ == "__main__":
    main()
    pass