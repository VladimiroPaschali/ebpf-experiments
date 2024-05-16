import subprocess as sp
import re
from time import sleep
import argparse
import os
import signal

BASH='sudo -E bash -c "export LD_LIBRARY_PATH=/lib64;'
STATS_PATH='../inxpect/inxpect'

def pretty_output(output):
    print("|\t Value \t | \t Run count \t|")
    print(f"|\t {output[0]} \t | \t {output[1]} \t|")

def csv_output(output):
    print("Value,Run count")
    print(f"{output[0]},{output[1]}")

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
    
def kill_background_process(process):
    try:
        if process and process.pid != 0:
            sp.run(['sudo', 'kill', '-9', str(process.pid)])
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
    # check error
    if process.poll() is not None:
        print(f"An error occurred while loading and attaching the program: {process.stderr.read()}")
        return -1
    sleep(0.5)
    return process

def macro(prog_path : str, ifname : str, t : int, event : str) -> tuple[int, int]:
    process = prog__load_and_attach(prog_path, ifname)
    if process == -1:
        print("Error loading program")
        return
    
    prog_name = prog_path.split('/')[-1]
    prog_id = prog__get_id_by_name(prog_name)

    run_cnt = bpftool__get_run_cnt(prog_name)
    
    value=perf__get_event_value(prog_id, event, t)
    
    run_cnt_new = bpftool__get_run_cnt(prog_name)
    kill_background_process(process)
    
    return (value,run_cnt_new - run_cnt)

def baseline(prog_path : str, ifname : str, t : int, event : str) -> tuple[int, int]:
    process = prog__load_and_attach(prog_path, ifname)
    if process == -1:
        print("Error loading program")
        return
    
    prog_name = prog_path.split('/')[-1]
    print(f"prog_name: {prog_name}")
    prog_id = prog__get_id_by_name(prog_name)

    run_cnt = bpftool__get_run_cnt(prog_name)
    
    value=perf__get_event_value(prog_id, event, t)
    
    run_cnt_new = bpftool__get_run_cnt(prog_name)

    kill_background_process(process)
    return (value,run_cnt_new - run_cnt)

def kfunc(prog_path : str, ifname : str, t : int, event : str):
    process = prog__load_and_attach(prog_path, ifname)
    if process == -1:
        print("Error loading program")
        return
    
    prog_name = prog_path.split('/')[-1]
    prog_id = prog__get_id_by_name(prog_name)

    run_cnt = bpftool__get_run_cnt(prog_name)
    
    value=perf__get_event_value(prog_id, event, t)
    
    run_cnt_new = bpftool__get_run_cnt(prog_name)
    
    
    
    print(f"res= {value/(run_cnt_new - run_cnt)}")
    kill_background_process(process)
    return

def main():
    parser = argparse.ArgumentParser(description = "Performance testing")
    parser.add_argument("-t", "--time", help = "Duration of each test in seconds (default:10)", metavar="10",type=int, required = False, default = 10)
    parser.add_argument("-e", "--event", help = "Name of the event (default:instructions)",  metavar="instructions",required = False, default = "instructions")
    parser.add_argument("-i", "--interface", help = "Interface name (default:ens2f1np1)",metavar="ens2f1np1", required = False, default = "ens2f1np1")
    parser.add_argument("-c", "--cpu", help = "CPU number (default:21)", metavar="21", type=int, required = False, default = 21)
    parser.add_argument("--csv", help = "Output in CSV format", action="store_true")
    args = parser.parse_args()

    print(f"CPU: {args.cpu}\n, Interface: {args.interface}\n, Event: {args.event}\n, Time: {args.time}s\n")
    
    print("\nCompiling all programs\n")
    make_all()
    
    print("\nRunning baseline benchmark\n")
    value, run_count = baseline('../exp_drop/drop', args.interface, args.time, args.event)
    if args.csv:
        csv_output((value,run_count))
    else: 
        pretty_output((value,run_count))
    
    print("\nRunning macro benchmark\n")
    value, run_count=macro('../macro', args.interface, args.time, args.event)
    if args.csv:
        csv_output((value,run_count))
    else: 
        pretty_output((value,run_count))

    print("\nRunning kfunc benchmark\n")
    value, run_count=kfunc('../kfunc', args.interface, args.time, args.event)
    if args.csv:
        csv_output((value,run_count))
    else: 
        pretty_output((value,run_count))

    return 0

if __name__ == "__main__":
    cpu = 21
    event= 'instructions'
    t = 5 # seconds
    baseline('./parse_drop', 'ens2f1np1', t, event)
    pass