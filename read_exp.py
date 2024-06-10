
import subprocess as sp
from time import sleep


BASH='sudo -E bash -c "export LD_LIBRARY_PATH=/lib64;'
STATS_PATH='./inxpect/inxpect_tr'
KPERF_PATH = '/opt/ebpf-experiment/inxpect/kperf_'

def run_drop(prog_path : str, ifname : str, cpu : int = None) -> int:
    command = f"{BASH} {prog_path}.o {ifname} {cpu if cpu != None else ''}\""
    process = sp.Popen(command, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, text=True)

    
    sleep(1)
    return process


def run_inxpect(time : int, cpu : int = 0):
    command = f"{BASH} {STATS_PATH} -n drop_kfunc -e instructions -a -C {cpu} -d {time}\""
    result = sp.run(command.split(), shell=True, stdout=sp.PIPE, stderr=sp.PIPE, text=True)

    return result


def main():
    cpu=sp.check_output(f'sudo /opt/ebpf-experiments/script_interrupts.sh ens2f0np0',shell=True)
    cpu=int(cpu.decode().strip())

    process = run_drop("./exp_drop/drop_kfunc", "ens2f0np0", cpu)
    
    result = run_inxpect(10, cpu)
    
    # main: 3005844503   40.53/pkt - 74170144 run_cnt
    run_cnt=result.stdout.split()[4]