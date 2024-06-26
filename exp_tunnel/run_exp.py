import argparse
import shlex
import subprocess
import signal
import time
import os
import sys
import re

#ridefiniti nel main in base ai parametri
EXPERIMENT_NAME = "tunnel"
EXPRIMENT_FUNC_NAME = "tunnel_kfunc" # FRANCESCO
INTERFACE = "enp81s0f0np0"
TIME =10
PERF_PATH="perf"
LIBBPF_PATH="/lib64"
LOADER_STATS="../inxpect/inxpect"

#legge stats da bpftool prog si possono calcolare PPS e Latency
def baseline():

    time.sleep(1.0)
    #oldvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    oldvalue_time = int(out.split(" ")[0])
    #oldvalue_runcnt
    oldvalue_runcnt = int(out.split(" ")[1])

    time.sleep(TIME)
    #newvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    newvalue_time = int(out.split(" ")[0])
    #newvalue_runcnt
    newvalue_runcnt = int(out.split(" ")[1])

    throughput = (newvalue_runcnt-oldvalue_runcnt)//TIME
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"baseline: throughput = {throughput} PPS latency = {latency} ns"

    subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)

#legge stats da bpftool prog si possono calcolare PPS e Latency
def bpftool():
    # evento = "instructions"
    evento = "llc_misses"


    # bpftool = subprocess.Popen(f'sudo bpftool prog profile name {EXPERIMENT_NAME} llc_misses > /dev/null 2> /dev/null',shell=True,preexec_fn=os.setsid)
    bpftool = subprocess.Popen(f'sudo bpftool prog profile name {EXPERIMENT_NAME} {evento}',shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE,preexec_fn=os.setsid)
    time.sleep(1.0)
    #oldvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    oldvalue_time = int(out.split(" ")[0])
    #oldvalue_runcnt
    oldvalue_runcnt = int(out.split(" ")[1])

    time.sleep(TIME)
    #newvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    newvalue_time = int(out.split(" ")[0])
    #newvalue_runcnt
    newvalue_runcnt = int(out.split(" ")[1])

    # bpftool.terminate()
    os.killpg(os.getpgid(bpftool.pid), signal.SIGINT)
    #reads PIPE stdout and stderr
    output, ris = bpftool.communicate()
    # print(output)
    # print(ris)
    out = output.splitlines()
    riga = out[2].decode("utf-8").split(" ")
    # #rimuove stringhe vuote "" dalla lista
    riga = list(filter(bool, riga))
    miss=int(riga[0])
    # print(miss)


    throughput = (newvalue_runcnt-oldvalue_runcnt)//TIME
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"bpftool: throughput = {throughput} PPS latency = {latency} ns"

    subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)

    stampa = f"bpftool {evento} per packet: {miss/(newvalue_runcnt-oldvalue_runcnt)}"
    subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)

#legge stats da bpftool prog si possono calcolare PPS e Latency
def perf():

    # evento="instructions"
    # evento="LLC-load-misses"
    evento = "L1-dcache-load-misses"


    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f1',shell=True)
    out=out.decode("utf-8")
    out=out.split(":")[0]
    prog_id = int(out)

    # perf = subprocess.Popen(f'sudo {PERF_PATH} stat -e LLC-load-misses -b {prog_id}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    perf = subprocess.Popen(f'sudo {PERF_PATH} stat -e {evento} -b {prog_id}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    # perf = subprocess.Popen(f'sudo {PERF_PATH} stat -e r0964 -b {prog_id}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

    #oldvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    # print(out)
    oldvalue_time = int(out.split(" ")[0])
    #oldvalue_runcnt
    oldvalue_runcnt = int(out.split(" ")[1])

    time.sleep(TIME)
    #newvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    newvalue_time = int(out.split(" ")[0])
    #newvalue_runcnt
    newvalue_runcnt = int(out.split(" ")[1])

    os.killpg(os.getpgid(perf.pid), signal.SIGINT)
    #reads PIPE stdout and stderr
    output, ris = perf.communicate()
    ris = ris.splitlines()
    riga = ris[3].decode("utf-8").split(" ")
    #rimuove stringhe vuote "" dalla lista
    riga = list(filter(bool, riga))
    instructions=riga[0]

    instructions=int(instructions.replace(",",""))
    # print(instructions)

    throughput = (newvalue_runcnt-oldvalue_runcnt)//TIME
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"perf: throughput = {throughput} PPS latency = {latency} ns"

    subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)
    # print(instructions, newvalue_runcnt, oldvalue_runcnt, newvalue_runcnt-oldvalue_runcnt , instructions/(newvalue_runcnt-oldvalue_runcnt))
    stampa = f"perf {evento} per packet: {instructions/(newvalue_runcnt-oldvalue_runcnt)}"
    subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)


#legge stats da bpftool prog si possono calcolare PPS e Latency
def kfunc():

    # evento="instructions"
    # evento="llc-misses"
    evento = "L1-dcache-load-misses"



    time.sleep(1.0)

    if not (os.path.exists(LOADER_STATS)):
            print("Compiling Kfunc loader")
            subprocess.check_output('make', cwd="../loader",shell=True)
            subprocess.check_output('chmod go+w *.o', shell=True)
    

    cpu=subprocess.check_output(f'sudo /opt/script_interrupts.sh {INTERFACE}',shell=True)
    cpu=cpu.decode().strip()
    print("CPU =",cpu)

    loader_stats_output = subprocess.Popen(f'sudo -E bash -c "export LD_LIBRARY_PATH={LIBBPF_PATH}; {LOADER_STATS} -n {EXPRIMENT_FUNC_NAME} -e {evento} -a -C {cpu}"',stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, shell=True)

    #oldvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    oldvalue_time = int(out.split(" ")[0])
    #oldvalue_runcnt
    oldvalue_runcnt = int(out.split(" ")[1])

    time.sleep(TIME)
    #newvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
    out=out.decode()
    newvalue_time = int(out.split(" ")[0])
    #newvalue_runcnt
    newvalue_runcnt = int(out.split(" ")[1])
    
    # close loader_stats FRACNESCO
    subprocess.check_output('sudo pkill inxpect', shell=True)
    #retrieve data FRANCESCO
    output, errors = loader_stats_output.communicate()
    output = output.decode("utf-8")
    print(output)
    print(errors)

    value = re.findall(r".*main: (\d+.*\d).*", output)[0].split(" ")[0].replace(".", "")
    
    throughput = (newvalue_runcnt-oldvalue_runcnt)//TIME
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"kfunc: throughput = {throughput} PPS latency = {latency} ns"
    subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)

    stampa = f"kfunc {evento} per packet: {int(value)/(newvalue_runcnt-oldvalue_runcnt)}" #FRACNESCO
    subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True) # FRANCESCO
# def instructions():

#     out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f1',shell=True)
#     out=out.decode("utf-8")
#     out=out.split(":")[0]
#     prog_id = int(out)
#     #preexec_fn=os.setsid a quanto pare è fondamentale 
#     process = subprocess.Popen(f'sudo {PERF_PATH}perf stat -e instructions -b {prog_id}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
#     time.sleep(TIME)
#     os.killpg(os.getpgid(process.pid), signal.SIGINT)
#     #reads PIPE stdout and stderr
#     output, ris = process.communicate()
#     ris = ris.splitlines()
#     riga = ris[3].decode("utf-8").split(" ")
#     instructions=riga[5]
#     # print(instructions)
#     stampa = f"instructions: {instructions}"
#     subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)



def parser():

    global EXPERIMENT_NAME
    global INTERFACE
    global TIME
    global PERF_PATH
    global LIBBPF_PATH

    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    
    parser = argparse.ArgumentParser(description = "Performance testing")
    parser.add_argument("-t", "--time", help = "Duration of each test in seconds (default:10)", metavar="10",type=int, required = False, default = 10)
    parser.add_argument("-e", "--experiment", help = "Name of the experiment (default:tunnel)",  metavar="tunnel",required = False, default = "tunnel")
    parser.add_argument("-i", "--interface", help = "Interface name (default:enp129s0f0np0)",metavar="enp129s0f0np0", required = False, default = "enp81s0f0np0")
    parser.add_argument("-p", "--perf", help = "Path of perf (default:/home/guest/linux/tools/perf/)",metavar="PATH", required = False, default = "perf")
    parser.add_argument("-l", "--libbpf", help = "Path of libbpf (default:/home/guest/libbpf/src/)",metavar="PATH", required = False, default = "/lib64")
    args = parser.parse_args()

    EXPERIMENT_NAME = args.experiment
    INTERFACE = args.interface
    TIME = args.time
    PERF_PATH=args.perf
    LIBBPF_PATH=args.libbpf

def main():
    try:
        parser()
        if(os.path.exists("result")):
            subprocess.check_output('rm result', shell=True)
        
        if not (os.path.exists("tunnel.o")):
            print("Compiling BPF programs")
            subprocess.check_output('make', shell=True)
            subprocess.check_output('chmod go+w *.o', shell=True)
            subprocess.check_output('chmod go+w *.h', shell=True)
        
        global EXPERIMENT_NAME
        print(f"Starting {EXPERIMENT_NAME}")
        subprocess.check_output("sudo sysctl kernel.bpf_stats_enabled=1", shell=True)
        subprocess.check_output('echo "'+EXPERIMENT_NAME+': " | tee -a result >/dev/null', shell=True)

        # my_env = {'LD_LIBRARY_PATH': '/lib64'}
        #nuovo path di lib64
        my_env = {'LD_LIBRARY_PATH': LIBBPF_PATH}


        command = f"./{EXPERIMENT_NAME}.o  {INTERFACE}"
        experiment = subprocess.Popen(shlex.split(command),env=my_env,shell=False)

        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
        out=out.decode()
        while out == "\n":
            print("No Packet received")
            time.sleep(1.0)
            out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
            out=out.decode()


        print(f"Start {EXPERIMENT_NAME} Baseline")
        baseline()


        print(f"Start {EXPERIMENT_NAME} bpftool")
        bpftool()

        print(f"Start {EXPERIMENT_NAME} perf")
        perf()
        
        # print(f"Start {EXPERIMENT_NAME} instructions")
        # instructions()

        experiment.terminate()
        # print("timer")
        # time.sleep(15.0)
        print("Start kfunc")
        EXPERIMENT_NAME = EXPERIMENT_NAME+"_kfunc"
        subprocess.check_output('echo "'+EXPERIMENT_NAME+': " | tee -a result >/dev/null', shell=True)
        command = f"./{EXPERIMENT_NAME}.o {INTERFACE}"
        experimentkfunc = subprocess.Popen(shlex.split(command),env=my_env,shell=False)
        kfunc()
        
        print(f"Start {EXPERIMENT_NAME} perf")
        perf()
        experimentkfunc.terminate()


        
    except KeyboardInterrupt:
        print("Interrupted")
    
    finally:
        print("Terminating experiment")
        try:
            experiment.terminate()
        except NameError:
            pass
        try:
            experimentkfunc.terminate()
        except NameError:
            pass



main()
