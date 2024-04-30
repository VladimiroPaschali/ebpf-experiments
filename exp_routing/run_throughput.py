import sys
import os
sys.path.append(os.path.abspath("/opt/trex-core/scripts/automation/trex_control_plane/interactive"))
from trex_stl_lib.api import * # type: ignore
sys.path.append(os.path.abspath("/opt/trex-core/scripts/stl"))
from rand_upd import register # type: ignore

import argparse
import shlex
import subprocess
import signal
import time
import re
import locale


#ridefiniti nel main in base ai parametri
EXPERIMENT_NAME = "routing"
EXPRIMENT_FUNC_NAME = "lpmtrie_kfunc" # FRANCESCO
INTERFACE = "ens2f0np0"
PERF_PATH="perf"
LIBBPF_PATH="/lib64"
LOADER_STATS="../loader/light-stats.o" # FRANCESCO
 
def init_trex():
    c = STLClient(server = '128.105.146.86') # type: ignore
    c.connect()
    stream = register().get_streams(None,None)
    c.reset(ports = [0])
    c.add_streams(stream, ports=[0])
    return c

def start_trex(c,duration,mult):
    c.clear_stats(ports=[0])
    num_mult = int(mult.split("pps")[0])
    c.start(ports = [0],mult=mult)

    # c.wait_on_traffic()
    print(f"Waiting for traffic to reach {mult}")
    while True:
        stats = c.get_stats()
        stats = stats['global']
        tx_pps = stats['tx_pps']
        # print(tx_pps)
        if tx_pps >= (num_mult//1.10):
            break
    print(f"Traffic rate reached {mult} waiting for up to {duration} seconds")

    # time.sleep(duration)

    # c.stop(ports=[0])
    # print("Stopped traffic")

    # print(tx_pps)
def stop_trex(c):
    c.stop(ports=[0])
    print("Stopped traffic")

def kfunc(num_mult):
    time.sleep(1.0)

    evento = "llc-misses"
    # evento = "instructions"


    if not (os.path.exists(LOADER_STATS)):
            print("Compiling Kfunc loader")
            subprocess.check_output('make', cwd="../loader",shell=True)
            subprocess.check_output('chmod go+w *.o', shell=True)
    

    loader_stats_output = subprocess.Popen(f'sudo -E bash -c "export LD_LIBRARY_PATH={LIBBPF_PATH}; {LOADER_STATS} -n {EXPRIMENT_FUNC_NAME} -e {evento} -a"',stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, shell=True)
    
    start = time.time()
    
    while True:

        #oldvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}" | cut -d" " -f12,14',shell=True)
        out=out.decode()
        # print(out,EXPERIMENT_NAME)
        oldvalue_time = int(out.split(" ")[0])
        #oldvalue_runcnt
        oldvalue_runcnt = int(out.split(" ")[1])

        time.sleep(1)
        #newvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
        out=out.decode()
        newvalue_time = int(out.split(" ")[0])
        #newvalue_runcnt
        newvalue_runcnt = int(out.split(" ")[1])
        if newvalue_runcnt-oldvalue_runcnt > num_mult//1.10:
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult//1.10)
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult/1.10)
            break
        
        if time.time()-start > TIME:
            break
    
    # close loader_stats FRACNESCO
    os.killpg(os.getpgid(loader_stats_output.pid), signal.SIGINT)

    # retrieve data FRANCESCO
    output, errors = loader_stats_output.communicate()
    output = output.decode("utf-8")
    # print(output)
    # print(errors)

    value, runcnt = re.findall(r".*main: (\d*.*\d).*- (\d*.*\d).*", output)[0]
    # print(value,runcnt)
    # print(newvalue_runcnt-oldvalue_runcnt)
    
    throughput = (newvalue_runcnt-oldvalue_runcnt)
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"kfunc: throughput = {throughput} PPS latency = {latency} ns"
    subprocess.check_output(f'echo {stampa} | tee throughput_result -a >/dev/null', shell=True)

    return throughput

#legge stats da bpftool prog si possono calcolare PPS e Latency
def baseline(num_mult):

    time.sleep(1.0)
    start = time.time()

    #oldvalue_time
    while True:

        #oldvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}" | cut -d" " -f12,14',shell=True)
        out=out.decode()
        # print(out,EXPERIMENT_NAME)
        oldvalue_time = int(out.split(" ")[0])
        #oldvalue_runcnt
        oldvalue_runcnt = int(out.split(" ")[1])

        time.sleep(1)
        #newvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
        out=out.decode()
        newvalue_time = int(out.split(" ")[0])
        #newvalue_runcnt
        newvalue_runcnt = int(out.split(" ")[1])
        if newvalue_runcnt-oldvalue_runcnt > num_mult//1.10:
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult//1.10)
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult/1.10)
            break
        
        if time.time()-start > TIME:
            break
    
    throughput = newvalue_runcnt-oldvalue_runcnt
    # print(throughput , num_mult//1.10, throughput<num_mult//1.10)
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"baseline: throughput = {throughput} PPS latency = {latency} ns"
    subprocess.check_output(f'echo {stampa} | tee throughput_result -a >/dev/null', shell=True)
     
    return throughput

    #legge stats da bpftool prog si possono calcolare PPS e Latency
def bpftool(num_mult):

    time.sleep(1.0)
    start = time.time()
    evento = "llc_misses"

    bpftool = subprocess.Popen(f'sudo bpftool prog profile name {EXPERIMENT_NAME} {evento}',shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE,preexec_fn=os.setsid)

    #oldvalue_time
    while True:

        #oldvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}" | cut -d" " -f12,14',shell=True)
        out=out.decode()
        # print(out,EXPERIMENT_NAME)
        oldvalue_time = int(out.split(" ")[0])
        #oldvalue_runcnt
        oldvalue_runcnt = int(out.split(" ")[1])

        time.sleep(1)
        #newvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
        out=out.decode()
        newvalue_time = int(out.split(" ")[0])
        #newvalue_runcnt
        newvalue_runcnt = int(out.split(" ")[1])
        if newvalue_runcnt-oldvalue_runcnt > num_mult//1.10:
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult//1.10)
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult/1.10)
            break
        
        if time.time()-start > TIME:
            break
    
    os.killpg(os.getpgid(bpftool.pid), signal.SIGINT)

    throughput = (newvalue_runcnt-oldvalue_runcnt)
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"bpftool: throughput = {throughput} PPS latency = {latency} ns"
    subprocess.check_output(f'echo {stampa} | tee throughput_result -a >/dev/null', shell=True)
     
    return throughput

#legge stats da bpftool prog si possono calcolare PPS e Latency
def perf(num_mult):

    evento = "LLC-load-misses"
    # evento = "instructions"


    time.sleep(1.0)
    start = time.time()

    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f1',shell=True)
    out=out.decode("utf-8")
    out=out.split(":")[0]
    prog_id = int(out)


    perf = subprocess.Popen(f'sudo {PERF_PATH} stat -e {evento} -b {prog_id}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    # perf = subprocess.Popen(f'sudo {PERF_PATH} stat -e instructions -b {prog_id}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

    #oldvalue_time
    while True:

        #oldvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}" | cut -d" " -f12,14',shell=True)
        out=out.decode()
        # print(out,EXPERIMENT_NAME)
        oldvalue_time = int(out.split(" ")[0])
        #oldvalue_runcnt
        oldvalue_runcnt = int(out.split(" ")[1])

        time.sleep(1)
        #newvalue_time
        out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
        out=out.decode()
        newvalue_time = int(out.split(" ")[0])
        #newvalue_runcnt
        newvalue_runcnt = int(out.split(" ")[1])
        if newvalue_runcnt-oldvalue_runcnt > num_mult//1.10:
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult//1.10)
            # print(newvalue_runcnt-oldvalue_runcnt, num_mult/1.10)
            break
        
        if time.time()-start > TIME:
            break

    os.killpg(os.getpgid(perf.pid), signal.SIGINT)
    # #reads PIPE stdout and stderr
    # output, ris = perf.communicate()
    # ris = ris.splitlines()
    # riga = ris[3].decode("utf-8").split(" ")
    # #rimuove stringhe vuote "" dalla lista
    # riga = list(filter(bool, riga))
    # instructions=riga[0]

    # instructions=int(instructions.replace(",",""))
    # # print(instructions)

    throughput = (newvalue_runcnt-oldvalue_runcnt)
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"perf: throughput = {throughput} PPS latency = {latency} ns"

    subprocess.check_output(f'echo {stampa} | tee throughput_result -a >/dev/null', shell=True)
    # # print(instructions, newvalue_runcnt, oldvalue_runcnt, newvalue_runcnt-oldvalue_runcnt , instructions/(newvalue_runcnt-oldvalue_runcnt))
    # stampa = f"perf {evento} per packet: {instructions/(newvalue_runcnt-oldvalue_runcnt)}"
    # subprocess.check_output(f'echo {stampa} | tee result -a >/dev/null', shell=True)
    return throughput


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
    parser.add_argument("-e", "--experiment", help = "Name of the experiment (default:routing)",  metavar="routing",required = False, default = "routing")
    parser.add_argument("-i", "--interface", help = "Interface name (default:enp129s0f0np0)",metavar="enp129s0f0np0", required = False, default = "ens2f0np0")
    parser.add_argument("-p", "--perf", help = "Path of perf (default:/home/guest/linux/tools/perf/)",metavar="PATH", required = False, default = "perf")
    parser.add_argument("-l", "--libbpf", help = "Path of libbpf (default:/home/guest/libbpf/src/)",metavar="PATH", required = False, default = "/lib64")

    args = parser.parse_args()

    EXPERIMENT_NAME = args.experiment
    if EXPERIMENT_NAME == "routing":
        EXPERIMENT_NAME = "lpmtrie"

    INTERFACE = args.interface
    TIME = args.time
    PERF_PATH=args.perf
    LIBBPF_PATH=args.libbpf

def main():
    c = init_trex()
    global EXPERIMENT_NAME

    try:
        parser()
        if(os.path.exists("throughput_result")):
            subprocess.check_output('rm throughput_result', shell=True)
        
        if not (os.path.exists("lpmtrie.o")):
            print("Compiling BPF programs")
            subprocess.check_output('make', shell=True)
            subprocess.check_output('chmod go+w *.o', shell=True)
            subprocess.check_output('chmod go+w *.h', shell=True)

        subprocess.check_output("sudo sysctl kernel.bpf_stats_enabled=1", shell=True)
        for i in range(4):
            #1MPPS
            mult = "1000000pps"
            if i == 3:
                EXPERIMENT_NAME = "lpmtrie_kfunc"
            if i==0 or i==3:
                #10MPPS
                mult = "4000000pps"

            while True:
                # print(i,EXPERIMENT_NAME,mult)
                start_trex(c,TIME,mult)
                # subprocess.check_output('echo "'+EXPERIMENT_NAME+' with "'+mult+'"" | tee -a throughput_result >/dev/null', shell=True)

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

                num_mult = int(mult.split("pps")[0])
                                    
                throughput =0

                match i:
                    # case 0:
                    #     throughput = baseline(num_mult)

                    # case 1:
                    #     throughput = perf(num_mult)
                    # case 2:
                    #     throughput = bpftool(num_mult)

                    case 3:
                        
                        throughput = kfunc(num_mult)
                # throughput = baseline(num_mult)
                # throughput = perf(num_mult)
                # throughput = bpftool(num_mult)



                # print(throughput, num_mult//1.10, throughput<num_mult//1.10)

                experiment.terminate()
                stop_trex(c)


                if throughput < num_mult//1.10:
                    break
                else:
                    num_mult = int(num_mult*1.10)
                    mult = str(num_mult)+"pps"


    except KeyboardInterrupt:
        print("Interrupted")
    
    finally:
        print("Terminating experiment")
        try:
            stop_trex(c)
            experiment.terminate()

        except NameError:
            pass
        try:
            subprocess.check_output('sudo pkill light-stats.o', shell=True)
        except:
            pass

# print(c)

main()