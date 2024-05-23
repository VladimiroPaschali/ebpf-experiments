import argparse
import shlex
import subprocess
import signal
import time
import os
import sys
import re
sys.path.append(os.path.abspath("/opt/trex-core/scripts/automation/trex_control_plane/interactive"))
from trex_stl_lib.api import * # type: ignore
sys.path.append(os.path.abspath("/opt/trex-core/scripts/stl"))
from rand_upd import register # type: ignore


#ridefiniti nel main in base ai parametri
EXPERIMENT_NAME = "xdp_nat_sr"
EXPRIMENT_FUNC_NAME = "xdp_nat_sr" # FRANCESCO
INTERFACE = "enp81s0f0np0"
TIME =10
PERF_PATH="perf"
LIBBPF_PATH="/lib64"
LOADER_STATS="../inxpect/inxpect" # FRANCESCO
SAMPLING = [1,8,32,64,128]

def init_trex():
    c = STLClient(server = '128.105.146.89') # type: ignore
    c.connect()
    # try:                                                    # load a profile
    #       profile = STLProfile.load("./nat.py")
    # except STLError as e:
    #     print("Error while loading profile")
    #     print(e.brief())
    #     return
    stream = register().get_streams(None,None)
    c.reset(ports = [0])
    # c.add_streams(profile.get_streams(), ports=[0])
    return c

def start_trex(c):
    # c.clear_stats(ports=[0])
    # num_mult = int(mult.split("pps")[0])
    # c.start(ports = [0],mult="40mpps")
    c.start_line(" -f ./nat.py -m 40mpps --port 0")

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

def exp_sampling(sampling):
    time.sleep(1.0)

    evento = "L1-dcache-load-misses"
    #evento ="llc-misses"

    # evento = "instructions"


    if not (os.path.exists(LOADER_STATS)):
            print("Compiling Kfunc loader")
            subprocess.check_output('make', cwd="../loader",shell=True)
            subprocess.check_output('chmod go+w *.o', shell=True)

    cpu=subprocess.check_output(f'sudo /opt/script_interrupts.sh {INTERFACE}',shell=True)
    cpu=cpu.decode().strip()
    print("CPU =",cpu)

    loader_stats_output = subprocess.Popen(f'sudo -E bash -c "export LD_LIBRARY_PATH={LIBBPF_PATH}; {LOADER_STATS} -n {EXPRIMENT_FUNC_NAME} -e {evento} -s {sampling} -c -C {cpu} -a"',stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, shell=True)
    #oldvalue_time
    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}" | cut -d" " -f12,14',shell=True)
    out=out.decode()
    # print(out,EXPERIMENT_NAME)
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
    # retrieve data FRANCESCO
    output, errors = loader_stats_output.communicate()
    output = output.decode("utf-8")
    print(output)
    print(errors)

    value= re.findall(r".*main: (\d*.*\d).*- (\d*.*\d).*", output)[0][0]
    value = value.split(" ")[-1]
    
    throughput = (newvalue_runcnt-oldvalue_runcnt)//TIME
    latency = (newvalue_time-oldvalue_time)//(newvalue_runcnt-oldvalue_runcnt)
    stampa = f"kfunc sample rate {sampling}: throughput = {throughput} PPS latency = {latency} ns"
    subprocess.check_output(f'echo {stampa} | tee sampling_result -a >/dev/null', shell=True)

    stampa = f"kfunc sample rate {sampling} {evento} per packet: {value.replace('.',',')}"
    subprocess.check_output(f'echo {stampa} | tee sampling_result -a >/dev/null', shell=True)



def parser():

    global EXPERIMENT_NAME
    global INTERFACE
    global TIME
    global PERF_PATH
    global LIBBPF_PATH
    global SAMPLING

    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    
    parser = argparse.ArgumentParser(description = "Performance testing")
    parser.add_argument("-t", "--time", help = "Duration of each test in seconds (default:10)", metavar="10",type=int, required = False, default = 10)
    parser.add_argument("-e", "--experiment", help = "Name of the experiment (default:xdp_nat_sr)",  metavar="xdp_nat_sr",required = False, default = "xdp_nat_sr")
    parser.add_argument("-i", "--interface", help = "Interface name (default:enp129s0f0np0)",metavar="enp129s0f0np0", required = False, default = "ens2f0np0")
    parser.add_argument("-p", "--perf", help = "Path of perf (default:/home/guest/linux/tools/perf/)",metavar="PATH", required = False, default = "perf")
    parser.add_argument("-l", "--libbpf", help = "Path of libbpf (default:/home/guest/libbpf/src/)",metavar="PATH", required = False, default = "/lib64")
    parser.add_argument("-s", "--sampling", help = "Sampling rates (default:1,8,32,128)",metavar="1,8,32,128", required = False, default = "1,2,3,4,5,6,7,8,9")

    args = parser.parse_args()

    EXPERIMENT_NAME = args.experiment
    INTERFACE = args.interface
    TIME = args.time
    PERF_PATH=args.perf
    LIBBPF_PATH=args.libbpf
    SAMPLING=args.sampling.split(",")

def main():
    try:
        parser()
        if(os.path.exists("sampling_result")):
            subprocess.check_output('rm sampling_result', shell=True)
        
        if not (os.path.exists("xdp_nat_sr.o")):
            print("Compiling BPF programs")
            subprocess.check_output('make', shell=True)
            subprocess.check_output('chmod go+w *.o', shell=True)
            subprocess.check_output('chmod go+w *.h', shell=True)
        
        trex=init_trex()


        for i in range(10):
            # 1 = 100%
            # 10 = 10%
            # 100 = 1%
            # 1000 = 0.1%
            for sampling in SAMPLING:
                subprocess.check_output("sudo sysctl kernel.bpf_stats_enabled=1", shell=True)
                subprocess.check_output('echo "'+EXPERIMENT_NAME+': sampling : '+str(sampling)+' run: '+str(i)+'" | tee -a sampling_result >/dev/null', shell=True)

                # my_env = {'LD_LIBRARY_PATH': '/lib64'}
                #nuovo path di lib64
                my_env = {'LD_LIBRARY_PATH': LIBBPF_PATH}
                command = f"./{EXPERIMENT_NAME}.o  {INTERFACE}"
                experiment = subprocess.Popen(shlex.split(command),env=my_env,shell=False)
                time.sleep(1.0)
                start_trex(trex)


                out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
                out=out.decode()
                while out == "\n":
                    print("No Packet received")
                    time.sleep(1.0)
                    out = subprocess.check_output(f'sudo bpftool prog | egrep "name {EXPERIMENT_NAME}"  | cut -d" " -f12,14',shell=True)
                    out=out.decode()

                print(f"Starting {EXPERIMENT_NAME} with sampling rate {sampling} run number {i}")
                exp_sampling(sampling)

                experiment.terminate()

                stop_trex(trex)
                time.sleep(1.0)


        
    except KeyboardInterrupt:
        print("Interrupted")
    
    finally:
        print("Terminating experiment")
        try:
            experiment.terminate()
        except NameError:
            pass



main()
