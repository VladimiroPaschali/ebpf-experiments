from trex_stl_lib.api import *
import argparse

# Example of STLVmFlowVarRepetableRandom instruction. 
# in this case it generate repetable random numbers with limit/seed

class STLS1(object):

    #def __init__ (self):
        #self.fsize  = 54;

    def create_stream (self, direction, cache_size):
        # Create base packet and pad it to size
        #size = self.fsize; # HW will add 4 bytes ethernet FCS
        src_ip = '16.0.0.1'
        dst_ip = '48.0.0.1'
        if direction:
            src_ip, dst_ip = dst_ip, src_ip

        base_pkt = Ether()/IP(src=src_ip,dst=dst_ip)/UDP(dport=12,sport=1025)

        #pad = max(0, size - len(base_pkt)) * 'x'
                             
        vm =STLScVmRaw([

            # #repetable random non funziona bene
            # STLVmFlowVarRepeatableRandom("ip_src",min_value="0.0.0.0",max_value="255.255.255.255",size=4,limit=7000, seed=0x1234),
            # STLVmFlowVarRepeatableRandom("ip_dst",min_value="0.0.0.0",max_value="255.255.255.255",size=4,limit=7000, seed=0x1235),
            # STLVmFlowVarRepeatableRandom("port_src",min_value=1,max_value=1000,size=2,limit=7000, seed=0x1236),
            # STLVmFlowVarRepeatableRandom("port_dst",min_value=1,max_value=1000,size=2,limit=7000, seed=0x1237),
            # STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src" ), # write ip to packet IP.src
            # STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= "IP.dst" ), # write ip to packet IP.dst
            # STLVmWrFlowVar(fv_name="port_src", pkt_offset= "UDP.sport" ), # write ip to packet UDP.sport
            # STLVmWrFlowVar(fv_name="port_dst", pkt_offset= "UDP.dport" ), # write ip to packet UDP.sport

            #funziona meglio
            STLVmFlowVar(name="ip_src", min_value="0.0.0.0", max_value="255.255.255.255", size=4, op="random"), # write ip to packet IP.src
            STLVmFlowVar(name="ip_dst", min_value="0.0.0.0", max_value="255.255.255.255", size=4, op="random" ), # write ip to packet IP.dst
            STLVmFlowVar(name="src_port", min_value=1025, max_value=65000, size=2, op="random"),
            STLVmFlowVar(name="dst_port", min_value=1025, max_value=65000, size=2, op="random"),
            STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src" ), # write ip to packet IP.src
            STLVmWrFlowVar(fv_name="ip_dst", pkt_offset= "IP.dst" ), # write ip to packet IP.dst
            STLVmWrFlowVar(fv_name="src_port", pkt_offset= "UDP.sport" ), # write ip to packet UDP.sport
            STLVmWrFlowVar(fv_name="dst_port", pkt_offset= "UDP.dport" ), # write ip to packet UDP.sport


            STLVmFixIpv4(offset = "IP")                                # fix checksum
        ],cache_size = cache_size # the cache size
        );




        #pkt = STLPktBuilder(pkt = base_pkt/pad,vm = vm)
        pkt = STLPktBuilder(pkt = base_pkt,vm = vm)
        stream = STLStream(packet = pkt,mode = STLTXCont())
        
        return stream


    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--cache_size',
                            type=int,
                            default=7000,
                            help="The cache size.")
        args = parser.parse_args(tunables)
        # create 1 stream 
        return [self.create_stream(direction, args.cache_size)]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
