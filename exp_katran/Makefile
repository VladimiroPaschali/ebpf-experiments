all: clean balancer.bpf.o balancer_kfunc.bpf.o
clean: 
	-rm -f *.o
	-rm -f *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g -w\
 		-O2 -c $< -o $@ -I ../inxpect/kperf_ 
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang  $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@) -L/lib64 -l:libbpf.so.1.4.0

