all: clean fw.bpf.o fw_kfunc.bpf.o fw_sr.bpf.o
	
clean:
	-rm -f *.o
	-rm -f *.skel.h


%.o: %.c
	clang -target bpf -O2 -I ../inxpect/kperf_ -g -c $< -o $@ 
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@)

