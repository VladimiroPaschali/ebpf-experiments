all: parsing.bpf.o parsing_kfunc.bpf.o
clean: 
	-rm -f *.o
	-rm -f *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g -w\
 		-O2 -I ../inxpect/kperf_ -c $< -o $@ 
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@) -lbpf

