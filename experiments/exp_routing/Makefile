all: lpmtrie.bpf.o lpmtrie_kfunc.bpf.o lpmtrie_sr.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g -w\
 		-O2 -c $< -o $@ -I ../../inxpect/kperf_
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@)

