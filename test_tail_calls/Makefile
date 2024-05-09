TARGET := tail

.PHONY: all


all:
	clang -g -O2 -target bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o 
	bpftool gen skeleton $(TARGET).bpf.o > $(TARGET).skel.h 
	gcc -g -O2 -o $(TARGET).o $(TARGET).c -lbpf