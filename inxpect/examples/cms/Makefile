TARGETS := cms

.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): 
	clang -g -O2 --target=bpf -I ../../kperf_ -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf

clean:
	rm -f $(TARGETS) *.o *.skel.h
