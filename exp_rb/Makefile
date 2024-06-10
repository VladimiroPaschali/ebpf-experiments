DROP_RB := drop_rb

.PHONY: all clean
.SILENT: all clean

all:
	@echo "Compiling drop RING BUFFER test..."
	clang \
		-target bpf \
		-g -w\
		-O2 -c $(DROP_RB).bpf.c -o $(DROP_RB).bpf.o -I ../inxpect/kperf_
	bpftool gen skeleton $(DROP_RB).bpf.o > $(DROP_RB).skel.h 
	clang -lbpf $(DROP_RB).c -o $(DROP_RB).o


clean:
	rm -f *.o *.skel.h