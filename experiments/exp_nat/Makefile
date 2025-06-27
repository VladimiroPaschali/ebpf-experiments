# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

TARGET := xdp_nat

KHEADER=../inxpect/kperf_
#include $(COMMON_DIR)/common.mk

.PHONY: all clean


all:
	clang -O2 -g -w -target bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o 
	# clang -O2 -g -w -target bpf -I $(KHEADER) -c $(TARGET)_kfunc.bpf.c -o $(TARGET)_kfunc.bpf.o
	# clang -O2 -g -w -target bpf -I $(KHEADER) -c $(TARGET)_sr.bpf.c -o $(TARGET)_sr.bpf.o
	
	bpftool gen skeleton $(TARGET).bpf.o > $(TARGET).skel.h 
	# bpftool gen skeleton $(TARGET)_kfunc.bpf.o > $(TARGET)_kfunc.skel.h
	# bpftool gen skeleton $(TARGET)_sr.bpf.o > $(TARGET)_sr.skel.h
	
	# clang -O2 -g -Wall -o $(TARGET)_kfunc.o $(TARGET)_kfunc.c -I $(KHEADER) -lbpf 
	clang -O2 -g -Wall -o $(TARGET).o $(TARGET).c -I $(KHEADER) -lbpf 
	# clang -O2 -g -Wall -o $(TARGET)_sr.o $(TARGET)_sr.c -I $(KHEADER) -lbpf

clean:
	rm -f *.o
	rm -f *.skel.h