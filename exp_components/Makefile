MACRO := macro
PARSE := drop
KFUNC := kfunc
FENTRY_READ := fentry_read
FENTRY_UPDATE_MAP := fentry_update
KHEADER := ../inxpect/kperf_

.PHONY: all clean
.SILENT: drop kfunc macro fentry_perf_read fentry_update_map

all: drop kfunc fentry_perf_read fentry_update_map #macro

drop:
	@echo "Compiling drop test..."
	clang \
		-target bpf \
		-g -w\
		-O2 -c $(PARSE).bpf.c -o $(PARSE).bpf.o -I $(KHEADER)
	bpftool gen skeleton $(PARSE).bpf.o > $(PARSE).skel.h 
	clang -lbpf $(PARSE).c -o $(PARSE).o

kfunc:
	@echo "Compiling kfunc test..."
	clang \
		-target bpf \
		-g -w\
		-O2 -c $(KFUNC).bpf.c -o $(KFUNC).bpf.o -I $(KHEADER)
	bpftool gen skeleton $(KFUNC).bpf.o > $(KFUNC).skel.h 
	clang -lbpf $(KFUNC).c -o  $(KFUNC).o
	
macro:
	@echo "Compiling macro test..."
	clang \
		-target bpf \
		-g -w\
		-O2 -c $(MACRO).bpf.c -o $(MACRO).bpf.o -I $(KHEADER)
	bpftool gen skeleton $(MACRO).bpf.o > $(MACRO).skel.h 
	clang -lbpf $(MACRO).c -o $(MACRO).o

fentry_perf_read:
	@echo "Compiling fentry perf event test..."
	clang \
		-target bpf \
		-g -w\
		-O2 -c $(FENTRY_READ).bpf.c -o $(FENTRY_READ).bpf.o -I $(KHEADER)
	bpftool gen skeleton $(FENTRY_READ).bpf.o > $(FENTRY_READ).skel.h 
	clang -lbpf $(FENTRY_READ).c -o $(FENTRY_READ).o

fentry_update_map:
	@echo "Compiling fentry update map test..."
	clang \
		-target bpf \
		-g -w\
		-O2 -c $(FENTRY_UPDATE_MAP).bpf.c -o $(FENTRY_UPDATE_MAP).bpf.o -I $(KHEADER)
	bpftool gen skeleton $(FENTRY_UPDATE_MAP).bpf.o > $(FENTRY_UPDATE_MAP).skel.h 
	clang -lbpf $(FENTRY_UPDATE_MAP).c -o $(FENTRY_UPDATE_MAP).o

clean: 
	-rm -f *.o
	-rm -f *.skel.h
