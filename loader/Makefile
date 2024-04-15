TARGET := loader-stats
PROFILER := ./profiler/profiler
KHEADER:= /usr/local/include/mykperf

.PHONY: all build clean
.SILENT: all build clean

all: build

build:
	@echo "Compiling $(PROFILER)"
	clang -g -O2 -target bpf -Wall -c $(PROFILER).bpf.c -o $(PROFILER).o

	@echo "Generating profiler skeleton"
	bpftool gen skeleton $(PROFILER).o > $(PROFILER).skel.h

	@echo "Compiling $(TARGET)"
	gcc -g -Wall -O2 -I$(KHEADER) $(TARGET).c -o $(TARGET).o -lbpf

install:
	@echo "Installing $(TARGET)"
	install -m 755 $(TARGET).o /usr/bin/$(TARGET)

clean:
	rm -f $(TARGET).o