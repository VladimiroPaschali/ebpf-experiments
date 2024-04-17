TARGET := loader-stats
TARGET_L := light-stats
PROFILER := ./profiler/profiler
KHEADER:= /usr/local/include/mykperf

.PHONY: all clean
.SILENT: all clean

all:
	@echo "Compiling $(PROFILER)"
	clang -g -O2 -target bpf -Wall -c $(PROFILER).bpf.c -o $(PROFILER).o

	@echo "Generating profiler skeleton"
	bpftool gen skeleton $(PROFILER).o > $(PROFILER).skel.h

	@echo "Compiling $(TARGET)"
	gcc -g -Wall -O2 -I$(KHEADER) $(TARGET).c -o $(TARGET).o -lbpf

	@echo "Compiling $(TARGET_L)"
	gcc -g -Wall -O2 -I$(KHEADER) $(TARGET_L).c -o $(TARGET_L).o -lbpf

install:
	@echo "Installing $(TARGET)"
	install -m 755 $(TARGET).o /usr/bin/$(TARGET)

	@echo "Installing $(TARGET_L)"
	install -m 755 $(TARGET_L).o /usr/bin/$(TARGET_L)

clean:
	rm -f $(TARGET).o
	rm -f $(TARGET_L).o