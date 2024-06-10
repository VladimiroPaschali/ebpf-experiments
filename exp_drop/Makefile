# Add colors to output
# https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux
# https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux

# Colors
RED = \033[0;31m
GREEN = \033[0;32m
NC = \033[0m

# Variables
BPF_SRCS = $(wildcard *.bpf.c)
BPF_OBJS = $(patsubst %.c,%.o,$(BPF_SRCS))
BPF_SKEL = $(patsubst %.bpf.o,%.skel.h,$(BPF_OBJS))
BPF_PROGS = $(patsubst %.bpf.o,%,$(BPF_OBJS))

.PHONY: all clean

all: $(BPF_OBJS) $(BPF_SKEL) $(BPF_PROGS)
	@echo "${GREEN}BPF_OBJS: $(BPF_OBJS)${NC}"
	@echo "${GREEN}BPF_SKEL: $(BPF_SKEL)${NC}"
	@echo "${GREEN}BPF_PROGS: $(BPF_PROGS)${NC}"
	@echo "Done"

$(BPF_OBJS): %.o: %.c
	clang \
		-target bpf \
		-g -w \
		-O2 -I ../inxpect/kperf_ -c $< -o $@ -l:libbpf.1.4.0.so
	@echo "Compiled $<"

$(BPF_SKEL): %.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@
	@echo "Generated $@"

$(BPF_PROGS): %: %.o
	clang $(patsubst %.o,%.c,$<)  -o $@ -lbpf

clean:
	@echo "${RED}Cleaning${NC}"
	-rm -f $(BPF_OBJS) $(BPF_SKEL) $(BPF_PROGS)
