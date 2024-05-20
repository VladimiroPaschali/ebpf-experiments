# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := nat
USER_TARGETS := nat_user

LLC ?= llc
CLANG ?= clang
CC := gcc

KHEADER=../inxpect/kperf_
#include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o

all:
	clang -O2 -g -w -target bpf -c xdp_nat.c -o xdp_nat.o 
	bpftool gen skeleton xdp_nat.o > xdp_nat.skel.h 
	clang -O2 -g -Wall -o xdp_nat_user.o xdp_nat_user.c -I $(KHEADER) -lbpf 
	clang -O2 -g -w -target bpf -I $(KHEADER) -c xdp_nat_kfunc.c -o xdp_nat_kfunc.o