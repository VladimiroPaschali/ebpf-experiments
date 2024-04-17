all: tunnel.bpf.o tunnel_kfunc.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g \
 		-O2 -I /usr/local/include/mykperf -c $< -o $@
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@) -lbpf

# kern:
# 	clang -O2 -target bpf -c tunnel.bpf.c -o tunnel.bpf.o
# user:
# 	clang tunnel.c -o tunnel.o -lbpf
# all: kern user

# clean: 
# 	-rm *.o
# 	-rm *.skel.h