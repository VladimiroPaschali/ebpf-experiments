all: tunnel.bpf.o tunnel_kfunc.bpf.o tunnel_sr.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g -w\
 		-O2 -I ../char_dev -c $< -o $@
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