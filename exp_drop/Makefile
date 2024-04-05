all: drop.bpf.o drop_map.bpf.o drop_kfunc.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
	-rm drop
	-rm drop_map
	-rm drop_kfunc
%.o: %.c 
	clang \
 		-target bpf \
 		-g \
 		-O2 -c $< -o $@
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%,$@)

