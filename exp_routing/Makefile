all: lpmtrie.bpf.o lpmtrie_kfunc.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g \
 		-O2 -c $< -o $@ -I ../char_dev
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@)

