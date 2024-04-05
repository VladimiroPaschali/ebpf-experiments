all: cms.bpf.o cms_kfunc.bpf.o ring_cms.bpf.o ring_cms_kfunc.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g \
 		-O2 -c $< -o $@ -I /usr/local/include/mykperf
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@)

