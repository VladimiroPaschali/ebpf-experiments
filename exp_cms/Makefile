all: clean cms.bpf.o cms_kfunc.bpf.o cms_sr.bpf.o #ring_cms.bpf.o ring_cms_kfunc.bpf.o
clean: 
	-rm -f *.o
	-rm -f *.skel.h
%.o: %.c 
	clang \
 		-target bpf \
 		-g -w\
 		-O2 -c $< -o $@ -I ../inxpect/kperf_
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@)

