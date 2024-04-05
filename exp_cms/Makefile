all: cms.bpf.o cms_kfunc.bpf.o ring_cms.bpf.o ring_cms_kfunc.bpf.o
clean: 
	-rm *.o
	-rm *.skel.h
	-rm cms_kfunc
	-rm cms
	-rm ring_cms_kfunc
	-rm ring_cms
%.o: %.c 
	clang \
 		-target bpf \
 		-g \
 		-O2 -c $< -o $@
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%,$@)

