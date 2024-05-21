all: clean fw.bpf.o
	
clean:
	-rm *.o
	-rm *.skel.h
%.o: %.c
	clang -target bpf -O2 -g -c $< -o $@ 
	bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@) 
	clang -lbpf $(patsubst %.bpf.o,%.c,$@) -o  $(patsubst %.bpf.o,%.o,$@)
