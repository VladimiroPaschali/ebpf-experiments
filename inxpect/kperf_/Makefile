obj-m += mykperf_module.o
HELPERS = mykperf_helpers

all:
	@echo "Building mykperf_module..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -lbpf
	
	@echo "Building $(OBJS)..."
	gcc -Wall -g -o $(HELPERS).o -c $(HELPERS).c	

clean:
	@echo "Cleaning mykperf_module..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod mykperf_module.ko

unload:
	sudo rmmod mykperf_module.ko

reload:
	sudo rmmod mykperf_module.ko
	sudo insmod mykperf_module.ko
