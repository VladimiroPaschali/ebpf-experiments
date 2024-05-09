obj-m += mykperf_module.o
HELPERS = mykperf_helpers

all:
	@echo "Building mykperf_module..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules -lbpf
	
	@echo "Building $(OBJS)..."
	gcc -o $(HELPERS).o -c $(HELPERS).c	

	@echo "Copying mykperf_module.h in /usr/local/include/mykperf"
	sudo mkdir -p /usr/local/include/mykperf
	sudo cp ./mykperf_module.h /usr/local/include/mykperf/mykperf_module.h
	gcc -g -Wall -O3 myioctl.c -o myioctl.o -lbpf

clean:
	@echo "Cleaning mykperf_module..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

	@echo "Removing mykperf_module.h from /usr/local/include/mykperf"
	sudo rm -rf /usr/local/include/mykperf

load:
	sudo insmod mykperf_module.ko

unload:
	sudo rmmod mykperf_module.ko

reload:
	sudo rmmod mykperf_module.ko
	sudo insmod mykperf_module.ko
