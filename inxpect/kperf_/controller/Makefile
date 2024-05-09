obj-m += mychardev.o
CPU := $(shell sudo ../../script_interrupts.sh enp81s0f0np0)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -g -Wall -O3 myioctl.c -o myioctl.o -lbpf
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm myioctl.o
	
load:
	sudo insmod mychardev.ko
unload:
	sudo rmmod mychardev
reload:
	@echo "Reloading the module"
	sudo rmmod mychardev
	sudo insmod mychardev.ko
	@echo "Setting CPU affinity"
	sudo ./myioctl.o $(CPU)
