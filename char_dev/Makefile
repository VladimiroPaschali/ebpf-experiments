obj-m += mychardev.o
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
	sudo rmmod mychardev
	sudo insmod mychardev.ko
