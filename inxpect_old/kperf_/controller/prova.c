#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "mychardev.h"
#include <stdio.h>
#include <time.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DEVICE_FILE "/dev/mychardev"

int enable(){

    int fd;
    __u64 message=0x0081f1;
    // Apri il dispositivo
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device.");
        return -1;
    }

    // Eseguire una richiesta IOCTL per ottenere il messaggio
    if (ioctl(fd, ENABLE_EVENT, &message) < 0) {
        perror("Failed to perform IOCTL GET.");
        close(fd);
        return -1;
    }

     printf("New message has been set. %x \n",message);

    close(fd);
    return 0;

}


int disable(){

    int fd;
    __u64 message=0x0081f1;
    // Apri il dispositivo
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device.");
        return -1;
    }

    // Eseguire una richiesta IOCTL per ottenere il messaggio
    if (ioctl(fd, DISABLE_EVENT, &message) < 0) {
        perror("Failed to perform IOCTL GET.");
        close(fd);
        return -1;
    }

     printf("New message has been set. %x \n",message);

    close(fd);
    return 0;

}


int main() {
    enable();

    sleep(5);
    
    disable();
    
    return 0;
}
