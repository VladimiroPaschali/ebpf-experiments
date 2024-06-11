#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "mykperf_ioctl.h"
#include <stdlib.h>
#include <unistd.h>


int main(int argc, char** argv){
	
	if (argc < 2){
		fprintf(stderr, "need one arg\n");
		return -1;
	}

	int curr_cpu=atoi(argv[1]);
	if (curr_cpu < 0){
		fprintf(stderr, "cpu must be greater than zero\n");
		return -1;
	}

    int fd = open(DEVICE_FILE, O_RDWR);
    if (fd <0){
		perror("Failed to open the device.");
		return -1;
	}

	if (ioctl(fd, SET_CPU,&curr_cpu )){
		perror("Failed to send curr_cpu ");
		close(fd);
		return -1;
	}

	fprintf(stdout, "CPU: %d set\n",curr_cpu);
	close(fd);
	return 0;
}
