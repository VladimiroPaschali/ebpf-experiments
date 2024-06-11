#ifndef __MYKPERF_IOCTL_H_
#define __MYKPERF_IOCTL_H_

#define DEVICE_FILE "/dev/kinxpect"
#define MAGIC 'e'

#define ENABLE_EVENT _IOWR(MAGIC, 1, __u64)
#define DISABLE_EVENT _IOW(MAGIC, 2, __u64)
#define SET_CPU _IOW(MAGIC, 3, int)

#endif // __MYKPERF_IOCTL_H_