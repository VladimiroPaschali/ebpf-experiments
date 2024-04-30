#ifndef _MYCHARDEV_H_
#define _MYCHARDEV_H_

#include <asm/types.h>

#define DEVICE_FILE "/dev/mychardev"
#define MAGIC 'e'

#define ENABLE_EVENT _IOWR(MAGIC, 1, __u64)
#define DISABLE_EVENT _IOW(MAGIC, 2, __u64)
#define CHANGE_EVENT _IOW(MAGIC, 3, __u64)
#define SET_CPU _IOW(MAGIC, 4, int)

#endif // _MYCHARDEV_H_