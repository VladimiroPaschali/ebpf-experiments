#define CMS_SIZE 1048576
// #define CMS_SIZE 8192
#define CMS_ROWS 4

#include <linux/types.h>

#pragma pack(1)
struct cms {
	__u8 count[CMS_ROWS][CMS_SIZE];
};

struct event {
	__u16 row_index;
	__u16 hash;
};
#pragma pack()
