#define CMS_SIZE 16384
// #define CMS_SIZE 16
#define CMS_ROWS 4

#include <linux/types.h>

#pragma pack(1)
struct cms
{
    __u8 count[CMS_ROWS][CMS_SIZE];
};

struct event
{
    __u16 row_index;
    __u16 hash;
};
#pragma pack()
