#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <asm/msr.h>
#include "mychardev.h"
#include <linux/btf.h>
#include <linux/btf_ids.h>

#define MAX_DEV 1

#define CAP_EVENT 0x530000
#define FIRST_MSR_EV_SELECT_REG 0x186
#define MAX_MSR_PROG_REG 7
#define FIRST_MSR_PROG_REG 0xC1

struct enabled_events_list
{
    struct list_head list;
    __u64 reg;
    __u64 event;
};

struct data
{
    __u64 event;
    __u64 reg;
};

__bpf_kfunc __u64 bpf_mykperf_rdmsr(__u64 counter);

static int mychardev_open(struct inode *inode, struct file *file);
static int mychardev_release(struct inode *inode, struct file *file);
static long mychardev_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static ssize_t mychardev_read(struct file *file, char __user *buf, size_t count, loff_t *offset);
static ssize_t mychardev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);
static __u64 enable_event(__u64 event);
static int disable_event(__u64 reg, __u64 event);
static void __add_event(__u64 reg, __u64 event);

struct enabled_events_list *node;

static const struct file_operations mychardev_fops = {.owner = THIS_MODULE,
                                                      .open = mychardev_open,
                                                      .release = mychardev_release,
                                                      .unlocked_ioctl = mychardev_ioctl,
                                                      .read = mychardev_read,
                                                      .write = mychardev_write};

struct mychar_device_data
{
    struct cdev cdev;
};

static int dev_major = 0;
static struct class *mychardev_class = NULL;
static struct mychar_device_data mychardev_data[1];

static int curr_cpu;

/*Declare and init the head node of the linked list*/
LIST_HEAD(head);

static void __add_event(__u64 reg, __u64 event)
{
    struct enabled_events_list *node = kmalloc(sizeof(struct enabled_events_list), GFP_KERNEL);
    node->reg = reg;
    node->event = event;

    list_add_tail(&node->list, &head);
    return;
}

static int mychardev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

#define MY_RDMSR(reg, l, h) asm volatile("rdmsr" : "=a"(l), "=d"(h) : "c"(reg))

__bpf_kfunc __u64 bpf_mykperf_rdmsr(__u64 counter)
{
    //__u32 h, l;
    __u64 ret = 0;
    // MY_RDMSR(0x309, l, h);
    asm volatile("mfence" ::: "memory");

    rdpmcl(((0 << 30) + counter), ret);
    // rdmsrl(0x309, ret);
    //  fence

    // asm volatile("mfence" ::: "memory");

    /* int err = rdmsrl_safe_on_cpu(14, 0x309, &ret);
    if (err)
    {
        printk("Error reading MSR: %d\n", err);
        return 0;
    }
     */
    return ret;
}

BTF_SET8_START(bpf_task_set)
BTF_ID_FLAGS(func, bpf_mykperf_rdmsr)
BTF_SET8_END(bpf_task_set)

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_task_set,
};

static int __init mychardev_init(void)
{
    register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_task_kfunc_set);

    int err, i;
    dev_t dev;

    err = alloc_chrdev_region(&dev, 0, MAX_DEV, "mychardev");

    dev_major = MAJOR(dev);

    mychardev_class = class_create("mychardev");
    // mychardev_class->dev_uevent = mychardev_uevent;

    for (i = 0; i < MAX_DEV; i++)
    {
        cdev_init(&mychardev_data[i].cdev, &mychardev_fops);
        mychardev_data[i].cdev.owner = THIS_MODULE;

        cdev_add(&mychardev_data[i].cdev, MKDEV(dev_major, i), 1);

        device_create(mychardev_class, NULL, MKDEV(dev_major, i), NULL, "mychardev", i);
    }

    return 0;
}

static void __exit mychardev_exit(void)
{

    // free all the nodes in the list
    struct enabled_events_list *temp, *next;
    list_for_each_entry_safe(temp, next, &head, list)
    {
        list_del(&temp->list);
        kfree(temp);
    }

    int i;

    for (i = 0; i < MAX_DEV; i++)
    {
        device_destroy(mychardev_class, MKDEV(dev_major, i));
    }

    class_unregister(mychardev_class);
    class_destroy(mychardev_class);

    unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

static int mychardev_open(struct inode *inode, struct file *file)
{
    printk("MYCHARDEV: Device open\n");
    return 0;
}

static int mychardev_release(struct inode *inode, struct file *file)
{
    printk("MYCHARDEV: Device close\n");
    return 0;
}

static long mychardev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int err = 0;
    __u64 r;
    __u64 event;
    switch (cmd)
    {
    case ENABLE_EVENT:
        if (copy_from_user(&event, (__u64 *)arg, sizeof(event)))
        {
            printk("Error copying data from user\n");
            return -EFAULT;
        }

        r = enable_event(event);
        if (r < 0)
        {
            printk("Error enabling event\n");
            return -1;
        }

        err = copy_to_user((uint32_t *)arg, &r, sizeof(r));
        if (err)
        {
            printk("Error copying data to user\n");
            return -EFAULT;
        }
        break;

    case DISABLE_EVENT:
        struct data msg = {0};
        if (copy_from_user(&msg, (__u64 *)arg, sizeof(struct data)))
        {
            printk("Error copying data from user\n");
            return -EFAULT;
        }

        err = disable_event(msg.reg, msg.event);
        if (err)
        {
            printk("Error disabling event\n");
            return -1;
        }
        break;
    case CHANGE_EVENT:
        struct data msg = {0};
        if (copy_from_user(&msg, (__u64 *)arg, sizeof(struct data)))
        {
            printk("Error copying data from user\n");
            return -EFAULT;
        }

        err = change_event(msg.reg, msg.event);
        if (err < 0)
        {
            printk("Error enabling event\n");
            err = copy_to_user((uint32_t *)arg, NULL, sizeof(struct data));
            if (err)
            {
                return -EFAULT;
            }
            return -1;
        }

        err = copy_to_user((uint32_t *)arg, &msg, sizeof(struct data));
        if (err)
        {
            printk("Error copying data to user\n");
            return -EFAULT;
        }
        break;
    case SET_CPU:
        if (copy_from_user(&curr_cpu, (int *)arg, sizeof(curr_cpu)))
        {
            printk("Error copying data from user\n");
            return -EFAULT;
        }
        printk("MYCHARDEV: Setting CPU: %d\n", curr_cpu);
        break;
    }
    printk("MYCHARDEV: Device ioctl\n");

    return err;
}

static ssize_t mychardev_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    uint8_t *data = "Hello from the kernel world!\n";
    size_t datalen = strlen(data);

    printk("Reading device: %d\n", MINOR(file->f_path.dentry->d_inode->i_rdev));

    if (count > datalen)
    {
        count = datalen;
    }

    if (copy_to_user(buf, data, count))
    {
        return -EFAULT;
    }

    return count;
}

static ssize_t mychardev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
    size_t maxdatalen = 30, ncopied;
    uint8_t databuf[maxdatalen];

    printk("Writing device: %d\n", MINOR(file->f_path.dentry->d_inode->i_rdev));

    if (count < maxdatalen)
    {
        maxdatalen = count;
    }

    ncopied = copy_from_user(databuf, buf, maxdatalen);

    if (ncopied == 0)
    {
        printk("Copied %zd bytes from the user\n", maxdatalen);
    }
    else
    {
        printk("Could't copy %zd bytes from the user\n", ncopied);
    }

    databuf[maxdatalen] = 0;

    printk("Data from the user: %s\n", databuf);

    return count;
}

// return zero mean error
static __u64 enable_event(__u64 event)
{
    __u64 r;
    uint32_t l, h;
    int err;
    for (r = FIRST_MSR_EV_SELECT_REG; r < (FIRST_MSR_EV_SELECT_REG + MAX_MSR_PROG_REG); r++)
    {
        err = rdmsr_safe_on_cpu(curr_cpu, r, &l, &h);
        if (err)
        {
            printk("Error reading MSR: %d\n", err);
            return -1;
        }

        // check if l and h are zero
        if ((l | h) == 0)
        {
            break;
        }
    }

    event = CAP_EVENT | event; // add CAP_EVENT to event
    l = event & 0xFFFFFFFF;
    h = event >> 32;
    err = wrmsr_on_cpu(curr_cpu, r, l, h);
    if (err)
    {
        printk("Error writing MSR: %d\n", err);
        return -1;
    }

    __add_event(r, event);

    // wich register was used to store PMC value
    __u64 output_reg = r - FIRST_MSR_EV_SELECT_REG;
    printk("MYCHARDEV: Enabling event %xon register: %x\n", event, output_reg);

    return output_reg;
}

static int disable_event(__u64 reg, __u64 event)
{
    event = CAP_EVENT | event;
    int err;
    struct enabled_events_list *temp, *next;
    list_for_each_entry(temp, &head, list)
    {
        if (temp->event == event && temp->reg == reg + FIRST_MSR_EV_SELECT_REG)
        {
            err = wrmsr_on_cpu(curr_cpu, temp->reg, 0, 0);
            if (err)
            {
                printk("Error writing MSR: %d\n", err);
                return -1;
            }
            printk("MYCHARDEV: Disabling event %x on register: %x\n", temp->event, temp->reg);
            list_del(&temp->list);
            kfree(temp);
            return 0;
        }
    }
    return 0;
}

static int change_event(__u64 reg, __u64 event)
{
    event = CAP_EVENT | event;
    int err;
    struct enabled_events_list *temp, *next;
    list_for_each_entry(temp, &head, list)
    {
        if (temp->reg == reg + FIRST_MSR_EV_SELECT_REG)
        {
            err = wrmsrl_on_cpu(curr_cpu, temp->reg, event);
            if (err)
            {
                printk("Error writing MSR: %d\n", err);
                return -1;
            }
            printk("MYCHARDEV: Changing event %x on register: %x\n", temp->event, temp->reg);
            return 0;
        }
    }
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("name");

module_init(mychardev_init);
module_exit(mychardev_exit);
