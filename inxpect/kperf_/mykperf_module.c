#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include <linux/cpumask.h>
#include "mykperf_module.h"
#include "mykperf_ioctl.h"

static __u64 __enable_event(__u64 event, int cpus);
static int __disable_event(__u64 reg, __u64 event, int cpu);
static void __add_event(__u64 reg, __u64 event, int cpu);

// -------------------- bpf prototypes ------------------------
__bpf_kfunc __u64 bpf_mykperf__rdpmc(__u8 counter);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CiZ");
MODULE_DESCRIPTION("A Dummy Kernel Module");

#define MAX_DEV 1

#define CAP_EVENT 0x530000
#define FIRST_MSR_EV_SELECT_REG 0x186
#define MAX_MSR_PROG_REG 7
#define FIRST_MSR_PROG_REG 0xC1

dev_t dev_num;
static struct cdev mykperf_cdev;
static struct class *mykperf_class = NULL;

__bpf_kfunc void bpf_mykperf__fence(void)
{
    asm volatile("lfence" : : : "memory");
}

__bpf_kfunc __u64 bpf_mykperf__rdpmc(__u8 counter)
{
    __u64 ret = 0;
    asm volatile("lfence" : : : "memory");
    rdpmcl(counter, ret);
    asm volatile("lfence" : : : "memory");
    return ret;
}

BTF_SET8_START(bpf_task_set)
BTF_ID_FLAGS(func, bpf_mykperf__rdpmc)
BTF_ID_FLAGS(func, bpf_mykperf__fence)
BTF_SET8_END(bpf_task_set)

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_task_set,
};

struct message
{
    __u64 event;
    __u64 reg;
    int cpu;
};

static long mykperf_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int err = 0;
    struct message msg = {0};
    switch (cmd)
    {
    case ENABLE_EVENT:
        int r = -1;
        if (copy_from_user(&msg, (__u64 *)arg, sizeof(struct message)))
        {
            printk("Error copying data from user\n");
            return -EFAULT;
        }

        r = __enable_event(msg.event, msg.cpu);
        if (r < 0)
        {
            printk("Error enabling event\n");
            return -1;
        }

        msg.reg = r;

        err = copy_to_user((uint32_t *)arg, &msg, sizeof(struct message));
        if (err)
        {
            printk("Error copying data to user\n");
            return -EFAULT;
        }
        break;
    case DISABLE_EVENT:
        if (copy_from_user(&msg, (__u64 *)arg, sizeof(struct message)))
        {
            printk("Error copying data from user\n");
            return -EFAULT;
        }

        err = __disable_event(msg.reg, msg.event, msg.cpu);
        if (err)
        {
            printk("Error disabling event\n");
            return -1;
        }
        break;
    }
    return err;
}

static const struct file_operations mykperf_fops = {.owner = THIS_MODULE, .unlocked_ioctl = mykperf_ioctl};

static int __init mykperf_module_init(void)
{
    register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_task_kfunc_set);
    int ret = 0;
    //  ---- INIT CHAR DEV FOR IOCTL ----
    ret = alloc_chrdev_region(&dev_num, 0, 1, "inxpect-dev");
    if (ret < 0)
    {
        printk(KERN_ERR "failed to alloc chrdev region\n");
        return ret;
    }

    mykperf_class = class_create("kinxpect");
    if (IS_ERR(mykperf_class))
    {
        printk(KERN_ERR "failed to create class\n");
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(mykperf_class);
    }

    cdev_init(&mykperf_cdev, &mykperf_fops);
    mykperf_cdev.owner = THIS_MODULE;
    ret = cdev_add(&mykperf_cdev, dev_num, 1);
    if (ret < 0)
    {
        printk(KERN_ERR "failed to add cdev\n");
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    device_create(mykperf_class, NULL, dev_num, NULL, "kinxpect", MINOR(dev_num));
    // --------------------------------------------------

    pr_info("kfunc registerd with success\n");
    return 0;
}

struct enabled_events_list
{
    struct list_head list;
    __u64 reg;
    __u64 event;
    int cpu;
};

/*Declare and init the head node of the linked list*/
LIST_HEAD(head);

static void __add_event(__u64 reg, __u64 event, int cpu)
{
    struct enabled_events_list *node = kmalloc(sizeof(struct enabled_events_list), GFP_KERNEL);
    node->reg = reg;
    node->event = event;
    node->cpu = cpu;

    list_add_tail(&node->list, &head);
    return;
}

// return zero mean error
static __u64 __enable_event(__u64 event, int cpu)
{
    __u32 r;
    uint32_t l, h;
    int err;
    int _cpu = 0;

    // TODO : do this check on our event, and overwrite other events. This permit us to find the right register and having the same register for all cpus.
    //  find a free register
    for (r = FIRST_MSR_EV_SELECT_REG; r < (FIRST_MSR_EV_SELECT_REG + MAX_MSR_PROG_REG); r++)
    {
        if (cpu == -1)
        {
            for_each_online_cpu(_cpu)
            {
                err = rdmsr_safe_on_cpu(_cpu, r, &l, &h);
                if (err)
                {
                    pr_err("Error reading MSR %x register on cpu %d: \n", r, _cpu, err);
                    return -1;
                }

                // check if l and h are zero
                if ((l | h) == 0)
                {
                    break;
                }
            }
            // check if l and h are zero
            if ((l | h) == 0)
            {
                break;
            }
        }
        else
        {
            err = rdmsr_safe_on_cpu(cpu, r, &l, &h);
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
    }

    event = CAP_EVENT | event; // add CAP_EVENT to event
    l = event & 0xFFFFFFFF;
    h = event >> 32;
    if (cpu == -1)
    {
        for_each_online_cpu(_cpu)
        {
            err = wrmsr_safe_on_cpu(_cpu, r, l, h);
            if (err)
            {
                printk("Error writing MSR: %d on cpu: %d\n", err, _cpu);
                return -1;
            }
        }
    }
    else
    {
        err = wrmsr_safe_on_cpu(cpu, r, l, h);
        if (err)
        {
            printk("Error writing MSR: %d\n", err);
            return -1;
        }
    }

    __add_event(r, event, cpu);

    // index register used to store PMC value
    __u64 output_reg = r - FIRST_MSR_EV_SELECT_REG;
    return output_reg;
}

static int __disable_event(__u64 reg, __u64 event, int cpu)
{
    event = CAP_EVENT | event;
    int err;
    struct enabled_events_list *temp;
    list_for_each_entry(temp, &head, list)
    {
        if (temp->event == event && temp->reg == reg + FIRST_MSR_EV_SELECT_REG && temp->cpu == cpu)
        {
            if (cpu == -1)
            {
                for_each_online_cpu(cpu)
                {
                    err = wrmsr_safe_on_cpu(cpu, temp->reg, 0, 0);
                    if (err)
                    {
                        printk("Error writing MSR: %d\n", err);
                        return -1;
                    }
                }
            }
            else
            {
                err = wrmsr_safe_on_cpu(cpu, temp->reg, 0, 0);
                if (err)
                {
                    printk("Error writing MSR: %d\n", err);
                    return -1;
                }
            }
            list_del(&temp->list);
            kfree(temp);
            return 0;
        }
    }
    return 0;
}

static void __exit mykperf_module_exit(void)
{
    // free all the nodes in the list
    struct enabled_events_list *temp, *next;
    list_for_each_entry_safe(temp, next, &head, list)
    {
        list_del(&temp->list);
        kfree(temp);
    }

    // ---- CLEANUP CHARDEV ----
    device_destroy(mykperf_class, dev_num);

    class_unregister(mykperf_class);
    class_destroy(mykperf_class);

    unregister_chrdev_region(dev_num, 1);
    cdev_del(&mykperf_cdev);
    // --------------------------

    pr_info("kernel module detached\n");
}

module_init(mykperf_module_init);
module_exit(mykperf_module_exit);
