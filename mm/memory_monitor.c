#include <linux/poll.h>
#include <linux/eventpoll.h>
#include <linux/wait.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>

#include "internal.h"

static atomic_t kswapd_monitor = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kswapd_poll_wait);

void kswapd_monitor_wake_up_queue(void)
{
    atomic_inc(&kswapd_monitor);
    wake_up_interruptible(&kswapd_poll_wait);
}

static __poll_t kswapd_monitor_poll(struct file *file, struct poll_table_struct *wait)
{
    struct seq_file *seq = file->private_data;

    poll_wait(file, &kswapd_poll_wait, wait);

    if (seq->poll_event != atomic_read(&kswapd_monitor)) {
        seq->poll_event = atomic_read(&kswapd_monitor);
        return EPOLLPRI;
    }

    return EPOLLIN | EPOLLRDNORM;
}

static int kswapd_monitor_show(struct seq_file *m, void *v)
{
    seq_printf(m, "kswapd_monitor_show kswapd_monitor %d\n", atomic_read(&kswapd_monitor));
    return 0;
}

static int kswapd_monitor_open(struct inode *inode, struct file *file)
{
    return single_open(file, kswapd_monitor_show, NULL);
}

static const struct proc_ops proc_kswapd_monitor_operations = {
    .proc_open = kswapd_monitor_open,
    .proc_poll = kswapd_monitor_poll,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init memory_monitor_init(void)
{
	proc_create("kswapd_monitor", 0, NULL, &proc_kswapd_monitor_operations);
	return 0;
}

__initcall(memory_monitor_init)
