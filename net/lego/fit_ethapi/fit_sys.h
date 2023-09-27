#ifndef _COMMON_H
#define _COMMON_H

#ifdef _LEGO_LINUX_MODULE_
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/completion.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/jiffies.h>
#include <linux/printk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/list.h>
#include <linux/string.h>
#else
#include <lego/types.h>
#include <lego/errno.h>
#include <lego/completion.h>
#include <lego/bitops.h>
#include <lego/bug.h>
#include <lego/spinlock.h>
#include <lego/semaphore.h>
#include <lego/jiffies.h>
#include <lego/printk.h>
#include <lego/completion.h>
#include <lego/delay.h>
#include <lego/sched.h>
#include <lego/kthread.h>
#include <lego/types.h>
#include <lego/bitmap.h>
#include <lego/list.h>
#include <lego/string.h>
#endif /* _LEGO_LINUX_MODULE_ */

/*
 * There is a conflict when compiled as a 
 * kernel module.
 */
#ifdef TIME_WAIT
#undef TIME_WAIT
#endif

#endif /* _COMMON_H */