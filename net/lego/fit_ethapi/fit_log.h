#ifndef _INCLUDE_FIT_LOG_H_
#define _INCLUDE_FIT_LOG_H_

#ifdef _LEGO_LINUX_MODULE_
#include <linux/printk.h>
#include <linux/bug.h>
#else
#include <lego/printk.h>
#include <lego/bug.h>
#endif /* _LEGO_LINUX_MODULE_ */

#define FIT_LOG_LEVEL   3

#define _FIT_LOG_PREFIX "FIT: "
#define fit_log(level, fmt, ...) do { \
    if (level <= FIT_LOG_LEVEL) \
        printk(_FIT_LOG_PREFIX fmt, ##__VA_ARGS__); \
    } while (0)

#define fit_err(fmt, ...) \
    fit_log(1, "[ERR] " fmt, ##__VA_ARGS__)
#define fit_warn( fmt, ...) \
    fit_log(2, "[WARN] " fmt, ##__VA_ARGS__)
#define fit_info(fmt, ...) \
    fit_log(3, fmt, ##__VA_ARGS__)
#define fit_debug(fmt, ...) \
    fit_log(4, fmt, ##__VA_ARGS__)

#define fit_panic(fmt, ...) \
    panic(_FIT_LOG_PREFIX fmt, ##__VA_ARGS__)

#endif /* _INCLUDE_FIT_LOG_H_ */