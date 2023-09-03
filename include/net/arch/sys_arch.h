#ifndef LWIP_ARCH_SYS_ARCH_H
#define LWIP_ARCH_SYS_ARCH_H

#ifdef _LEGO_LINUX_MODULE_
#include <linux/types.h>
#else
#include <lego/types.h>
#endif /* _LEGO_LINUX_MODULE_ */

typedef	int sys_sem_t;
typedef int sys_mbox_t;
typedef int sys_thread_t;

#define SYS_MBOX_NULL	(-1)
#define SYS_SEM_NULL	(-1)

void lwip_core_lock(void);
void lwip_core_unlock(void);
void lwip_core_init(void);

#define SYS_ARCH_DECL_PROTECT(lev)
#define SYS_ARCH_PROTECT(lev)
#define SYS_ARCH_UNPROTECT(lev)

#define SYS_ARCH_NOWAIT  0xfffffffe

#include <lego/slab.h>

#endif
