/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_PID_H_
#define _LEGO_MEMORY_PID_H_

#include <lego/comp_memory.h>

void free_lego_task(struct lego_task_struct *tsk);

struct lego_task_struct *
alloc_lego_task(unsigned int node, unsigned int pid);

struct lego_task_struct *
find_lego_task_by_pid(unsigned int node, unsigned int pid);

#endif /* _LEGO_MEMORY_PID_H_ */
