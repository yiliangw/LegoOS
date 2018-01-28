/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_SWEEP_H_
#define _LEGO_PROCESSOR_PCACHE_SWEEP_H_

#include <processor/pcache_types.h>

/*
 * SUCCESS_ONE: We evicted one pcache line successfully
 * SUCCESS_NOACTION: There are free pcache lines showed up during eviction
 * SUCCESS_FAILED: Eviction code failed somehow
 */
enum evict_status {
	PCACHE_EVICT_SUCCESS_ONE,
	PCACHE_EVICT_SUCCESS_NOACTION,
	PCACHE_EVICT_FAILED
};

/*
 * Common sweep threads for certain eviction algorithms:
 * 	LRU: Least-Recently Used
 */
#ifdef CONFIG_PCACHE_EVICT_GENERIC_SWEEP
int __init evict_sweep_init(void);
#else
static inline int evict_sweep_init(void) { return 0; }
#endif

/*
 * Eviction Algorithm
 * 	Least Recently Used
 */
#ifdef CONFIG_PCACHE_EVICT_LRU
static inline void dec_pset_nr_lru(struct pcache_set *pset)
{
	atomic_dec(&pset->nr_lru);
}

static inline void inc_pset_nr_lru(struct pcache_set *pset)
{
	atomic_inc(&pset->nr_lru);
}

static inline int pset_nr_lru(struct pcache_set *pset)
{
	return atomic_read(&pset->nr_lru);
}

static inline void
__add_to_lru_list(struct pcache_meta *pcm, struct pcache_set *pset)
{
	list_add(&pcm->lru, &pset->lru_list);
	inc_pset_nr_lru(pset);
}

static inline void
add_to_lru_list(struct pcache_meta *pcm, struct pcache_set *pset)
{
	spin_lock(&pset->lru_lock);
	__add_to_lru_list(pcm, pset);
	spin_unlock(&pset->lru_lock);
}

static inline void
__del_from_lru_list(struct pcache_meta *pcm, struct pcache_set *pset)
{
	list_del(&pcm->lru);
	dec_pset_nr_lru(pset);
}

static inline void
del_from_lru_list(struct pcache_meta *pcm, struct pcache_set *pset)
{
	spin_lock(&pset->lru_lock);
	__del_from_lru_list(pcm, pset);
	spin_unlock(&pset->lru_lock);
}

static inline void attach_to_lru(struct pcache_meta *pcm)
{
	struct pcache_set *pset;

	pset = pcache_meta_to_pcache_set(pcm);
	add_to_lru_list(pcm, pset);
}

static inline void detach_from_lru(struct pcache_meta *pcm)
{
	struct pcache_set *pset;

	pset = pcache_meta_to_pcache_set(pcm);
	del_from_lru_list(pcm, pset);
}

static inline void init_pcache_lru(struct pcache_meta *pcm)
{
	INIT_LIST_HEAD(&pcm->lru);
}

/* Callback: find a pcache line to evict */
struct pcache_meta *evict_find_line_lru(struct pcache_set *pset);

/* Callback: sweep a given set */
void sweep_pset_lru(struct pcache_set *pset);

#else
static inline void
add_to_lru_list(struct pcache_meta *pcm, struct pcache_set *pset) { }
static inline void
del_from_lru_list(struct pcache_meta *pcm, struct pcache_set *pset) { }

static inline void attach_to_lru(struct pcache_meta *pcm) { }
static inline void detach_from_lru(struct pcache_meta *pcm) { }

static inline void init_pcache_lru(struct pcache_meta *pcm) { }

static inline struct pcache_meta *
evict_find_line_lru(struct pcache_set *pset)
{
	BUG();
}

static inline void sweep_pset_lru(struct pcache_set *pset)
{
	BUG();
}

#endif /* EVICT_LRU */

/*
 * Eviction Algorithm
 * 	First-In-First-Out (FIFO)
 */
#ifdef CONFIG_PCACHE_EVICT_FIFO
struct pcache_meta *evict_find_line_fifo(struct pcache_set *pset);
#else
static inline struct pcache_meta *
evict_find_line_fifo(struct pcache_set *pset) { BUG(); }
#endif /* EVICT_FIFO */

/*
 * Eviction Algorithm
 * 	Random
 */
#ifdef CONFIG_PCACHE_EVICT_RANDOM
struct pcache_meta *evict_find_line_random(struct pcache_set *pset);
#else
static inline struct pcache_meta *
evict_find_line_random(struct pcache_set *pset) { BUG(); }
#endif /* EVICT_RANDOM */

#endif /* _LEGO_PROCESSOR_PCACHE_SWEEP_H_ */