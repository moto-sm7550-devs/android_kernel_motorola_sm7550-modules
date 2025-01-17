// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Moto. All rights reserved.
 */

#include <linux/cgroup-defs.h>
#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/percpu-rwsem.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/stacktrace.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/sched/cputime.h>
#endif

#include <trace/hooks/rwsem.h>
#include <trace/hooks/dtask.h>

#include <../kernel/sched/sched.h>
#include "../msched_common.h"
#include "locking_main.h"

#define ENABLE_REORDER_LIST 1
#define ENABLE_INHERITE 1

#define RWSEM_READER_OWNED	(1UL << 0)
#define RWSEM_RD_NONSPINNABLE	(1UL << 1)
#define RWSEM_WR_NONSPINNABLE	(1UL << 2)
#define RWSEM_NONSPINNABLE	(RWSEM_RD_NONSPINNABLE | RWSEM_WR_NONSPINNABLE)
#define RWSEM_OWNER_FLAGS_MASK	(RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)

#define RWSEM_WRITER_LOCKED	(1UL << 0)
#define RWSEM_WRITER_MASK	RWSEM_WRITER_LOCKED

/*
 * Note:
 * The following macros must be the same as in kernel/locking/rwsem.c
 */
#define RWSEM_FLAG_WAITERS	(1UL << 1)
#define RWSEM_FLAG_HANDOFF	(1UL << 2)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	unsigned long timeout;
	bool handoff_set;
};
#endif

#define rwsem_first_waiter(sem) \
	list_first_entry(&sem->wait_list, struct rwsem_waiter, list)

static inline struct task_struct *rwsem_owner(struct rw_semaphore *sem)
{
	return (struct task_struct *)
		(atomic_long_read(&sem->owner) & ~RWSEM_OWNER_FLAGS_MASK);
}

static inline bool rwsem_test_oflags(struct rw_semaphore *sem, long flags)
{
	return atomic_long_read(&sem->owner) & flags;
}

static inline bool is_rwsem_reader_owned(struct rw_semaphore *sem)
{
#if IS_ENABLED(CONFIG_DEBUG_RWSEMS)
	/*
	 * Check the count to see if it is write-locked.
	 */
	long count = atomic_long_read(&sem->count);

	if (count & RWSEM_WRITER_MASK)
		return false;
#endif
	return rwsem_test_oflags(sem, RWSEM_READER_OWNED);
}

#ifdef ENABLE_REORDER_LIST
bool rwsem_list_add(struct task_struct *tsk, struct list_head *entry, struct list_head *head)
{
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	struct rwsem_waiter *waiter = NULL;
	int index = 0;
	int prio = 0;

	if (!entry || !head) {
		printk(KERN_ERR "rwsem_list_add %p %p is NULL", entry, head);
		return false;
	}
	prio = task_get_mvp_prio(current, true);

	if (prio > 0) {
		list_for_each_safe(pos, n, head) {
			waiter = list_entry(pos, struct rwsem_waiter, list);
			if (waiter && waiter->task->prio > MAX_RT_PRIO && prio > task_get_mvp_prio(waiter->task, true)) {
				cond_trace_printk(unlikely(is_debuggable(DEBUG_BASE)),
					"rwsem_list_add %d prio=%d(%d)index=%d\n", tsk->pid, prio, task_get_mvp_prio(waiter->task, true), index);
				list_add(entry, waiter->list.prev);
				return true;
			}
			index +=1;
		}

		if (pos == head) {
			list_add_tail(entry, head);
		}
		return true;
	}

	return false;
}

/* timeout is 5s */
#define WAIT_TIMEOUT		5000

inline bool test_wait_timeout(struct rw_semaphore *sem)
{
	struct rwsem_waiter *waiter;
	unsigned long timeout;
	struct task_struct *task;
	long count;
	bool ret = false;

	if (!sem)
		return false;

	count = atomic_long_read(&sem->count);
	if (!(count & RWSEM_FLAG_WAITERS))
		return false;

	waiter = rwsem_first_waiter(sem);
	if (!waiter)
		return false;

	timeout = waiter->timeout;
	task = waiter->task;
	if (!task)
		return false;

	ret = time_is_before_jiffies(timeout + msecs_to_jiffies(WAIT_TIMEOUT));
	if (ret) {
		cond_trace_printk(unlikely(is_debuggable(DEBUG_BASE)),
			"rwsem wait timeout [%s$%d]: task=%s, pid=%d, tgid=%d, prio=%d, ux=%d, timeout=%lu(0x%lx), t_m=%lu(0x%lx), jiffies=%lu(0x%lx)\n",
			__func__, __LINE__,
			task->comm, task->pid, task->tgid, task->prio, task_get_ux_type(task),
			timeout, timeout,
			timeout + msecs_to_jiffies(WAIT_TIMEOUT), timeout + msecs_to_jiffies(WAIT_TIMEOUT),
			jiffies, jiffies);
	}

	return ret;
}

static void android_vh_alter_rwsem_list_add_handler(void *unused, struct rwsem_waiter *waiter,
			struct rw_semaphore *sem, bool *already_on_list)
{
	bool ret = false;
	if (!waiter || !sem)
		return;

	if (unlikely(!locking_opt_enable()))
		return;

	if (waiter->type == RWSEM_WAITING_FOR_READ)
		return;

	if (test_wait_timeout(sem))
		return;

	ret = rwsem_list_add(waiter->task, &waiter->list, &sem->wait_list);

	if (ret)
		*already_on_list = true;
}
#endif

#ifdef ENABLE_INHERITE
static void android_vh_rwsem_wake_handler(void *unused, struct rw_semaphore *sem)
{
	struct task_struct *owner_ts = NULL;
	long owner = atomic_long_read(&sem->owner);
	bool boost = false;

	if (unlikely(!locking_opt_enable() || !sem)) {
		return;
	}

	if (!current_is_important_ux() && (current->prio > 100)) {
		return;
	}

	if (is_rwsem_reader_owned(sem)) {
		cond_trace_printk(unlikely(is_debuggable(DEBUG_BASE)),
			"is_rwsem_reader_owned, ignore! owner=%lx count=%lx\n", atomic_long_read(&sem->owner),
			atomic_long_read(&sem->count));
		return;
	}

	owner_ts = rwsem_owner(sem);
	if (!owner_ts) {
		cond_trace_printk(unlikely(is_debuggable(DEBUG_BASE)),
			"rwsem can't find owner=%lx count=%lx\n", atomic_long_read(&sem->owner),
			atomic_long_read(&sem->count));
		return;
	}

	get_task_struct(owner_ts);
	boost = lock_inherit_ux_type(owner_ts, current, "rwsem_wake");

	if (boost && (atomic_long_read(&sem->owner) != owner || is_rwsem_reader_owned(sem))) {
		cond_trace_printk(unlikely(is_debuggable(DEBUG_BASE)),
			"rwsem owner status has been changed owner=%lx(%lx)\n",
			atomic_long_read(&sem->owner), owner);
		lock_clear_inherited_ux_type(owner_ts, "rwsem_wake_finish");
	}
	put_task_struct(owner_ts);
}

static void android_vh_rwsem_wake_finish_handler(void *unused, struct rw_semaphore *sem)
{
	if (unlikely(!locking_opt_enable())) {
		return;
	}
	lock_clear_inherited_ux_type(current, "rwsem_wake_finish");
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static void android_vh_record_pcpu_rwsem_time_early(void *unused, unsigned long settime_jiffies, struct percpu_rw_semaphore *sem)
{
	if (unlikely(!locking_opt_enable()))
		return;

	if (sem == &cgroup_threadgroup_rwsem) {
		lock_protect_update_starttime(current, settime_jiffies, "percpu_rwsem", sem);
	}
}
#endif

void register_rwsem_vendor_hooks(void)
{
#ifdef ENABLE_REORDER_LIST
	register_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add_handler, NULL);
#endif

#ifdef ENABLE_INHERITE
	register_trace_android_vh_rwsem_wake(android_vh_rwsem_wake_handler, NULL);
	register_trace_android_vh_rwsem_wake_finish(android_vh_rwsem_wake_finish_handler, NULL);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    register_trace_android_vh_record_pcpu_rwsem_time_early(android_vh_record_pcpu_rwsem_time_early, NULL);
#endif
}

void unregister_rwsem_vendor_hooks(void)
{
#ifdef ENABLE_REORDER_LIST
	unregister_trace_android_vh_alter_rwsem_list_add(android_vh_alter_rwsem_list_add_handler, NULL);
#endif
#ifdef ENABLE_INHERITE
	unregister_trace_android_vh_rwsem_wake(android_vh_rwsem_wake_handler, NULL);
	unregister_trace_android_vh_rwsem_wake_finish(android_vh_rwsem_wake_finish_handler, NULL);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    unregister_trace_android_vh_record_pcpu_rwsem_time_early(android_vh_record_pcpu_rwsem_time_early, NULL);
#endif
}

