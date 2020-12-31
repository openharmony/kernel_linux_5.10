/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_QSPINLOCK_H
#define _ASM_QSPINLOCK_H

#include <asm/paravirt.h>
#include <asm-generic/qspinlock_types.h>

#define _Q_PENDING_LOOPS	(1 << 9)
#define queued_spin_unlock queued_spin_unlock

#ifdef CONFIG_PARAVIRT_SPINLOCKS
extern void native_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
extern void __pv_init_lock_hash(void);
extern void __pv_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
extern void __pv_queued_spin_unlock(struct qspinlock *lock);

static inline void native_queued_spin_unlock(struct qspinlock *lock)
{
	compiletime_assert_atomic_type(lock->locked);
	c_sync();
	WRITE_ONCE(lock->locked, 0);
}

static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	pv_queued_spin_lock_slowpath(lock, val);
}

static inline void queued_spin_unlock(struct qspinlock *lock)
{
	pv_queued_spin_unlock(lock);
}

#define vcpu_is_preempted vcpu_is_preempted
static inline bool vcpu_is_preempted(long cpu)
{
	return pv_vcpu_is_preempted(cpu);
}
#else
static inline void queued_spin_unlock(struct qspinlock *lock)
{
	compiletime_assert_atomic_type(lock->locked);
	c_sync();
	WRITE_ONCE(lock->locked, 0);
}
#endif

#include <asm-generic/qspinlock.h>

#endif /* _ASM_QSPINLOCK_H */
