/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 *
 * But use these as seldom as possible since they are much more slower
 * than regular operations.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_ATOMIC_H
#define _ASM_ATOMIC_H

#include <linux/types.h>
#include <asm/barrier.h>
#include <asm/cpu-features.h>
#include <asm/cmpxchg.h>

#if __SIZEOF_LONG__ == 4
#define __LL		"ll.w	"
#define __SC		"sc.w	"
#define __AMADD		"amadd.w	"
#define __AMAND_DB	"amand_db.w	"
#define __AMOR_DB	"amor_db.w	"
#define __AMXOR_DB	"amxor_db.w	"
#elif __SIZEOF_LONG__ == 8
#define __LL		"ll.d	"
#define __SC		"sc.d	"
#define __AMADD		"amadd.d	"
#define __AMAND_DB	"amand_db.d	"
#define __AMOR_DB	"amor_db.d	"
#define __AMXOR_DB	"amxor_db.d	"
#endif

#define ATOMIC_INIT(i)	  { (i) }

/*
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.
 */
#define atomic_read(v)		READ_ONCE((v)->counter)

/*
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
#define atomic_set(v, i)	WRITE_ONCE((v)->counter, (i))

#define ATOMIC_OP(op, I, asm_op)					\
static __inline__ void atomic_##op(int i, atomic_t * v)			\
{									\
	__asm__ __volatile__(						\
	"am"#asm_op".w" " $zero, %1, %0	\n"				\
	: "+ZB" (v->counter)				   		\
	: "r" (I)							\
	: "memory");						   	\
}

#define ATOMIC_OP_RETURN(op, I, asm_op, c_op, mb, suffix)		\
static __inline__ int atomic_##op##_return##suffix(int i, atomic_t * v)	\
{									\
	int result;							\
									\
	__asm__ __volatile__(						\
	"am"#asm_op#mb".w" " %1, %2, %0		\n"			\
	: "+ZB" (v->counter), "=&r" (result)				\
	: "r" (I)							\
	: "memory");							\
									\
	return result c_op I;						\
}

#define ATOMIC_FETCH_OP(op, I, asm_op, mb, suffix)			\
static __inline__ int atomic_fetch_##op##suffix(int i, atomic_t * v)	\
{									\
	int result;							\
									\
	__asm__ __volatile__(						\
	"am"#asm_op#mb".w" " %1, %2, %0		\n"			\
	: "+ZB" (v->counter), "=&r" (result)				\
	: "r" (I)							\
	: "memory");							\
									\
	return result;							\
}

#define ATOMIC_OPS(op, I, asm_op, c_op)					\
	ATOMIC_OP(op, I, asm_op)					\
	ATOMIC_OP_RETURN(op, I, asm_op, c_op, _db,         )		\
	ATOMIC_OP_RETURN(op, I, asm_op, c_op,    , _relaxed)		\
	ATOMIC_FETCH_OP(op, I, asm_op, _db,         )			\
	ATOMIC_FETCH_OP(op, I, asm_op,    , _relaxed)

ATOMIC_OPS(add, i, add, +)
ATOMIC_OPS(sub, -i, add, +)

#define atomic_add_return		atomic_add_return
#define atomic_add_return_acquire	atomic_add_return
#define atomic_add_return_release	atomic_add_return
#define atomic_add_return_relaxed	atomic_add_return_relaxed
#define atomic_sub_return		atomic_sub_return
#define atomic_sub_return_acquire	atomic_sub_return
#define atomic_sub_return_release	atomic_sub_return
#define atomic_sub_return_relaxed	atomic_sub_return_relaxed
#define atomic_fetch_add		atomic_fetch_add
#define atomic_fetch_add_acquire	atomic_fetch_add
#define atomic_fetch_add_release	atomic_fetch_add
#define atomic_fetch_add_relaxed	atomic_fetch_add_relaxed
#define atomic_fetch_sub		atomic_fetch_sub
#define atomic_fetch_sub_acquire	atomic_fetch_sub
#define atomic_fetch_sub_release	atomic_fetch_sub
#define atomic_fetch_sub_relaxed	atomic_fetch_sub_relaxed

#undef ATOMIC_OPS

#define ATOMIC_OPS(op, I, asm_op)					\
	ATOMIC_OP(op, I, asm_op)					\
	ATOMIC_FETCH_OP(op, I, asm_op, _db,         )			\
	ATOMIC_FETCH_OP(op, I, asm_op,    , _relaxed)

ATOMIC_OPS(and, i, and)
ATOMIC_OPS(or, i, or)
ATOMIC_OPS(xor, i, xor)

#define atomic_fetch_and		atomic_fetch_and
#define atomic_fetch_and_acquire	atomic_fetch_and
#define atomic_fetch_and_release	atomic_fetch_and
#define atomic_fetch_and_relaxed	atomic_fetch_and_relaxed
#define atomic_fetch_or			atomic_fetch_or
#define atomic_fetch_or_acquire		atomic_fetch_or
#define atomic_fetch_or_release		atomic_fetch_or
#define atomic_fetch_or_relaxed		atomic_fetch_or_relaxed
#define atomic_fetch_xor		atomic_fetch_xor
#define atomic_fetch_xor_acquire	atomic_fetch_xor
#define atomic_fetch_xor_release	atomic_fetch_xor
#define atomic_fetch_xor_relaxed	atomic_fetch_xor_relaxed

#undef ATOMIC_OPS
#undef ATOMIC_FETCH_OP
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

static __inline__ int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
       int prev, rc;

	__asm__ __volatile__ (
		"0:	ll.w	%[p],  %[c]\n"
		"	beq	%[p],  %[u], 1f\n"
		"	add.w	%[rc], %[p], %[a]\n"
		"	sc.w	%[rc], %[c]\n"
		"	beqz	%[rc], 0b\n"
		"	b	2f\n"
		"1:\n"
		__WEAK_LLSC_MB
		"2:\n"
		: [p]"=&r" (prev), [rc]"=&r" (rc),
		  [c]"=ZB" (v->counter)
		: [a]"r" (a), [u]"r" (u)
		: "memory");

	return prev;
}
#define atomic_fetch_add_unless atomic_fetch_add_unless

/*
 * atomic_sub_if_positive - conditionally subtract integer from atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ int atomic_sub_if_positive(int i, atomic_t * v)
{
	int result;
	int temp;

	if (__builtin_constant_p(i)) {
		__asm__ __volatile__(
		"1:	ll.w	%1, %2		# atomic_sub_if_positive\n"
		"	addi.w	%0, %1, %3				\n"
		"	or	%1, %0, $zero				\n"
		"	blt	%0, $zero, 2f				\n"
		"	sc.w	%1, %2					\n"
		"	beq	$zero, %1, 1b				\n"
		"2:							\n"
		__WEAK_LLSC_MB
		: "=&r" (result), "=&r" (temp), "+ZC" (v->counter)
		: "I" (-i));
	} else {
		__asm__ __volatile__(
		"1:	ll.w	%1, %2		# atomic_sub_if_positive\n"
		"	sub.w	%0, %1, %3				\n"
		"	or	%1, %0, $zero				\n"
		"	blt	%0, $zero, 2f				\n"
		"	sc.w	%1, %2					\n"
		"	beq	$zero, %1, 1b				\n"
		"2:							\n"
		__WEAK_LLSC_MB
		: "=&r" (result), "=&r" (temp), "+ZC" (v->counter)
		: "r" (i));
	}

	return result;
}

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))
#define atomic_xchg(v, new) (xchg(&((v)->counter), (new)))

/*
 * atomic_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic_t
 */
#define atomic_dec_if_positive(v)	atomic_sub_if_positive(1, v)

#ifdef CONFIG_64BIT

#define ATOMIC64_INIT(i)    { (i) }

/*
 * atomic64_read - read atomic variable
 * @v: pointer of type atomic64_t
 *
 */
#define atomic64_read(v)	READ_ONCE((v)->counter)

/*
 * atomic64_set - set atomic variable
 * @v: pointer of type atomic64_t
 * @i: required value
 */
#define atomic64_set(v, i)	WRITE_ONCE((v)->counter, (i))

#define ATOMIC64_OP(op, I, asm_op)					\
static __inline__ void atomic64_##op(long i, atomic64_t * v)		\
{									\
	__asm__ __volatile__(						\
	"am"#asm_op".d " " $zero, %1, %0	\n"			\
	: "+ZB" (v->counter)						\
	: "r" (I)							\
	: "memory");							\
}

#define ATOMIC64_OP_RETURN(op, I, asm_op, c_op, mb, suffix)			\
static __inline__ long atomic64_##op##_return##suffix(long i, atomic64_t * v)	\
{										\
	long result;								\
	__asm__ __volatile__(							\
	"am"#asm_op#mb".d " " %1, %2, %0		\n"			\
	: "+ZB" (v->counter), "=&r" (result)					\
	: "r" (I)								\
	: "memory");								\
										\
	return result c_op I;							\
}

#define ATOMIC64_FETCH_OP(op, I, asm_op, mb, suffix)				\
static __inline__ long atomic64_fetch_##op##suffix(long i, atomic64_t * v)	\
{										\
	long result;								\
										\
	__asm__ __volatile__(							\
	"am"#asm_op#mb".d " " %1, %2, %0		\n"			\
	: "+ZB" (v->counter), "=&r" (result)					\
	: "r" (I)								\
	: "memory");								\
										\
	return result;								\
}

#define ATOMIC64_OPS(op, I, asm_op, c_op)				      \
	ATOMIC64_OP(op, I, asm_op)					      \
	ATOMIC64_OP_RETURN(op, I, asm_op, c_op, _db,         )		      \
	ATOMIC64_OP_RETURN(op, I, asm_op, c_op,    , _relaxed)		      \
	ATOMIC64_FETCH_OP(op, I, asm_op, _db,         )			      \
	ATOMIC64_FETCH_OP(op, I, asm_op,    , _relaxed)

ATOMIC64_OPS(add, i, add, +)
ATOMIC64_OPS(sub, -i, add, +)

#define atomic64_add_return		atomic64_add_return
#define atomic64_add_return_acquire	atomic64_add_return
#define atomic64_add_return_release	atomic64_add_return
#define atomic64_add_return_relaxed	atomic64_add_return_relaxed
#define atomic64_sub_return		atomic64_sub_return
#define atomic64_sub_return_acquire	atomic64_sub_return
#define atomic64_sub_return_release	atomic64_sub_return
#define atomic64_sub_return_relaxed	atomic64_sub_return_relaxed
#define atomic64_fetch_add		atomic64_fetch_add
#define atomic64_fetch_add_acquire	atomic64_fetch_add
#define atomic64_fetch_add_release	atomic64_fetch_add
#define atomic64_fetch_add_relaxed	atomic64_fetch_add_relaxed
#define atomic64_fetch_sub		atomic64_fetch_sub
#define atomic64_fetch_sub_acquire	atomic64_fetch_sub
#define atomic64_fetch_sub_release	atomic64_fetch_sub
#define atomic64_fetch_sub_relaxed	atomic64_fetch_sub_relaxed

#undef ATOMIC64_OPS

#define ATOMIC64_OPS(op, I, asm_op)					      \
	ATOMIC64_OP(op, I, asm_op)					      \
	ATOMIC64_FETCH_OP(op, I, asm_op, _db,         )			      \
	ATOMIC64_FETCH_OP(op, I, asm_op,    , _relaxed)

ATOMIC64_OPS(and, i, and)
ATOMIC64_OPS(or, i, or)
ATOMIC64_OPS(xor, i, xor)

#define atomic64_fetch_and		atomic64_fetch_and
#define atomic64_fetch_and_acquire	atomic64_fetch_and
#define atomic64_fetch_and_release	atomic64_fetch_and
#define atomic64_fetch_and_relaxed	atomic64_fetch_and_relaxed
#define atomic64_fetch_or		atomic64_fetch_or
#define atomic64_fetch_or_acquire	atomic64_fetch_or
#define atomic64_fetch_or_release	atomic64_fetch_or
#define atomic64_fetch_or_relaxed	atomic64_fetch_or_relaxed
#define atomic64_fetch_xor		atomic64_fetch_xor
#define atomic64_fetch_xor_acquire	atomic64_fetch_xor
#define atomic64_fetch_xor_release	atomic64_fetch_xor
#define atomic64_fetch_xor_relaxed	atomic64_fetch_xor_relaxed

#undef ATOMIC64_OPS
#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_OP_RETURN
#undef ATOMIC64_OP

static __inline__ long atomic64_fetch_add_unless(atomic64_t *v, long a, long u)
{
       long prev, rc;

	__asm__ __volatile__ (
		"0:	ll.d	%[p],  %[c]\n"
		"	beq	%[p],  %[u], 1f\n"
		"	add.d	%[rc], %[p], %[a]\n"
		"	sc.d	%[rc], %[c]\n"
		"	beqz	%[rc], 0b\n"
		"	b	2f\n"
		"1:\n"
		__WEAK_LLSC_MB
		"2:\n"
		: [p]"=&r" (prev), [rc]"=&r" (rc),
		  [c] "=ZB" (v->counter)
		: [a]"r" (a), [u]"r" (u)
		: "memory");

	return prev;
}
#define atomic64_fetch_add_unless atomic64_fetch_add_unless

/*
 * atomic64_sub_if_positive - conditionally subtract integer from atomic
 *                            variable
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically test @v and subtract @i if @v is greater or equal than @i.
 * The function returns the old value of @v minus @i.
 */
static __inline__ long atomic64_sub_if_positive(long i, atomic64_t * v)
{
	long result;
	long temp;

	if (__builtin_constant_p(i)) {
		__asm__ __volatile__(
		"1:	ll.d	%1, %2 	# atomic64_sub_if_positive	\n"
		"	addi.d	%0, %1, %3				\n"
		"	or	%1, %0, $zero				\n"
		"	blt	%0, $zero, 2f				\n"
		"	sc.d	%1, %2					\n"
		"	beq	%1, $zero, 1b				\n"
		"2:							\n"
		__WEAK_LLSC_MB
		: "=&r" (result), "=&r" (temp), "+ZC" (v->counter)
		: "I" (-i));
	} else {
		__asm__ __volatile__(
		"1:	ll.d	%1, %2 	# atomic64_sub_if_positive	\n"
		"	sub.d	%0, %1, %3				\n"
		"	or	%1, %0, $zero				\n"
		"	blt	%0, $zero, 2f				\n"
		"	sc.d	%1, %2					\n"
		"	beq	%1, $zero, 1b				\n"
		"2:							\n"
		__WEAK_LLSC_MB
		: "=&r" (result), "=&r" (temp), "+ZC" (v->counter)
		: "r" (i));
	}

	return result;
}

#define atomic64_cmpxchg(v, o, n) \
	((__typeof__((v)->counter))cmpxchg(&((v)->counter), (o), (n)))
#define atomic64_xchg(v, new) (xchg(&((v)->counter), (new)))

/*
 * atomic64_dec_if_positive - decrement by 1 if old value positive
 * @v: pointer of type atomic64_t
 */
#define atomic64_dec_if_positive(v)	atomic64_sub_if_positive(1, v)

#endif /* CONFIG_64BIT */

#endif /* _ASM_ATOMIC_H */
