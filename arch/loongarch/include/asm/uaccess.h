/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#ifndef _ASM_UACCESS_H
#define _ASM_UACCESS_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/extable.h>
#include <asm/extable.h>
#include <asm/asm-extable.h>

#ifdef CONFIG_64BIT

extern u64 __ua_limit;

#define __UA_LIMIT	__ua_limit

#define __UA_ADDR	".dword"
#define __UA_LA		"la.abs"

#endif /* CONFIG_64BIT */

/*
 * Is a address valid? This does a straightforward calculation rather
 * than tests.
 *
 * Address valid if:
 *  - "addr" doesn't have any high-bits set
 *  - AND "size" doesn't have any high-bits set
 *  - AND "addr+size" doesn't have any high-bits set
 *  - OR we are in kernel mode.
 *
 * __ua_size() is a trick to avoid runtime checking of positive constant
 * sizes; for those we already know at compile time that the size is ok.
 */
#define __ua_size(size)							\
	((__builtin_constant_p(size) && (signed long) (size) > 0) ? 0 : (size))

/*
 * access_ok: - Checks if a user space pointer is valid
 * @addr: User space pointer to start of block to check
 * @size: Size of block to check
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Checks if a pointer to a block of memory in user space is valid.
 *
 * Returns true (nonzero) if the memory block may be valid, false (zero)
 * if it is definitely invalid.
 *
 * Note that, depending on architecture, this function probably just
 * checks that the pointer is in the user space range - after calling
 * this function, memory access functions may still return -EFAULT.
 */
static inline int __access_ok(const void __user *p, unsigned long size)
{
	unsigned long addr = (unsigned long)p;
	unsigned long end = addr + size - !!size;

	return (__UA_LIMIT & (addr | end | __ua_size(size))) == 0;
}

#define access_ok(addr, size)					\
	likely(__access_ok((addr), (size)))

/*
 * get_user: - Get a simple variable from user space.
 * @x:	 Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define get_user(x,ptr) \
({									\
	const __typeof__(*(ptr)) __user *__p = (ptr);			\
									\
	might_fault();							\
	access_ok(__p, sizeof(*__p)) ? __get_user((x), __p) :		\
				       ((x) = 0, -EFAULT);		\
})

/*
 * put_user: - Write a simple value into user space.
 * @x:	 Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define put_user(x,ptr) \
({									\
	__typeof__(*(ptr)) __user *__p = (ptr);				\
									\
	might_fault();							\
	access_ok(__p, sizeof(*__p)) ? __put_user((x), __p) : -EFAULT;	\
})

/*
 * __get_user: - Get a simple variable from user space, with less checking.
 * @x:	 Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
#define __get_user(x,ptr) \
({									\
	int __gu_err = 0;						\
									\
	__chk_user_ptr(ptr);						\
	__get_user_common((x), sizeof(*(ptr)), ptr);			\
	__gu_err;							\
})

/*
 * __put_user: - Write a simple value into user space, with less checking.
 * @x:	 Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define __put_user(x,ptr) \
({									\
	int __pu_err = 0;						\
	__typeof__(*(ptr)) __pu_val;					\
									\
	__pu_val = (x);							\
	__chk_user_ptr(ptr);						\
	__put_user_common(ptr, sizeof(*(ptr)));				\
	__pu_err;							\
})

struct __large_struct { unsigned long buf[100]; };
#define __m(x) (*(struct __large_struct __user *)(x))

#ifdef CONFIG_32BIT
#define __GET_DW(val, insn, ptr) __get_data_asm_ll32(val, insn, ptr)
#endif
#ifdef CONFIG_64BIT
#define __GET_DW(val, insn, ptr) __get_data_asm(val, insn, ptr)
#endif

#define __get_user_common(val, size, ptr)				\
do {									\
	switch (size) {							\
	case 1: __get_data_asm(val, "ld.b", ptr); break;		\
	case 2: __get_data_asm(val, "ld.h", ptr); break;		\
	case 4: __get_data_asm(val, "ld.w", ptr); break;		\
	case 8: __GET_DW(val, "ld.d", ptr); break;			\
	default: BUILD_BUG(); break;					\
	}								\
} while (0)

#define __get_kernel_common(val, size, ptr) __get_user_common(val, size, ptr)

#define __get_data_asm(val, insn, ptr)					\
{									\
	long __gu_tmp;							\
									\
	__asm__ __volatile__(						\
	"1:	" insn "	%1, %2				\n"	\
	"2:							\n"	\
	_ASM_EXTABLE_UACCESS_ERR_ZERO(1b, 2b, %0, %1)			\
	: "+r" (__gu_err), "=r" (__gu_tmp)				\
	: "m" (__m(ptr)));						\
									\
	(val) = (__typeof__(*(ptr))) __gu_tmp;				\
}

/*
 * Get a long long 64 using 32 bit registers.
 */
#define __get_data_asm_ll32(val, insn, ptr)				\
{									\
	union {								\
		unsigned long long	l;				\
		__typeof__(*(addr))	t;				\
	} __gu_tmp;							\
									\
	__asm__ __volatile__(						\
	"1:	ld.w	%1, (%2)				\n"	\
	"2:	ld.w	%D1, 4(%2)				\n"	\
	"3:							\n"	\
	"	.section	.fixup,\"ax\"			\n"	\
	"4:	li.w	%0, %3					\n"	\
	"	slli.d	%1, $r0, 0				\n"	\
	"	slli.d	%D1, $r0, 0				\n"	\
	"	b	3b					\n"	\
	"	.previous					\n"	\
	"	.section	__ex_table,\"a\"		\n"	\
	"	" __UA_ADDR "	1b, 4b				\n"	\
	"	" __UA_ADDR "	2b, 4b				\n"	\
	"	.previous					\n"	\
	: "+r" (__gu_err), "=&r" (__gu_tmp.l)				\
	: "r" (ptr), "i" (-EFAULT));					\
									\
	(val) = __gu_tmp.t;						\
}

#ifdef CONFIG_32BIT
#define __PUT_DW(insn, ptr) __put_data_asm_ll32(insn, ptr)
#endif
#ifdef CONFIG_64BIT
#define __PUT_DW(insn, ptr) __put_data_asm(insn, ptr)
#endif

#define __put_user_common(ptr, size)					\
do {									\
	switch (size) {							\
	case 1: __put_data_asm("st.b", ptr); break;			\
	case 2: __put_data_asm("st.h", ptr); break;			\
	case 4: __put_data_asm("st.w", ptr); break;			\
	case 8: __PUT_DW("st.d", ptr); break;				\
	default: BUILD_BUG(); break;					\
	}								\
} while (0)

#define __put_kernel_common(ptr, size) __put_user_common(ptr, size)

#define __put_data_asm(insn, ptr)					\
{									\
	__asm__ __volatile__(						\
	"1:	" insn "	%z2, %1		# __put_user_asm\n"	\
	"2:							\n"	\
	_ASM_EXTABLE_UACCESS_ERR(1b, 2b, %0)				\
	: "+r" (__pu_err), "=m" (__m(ptr))				\
	: "Jr" (__pu_val));						\
}

#define __put_data_asm_ll32(insn, ptr)					\
{									\
	__asm__ __volatile__(						\
	"1:	st.w	%1, (%2)	# __put_user_asm_ll32	\n"	\
	"2:	st.w	%D1, 4(%2)				\n"	\
	"3:							\n"	\
	"	.section	.fixup,\"ax\"			\n"	\
	"4:	li.w	%0, %3					\n"	\
	"	b	3b					\n"	\
	"	.previous					\n"	\
	"	.section	__ex_table,\"a\"		\n"	\
	"	" __UA_ADDR "	1b, 4b				\n"	\
	"	" __UA_ADDR "	2b, 4b				\n"	\
	"	.previous"						\
	: "+r" (__pu_err)						\
	: "r" (__pu_val), "r" (ptr), "i" (-EFAULT));			\
}

#define HAVE_GET_KERNEL_NOFAULT

#define __get_kernel_nofault(dst, src, type, err_label)			\
do {									\
	int __gu_err = 0;						\
									\
	__get_kernel_common(*((type *)(dst)), sizeof(type),		\
			    (__force type *)(src));			\
	if (unlikely(__gu_err))						\
		goto err_label;						\
} while (0)

#define __put_kernel_nofault(dst, src, type, err_label)			\
do {									\
	type __pu_val;							\
	int __pu_err = 0;						\
									\
	__pu_val = *(__force type *)(src);				\
	__put_kernel_common(((type *)(dst)), sizeof(type));		\
	if (unlikely(__pu_err))						\
		goto err_label;						\
} while (0)

extern unsigned long __copy_user(void *to, const void *from, __kernel_size_t n);

static inline unsigned long __must_check
raw_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return __copy_user(to, (__force const void *)from, n);
}

static inline unsigned long __must_check
raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return __copy_user((__force void *)to, from, n);
}

#define INLINE_COPY_FROM_USER
#define INLINE_COPY_TO_USER

/*
 * __clear_user: - Zero a block of memory in user space, with less checking.
 * @addr: Destination address, in user space.
 * @to:	  Number of bytes to zero.
 *
 * Zero a block of memory in user space.  Caller must check
 * the specified block with access_ok() before calling this function.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
extern unsigned long __clear_user(void __user *addr, __kernel_size_t size);

#define clear_user(addr,n)						\
({									\
	void __user * __cl_addr = (addr);				\
	unsigned long __cl_size = (n);					\
	if (__cl_size && access_ok(__cl_addr, __cl_size))		\
		__cl_size = __clear_user(__cl_addr, __cl_size);		\
	__cl_size;							\
})

extern long strncpy_from_user(char *dest, const char __user *src, long count);
extern long strnlen_user(const char __user *str, long n);

#endif /* _ASM_UACCESS_H */
