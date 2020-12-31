// SPDX-License-Identifier: GPL-2.0
/*
 * arch/loongarch/boot/compressed/string.c
 *
 * Very small subset of simple string routines
 */

#include <linux/types.h>

void __weak *memset(void *s, int c, size_t n)
{
	int i;
	char *ss = s;

	for (i = 0; i < n; i++)
		ss[i] = c;
	return s;
}

void __weak *memcpy(void *dest, const void *src, size_t n)
{
	int i;
	const char *s = src;
	char *d = dest;

	for (i = 0; i < n; i++)
		d[i] = s[i];
	return dest;
}

void __weak *memmove(void *dest, const void *src, size_t n)
{
	int i;
	const char *s = src;
	char *d = dest;

	if (d < s) {
		for (i = 0; i < n; i++)
			d[i] = s[i];
	} else if (d > s) {
		for (i = n - 1; i >= 0; i--)
			d[i] = s[i];
	}

	return dest;
}
