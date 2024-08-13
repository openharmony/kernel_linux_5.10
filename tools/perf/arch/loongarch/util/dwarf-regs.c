// SPDX-License-Identifier: GPL-2.0
/*
 * dwarf-regs.c : Mapping of DWARF debug register numbers into register names.
 *
 * Copyright (C) 2013 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <stdio.h>
#include <errno.h> /* for EINVAL */
#include <string.h> /* for strcmp */
#include <dwarf-regs.h>

struct pt_regs_dwarfnum {
	const char *name;
	unsigned int dwarfnum;
};

static struct pt_regs_dwarfnum loongarch_gpr_table[] = {
	{"$0", 0}, {"$1", 1}, {"$2", 2}, {"$3", 3},
	{"$4", 4}, {"$5", 5}, {"$6", 6}, {"$7", 7},
	{"$8", 8}, {"$9", 9}, {"$10", 10}, {"$11", 11},
	{"$12", 12}, {"$13", 13}, {"$14", 14}, {"$15", 15},
	{"$16", 16}, {"$17", 17}, {"$18", 18}, {"$19", 19},
	{"$20", 20}, {"$21", 21}, {"$22", 22}, {"$23", 23},
	{"$24", 24}, {"$25", 25}, {"$26", 26}, {"$27", 27},
	{"$28", 28}, {"$29", 29}, {"$30", 30}, {"$31", 31},
	{NULL, 0}
};

const char *get_arch_regstr(unsigned int n)
{
	n %= 32;
	return loongarch_gpr_table[n].name;
}

int regs_query_register_offset(const char *name)
{
	const struct pt_regs_dwarfnum *roff;

	for (roff = loongarch_gpr_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->dwarfnum;
	return -EINVAL;
}
