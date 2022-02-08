# SPDX-License-Identifier: GPL-2.0-only
zram-y	:=	zcomp.o zram_drv.o

zram-$(CONFIG_ZRAM_GROUP) += zram_group/zram_group.o zram_group/zlist.o zram_group/group_writeback.o

obj-$(CONFIG_ZRAM)	+=	zram.o

ccflags-$(CONFIG_ZRAM_GROUP) += -I$(srctree)/drivers/block/zram/zram_group/
ccflags-$(CONFIG_HYPERHOLD) += -I$(srctree)/drivers/hyperhold/
