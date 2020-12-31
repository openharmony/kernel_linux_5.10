# SPDX-License-Identifier: GPL-2.0
#
# Author: Huacai Chen <chenhuacai@loongson.cn>
# Copyright (C) 2020 Loongson Technology Corporation Limited

#
# Drop some uninteresting sections in the kernel.
# This is only relevant for ELF kernels but doesn't hurt a.out
#
drop-sections := .comment .note .options
strip-flags   := $(addprefix --remove-section=,$(drop-sections))

suffix-y			:= bin
suffix-$(CONFIG_KERNEL_GZIP)	:= gz
suffix-$(CONFIG_KERNEL_BZIP2)	:= bz2
suffix-$(CONFIG_KERNEL_LZMA)	:= lzma
suffix-$(CONFIG_KERNEL_LZO)	:= lzo
suffix-$(CONFIG_KERNEL_LZ4)	:= lz4
suffix-$(CONFIG_KERNEL_ZSTD)	:= zst

targets += vmlinux.bin
quiet_cmd_bin = OBJCOPY $@
      cmd_bin = $(OBJCOPY) -O binary $(strip-flags) $(VMLINUX) $@
$(obj)/vmlinux.bin: $(VMLINUX) FORCE
	$(call if_changed,bin)

#
# Compressed vmlinux images
#

extra-y += vmlinux.bin.gz
extra-y += vmlinux.bin.bz2
extra-y += vmlinux.bin.lzma
extra-y += vmlinux.bin.lzo
extra-y += vmlinux.bin.lz4
extra-y += vmlinux.bin.zst

$(obj)/vmlinux.bin.bz2: $(obj)/vmlinux.bin FORCE
	$(call if_changed,bzip2)

$(obj)/vmlinux.bin.gz: $(obj)/vmlinux.bin FORCE
	$(call if_changed,gzip)

$(obj)/vmlinux.bin.lzma: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lzma)

$(obj)/vmlinux.bin.lzo: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lzo)

$(obj)/vmlinux.bin.lz4: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lz4)

$(obj)/vmlinux.bin.zst: $(obj)/vmlinux.bin FORCE
	$(call if_changed,zst22)
