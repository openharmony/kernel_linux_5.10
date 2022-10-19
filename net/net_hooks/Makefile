# SPDX-License-Identifier: GPL-2.0
#
# The Makefile file is inserted when the "linux-5.10\net\" directory
# adds a separate warehouse module. The content of the Makefile file
# of the new module is added to this file to avoid downloading the
# kernel repository separately. When the kernel repository is not downloaded,
# an error message is displayed indicating that the Makefile file of the new
# module cannot be found.

# net/newip/hooks/Makefile
ifeq ($(CONFIG_NEWIP_HOOKS),y)
obj-$(CONFIG_NET) += ../newip/hooks/
endif

# net/newip/Makefile
ifeq ($(CONFIG_NEWIP),y)
obj-$(CONFIG_NET) += ../newip/
endif
