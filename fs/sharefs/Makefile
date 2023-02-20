obj-$(CONFIG_SHARE_FS) += sharefs.o
ccflags-y += -I$(src)

sharefs-y := dentry.o file.o inode.o main.o super.o lookup.o authentication.o config.o
ccflags-y += -I$(src) -Werror -Wall
export CONFIG_SHARE_FS := m
KDIR ::= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean