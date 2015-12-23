AMFS_VERSION="0.1"

EXTRA_CFLAGS += -DAMFS_VERSION=\"$(AMFS_VERSION)\"

obj-$(CONFIG_AM_FS) += amfs.o

amfs-y :=	dentry.o file.o inode.o main.o super.o lookup.o mmap.o \
			amfs_h_list.o amfs_utility.o

all: user kernel

user: amfsctl.c
	gcc -Wall -Werror amfsctl.c -o amfsctl

kernel:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
