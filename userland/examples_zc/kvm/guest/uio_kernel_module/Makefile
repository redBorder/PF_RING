# obj-m is a list of what kernel modules to build.  The .o and other
# objects will be automatically built from the corresponding .c file -
# no need to list the source files explicitly.

obj-m := uio_ivshmem.o 

# KDIR is the location of the kernel source.  The current standard is
# to link to the associated source tree from the directory containing
# the compiled modules.
KERNEL_DEVEL_PACKAGE= $(shell rpm -qa | grep kernel-devel)
BUILD_KERNEL= $(shell rpm -q --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}' $(KERNEL_DEVEL_PACKAGE))
KDIR  := /lib/modules/$(BUILD_KERNEL)/build

# PWD is the current working directory and the location of our module
# source files.
PWD   := $(shell pwd)

# default is the default make target.  The rule here says to run make
# with a working directory of the directory containing the kernel
# source and compile only the modules in the PWD (local) directory.
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	cp uio_ivshmem.ko /lib/modules/$(BUILD_KERNEL)/kernel/drivers/uio/

clean:
	rm -f *.ko *.o uio_ivshmem.mod.c Module.symvers
