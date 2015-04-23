obj-m := drop.o
KERNELBUILD := /lib/modules/2.6.32.12-0.7-default/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c .tmp_versions

