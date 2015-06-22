obj-m := webredirect.o
#kernel_path = /home/alex/kernel/core/linux/src/linux-3.13
kernel_path   :=/lib/modules/$(shell uname -r)/build

all: clean
	make -C $(kernel_path) M=$(PWD) modules
clean:
	make -C $(kernel_path) M=$(PWD) clean
