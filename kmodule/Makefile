objm = network_function.o xt_tcpudp.o set_rule_nat.o

obj-m += $(objm)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

