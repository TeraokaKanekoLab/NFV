objm = xt_target_struct_mod.o
#objm = test.o

obj-m += $(objm)

all:
	make -C /lib/modules/4.4.90-generic/build M=$(PWD) modules

clean:
	make -C /lib/modules/4.4.90-generic/build M=$(PWD) clean

