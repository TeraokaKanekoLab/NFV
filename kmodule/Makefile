objm =   nf_nat_proto_common.o nf_nat_proto_udp.o nf_nat_proto_tcp.o nf_nat_proto_unknown.o nf_nat_core.o nf_nat_proto_icmp.o nf_nat_l3proto_ipv4.o iptable_nat.o xt_NAT.o

obj-m += $(objm)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

