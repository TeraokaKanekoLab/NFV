#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x6b021035, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x29856e61, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x2126586c, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0x65163c07, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xeca3c761, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
	{ 0xd21bbd23, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0x45eba30f, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "68FDFC781FF04E2328858FD");
