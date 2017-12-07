#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

extern unsigned int iptable_nat_ipv4_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

unsigned int nf_nat_func(struct sk_buff *skb, const struct nf_hook_state *state)
{
  int ret = 1;
  printk(KERN_INFO "Starting NAT...\n");
  ret = iptable_nat_ipv4_in(NULL, skb, state);
  return ret;
}
EXPORT_SYMBOL(nf_nat_func);

static int __init nf_nat_init(void)
{
  printk(KERN_INFO "Kernel moduel NAT is inserted\n");
  return 0;
}

static void __exit nf_nat_exit(void)
{
  printk(KERN_INFO "Kernel moduel NAT is removed\n");
}

module_init(nf_nat_init);
module_exit(nf_nat_exit);


