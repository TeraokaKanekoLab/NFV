#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

unsigned int nf1_func(struct sk_buff *skb)
{
  printk(KERN_INFO "This is NF1\n");
  //return 0;
  return 1;
}
EXPORT_SYMBOL(nf1_func);

static int __init nf1_tg_init(void)
{
  /* return register_nf_target(nf1_func, -100, "NF1"); */
  printk(KERN_INFO "Kernel moduel NF1 is inserted\n");
  return 0;
}

static void __exit nf1_tg_exit(void)
{
  printk(KERN_INFO "Kernel moduel NF1 is removed\n");
}

module_init(nf1_tg_init);
module_exit(nf1_tg_exit);


