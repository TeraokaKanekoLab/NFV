#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

unsigned int nf_log_func(struct sk_buff *skb, const struct nf_hook_state *state)
{
  printk(KERN_INFO "This is LOG\n");
  return 1;
}
EXPORT_SYMBOL(nf_log_func);

static int __init nf0_tg_init(void)
{
  /* return register_nf_target(nf1_func, -100, "NF1"); */
  printk(KERN_INFO "Kernel moduel LOG is inserted\n");
  return 0;
}

static void __exit nf0_tg_exit(void)
{
  printk(KERN_INFO "Kernel moduel LOG is removed\n");
}

module_init(nf0_tg_init);
module_exit(nf0_tg_exit);


