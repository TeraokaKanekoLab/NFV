#include <uapi/linux/pkt_cls.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <net/ip.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_l3proto.h>

static const struct xt_table nf_nat_ipv4_table = {
  .name   = "nat",
  /* .valid_hooks  = (1 << NF_INET_PRE_ROUTING) |
    (1 << NF_INET_POST_ROUTING) |
    (1 << NF_INET_LOCAL_OUT) |
    (1 << NF_INET_LOCAL_IN), */
  .valid_hooks  = (1 << NF_INET_PRE_ROUTING),
  .me   = THIS_MODULE,
  .af   = NFPROTO_IPV4,
};

extern unsigned int iptable_nat_ipv4_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct ipt_entry *ipt_next_entry(const struct ipt_entry *entry)
{
  return (void *)entry + entry->next_offset;
}

static struct ipt_entry *get_entry(const void *base, unsigned int offset)
{
    return (struct ipt_entry *)(base + offset);
}

unsigned int ipt_do_table_test2(struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
  struct xt_action_param acpar;
  const void *table_base;
  unsigned int verdict = NF_DROP;
  const struct xt_table_info *private;
  unsigned int hook = NF_INET_PRE_ROUTING;
  struct ipt_entry *e;
  struct xt_entry_target *t;

  private = table->private;
  table_base = private->entries;

  e = get_entry(table_base, private->hook_entry[hook]);
  t = ipt_get_target(e);

  acpar.hotdrop = false;

  if (!t->u.kernel.target) {
    printk(KERN_INFO "NF function is set Likely\n");
    return 0;
  } 
  if (!t->data) {
    printk(KERN_INFO "target data is not set Likely\n");
    return 0;
  }
  if (!t->u.kernel.target->target) {
    printk(KERN_INFO "target function is not set Likely\n");
    return 0;
  }

  do {
    if (!t->u.kernel.target) {
      printk(KERN_INFO "NF function\n");
    } else if (!t->u.kernel.target->target) {
      printk(KERN_INFO "Standard target\n");
    }

    if (!t->u.kernel.target) {
      printk(KERN_INFO "NF function verdict\n");
    } else {
      acpar.target = t->u.kernel.target;
      acpar.targinfo = t->data;

      verdict = t->u.kernel.target->target(skb, &acpar);
      if (verdict == XT_CONTINUE) {
        printk(KERN_INFO "continue\n");
        e = ipt_next_entry(e);
      } else {
        printk(KERN_INFO "Nat is finished\n");
        break;
      }
    }
  } while (!acpar.hotdrop);

  if (acpar.hotdrop) {
    return NF_DROP;
  } else {
    return verdict;
  }
  return NF_ACCEPT;
}

//unsigned int nf_nat_func(struct sk_buff *skb, const struct nf_hook_state *state)
//{
//  int ret = 1;
//  printk(KERN_INFO "Starting NAT...\n");
//  //ret = iptable_nat_ipv4_in(NULL, skb, state);
//  if (!state) {
//    printk(KERN_INFO " state is not found...\n");
//    return ret;
//  }
//
//  if (!state->net->ipv4.nat_table) {
//    printk(KERN_INFO " NAT table is not found...\n");
//    return ret;
//  }
////  ret = ipt_do_table(skb, state, state->net->ipv4.nat_table);
////  ret = ipt_do_table_test2(skb, state, state->net->ipv4.nat_table);
//  return ret;
//}
//EXPORT_SYMBOL(nf_nat_func);

static int __init nf_nat_init(void)
{
  printk(KERN_INFO "Kernel moduel NAT is inserted\n");

  /*
  net = current->nsproxy->net_ns;
  printk(KERN_INFO "ns_common's inum is %u (in set_rule module)\n", net->ns.inum);
  // register nat table 
  struct ipt_replace *repl;
  repl = ipt_alloc_initial_table(&nf_nat_ipv4_table);
  if (repl == NULL)
    return -ENOMEM;
  net->ipv4.nat_table = ipt_register_table(net, &nf_nat_ipv4_table, repl);
  kfree(repl); */
  return 0;
}

static void __exit nf_nat_exit(void)
{
  printk(KERN_INFO "Kernel moduel NAT is removed\n");
}

module_init(nf_nat_init);
module_exit(nf_nat_exit);

MODULE_LICENSE("GPL");


