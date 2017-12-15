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

unsigned int nf_nat_func(struct sk_buff *skb, const struct nf_hook_state *state)
{
  int ret = 1;
  printk(KERN_INFO "Starting NAT...\n");
  //ret = iptable_nat_ipv4_in(NULL, skb, state);
  return ret;
}
EXPORT_SYMBOL(nf_nat_func);

static int __init nf_nat_init(void)
{
  struct net *net;
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


