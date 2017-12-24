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

struct nf_nat_ipv4_multi_range_compat *mr;

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
extern unsigned int nf_nat_ipv4_fn1(void *priv, struct sk_buff *skb, const struct nf_hook_state *state, struct nf_nat_ipv4_multi_range_compat *mr);
extern __be32 in_aton(const char *str);

unsigned int nf_nat_func(struct sk_buff *skb, const struct nf_hook_state *state)
{
  int ret = 1;
  printk(KERN_INFO "Starting NAT...\n");
  //ret = iptable_nat_ipv4_in(NULL, skb, state, mr);
  //ret = iptable_nat_ipv4_fn(NULL, skb, state, iptable_nat_do_chain, mr);
  //ret = ipt_do_table(skb, state, state->net->ipv4.nat_table);
  ret = nf_nat_ipv4_fn1(NULL, skb, state, mr);
  return ret;
}
EXPORT_SYMBOL(nf_nat_func);

static int __init nf_nat_init(void)
{
  printk(KERN_INFO "Kernel moduel NAT is inserted\n");
  
  mr = kmalloc(sizeof(struct nf_nat_ipv4_multi_range_compat), GFP_KERNEL);
  if (mr == NULL) {
    printk(KERN_INFO "kmalloc failed: mr is NULL\n");
    return -1;
  }

  /* target rule for nat (DST) */
  mr->range[0].min_ip = in_aton("10.10.9.4");
  mr->range[0].max_ip = in_aton("10.10.9.4");
  mr->range[0].min.all = ntohs(0xc3c8);
  mr->range[0].max.all = ntohs(0xc3c8);

  return 0;
}

static void __exit nf_nat_exit(void)
{
  printk(KERN_INFO "Kernel moduel NAT is removed\n");
}

module_init(nf_nat_init);
module_exit(nf_nat_exit);

MODULE_LICENSE("GPL");


