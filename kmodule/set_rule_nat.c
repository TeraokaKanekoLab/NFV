#include <uapi/linux/pkt_cls.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <linux/user_namespace.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <uapi/linux/netfilter/xt_tcpudp.h>
#include <uapi/linux/netfilter.h>
#include <net/netfilter/nf_log.h>
#include <uapi/linux/netfilter/nf_nat.h>
#include <uapi/linux/netfilter/nf_conntrack_common.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>
#define NETLINK_USER 31

#define IPT_MIN_ALIGN (__alignof__(struct ipt_entry))
#define IPT_ALIGN(s) (((s) + ((IPT_MIN_ALIGN)-1)) & ~((IPT_MIN_ALIGN)-1))
#define ipt_entry_match xt_entry_match
#define ipt_entry_target xt_entry_target
#define ipt_udp xt_udp
#define ipt_tcp xt_tcp

extern __be32 in_aton(const char *str);
extern unsigned int nf1_func(struct sk_buff *skb);
extern int register_nf_target(unsigned int (*nf_func)(struct sk_buff *skb, const struct nf_hook_state *state), int priority, char *name);
extern bool udp_mt(const struct sk_buff *skb, struct xt_action_param *par);
extern bool tcp_mt(const struct sk_buff *skb, struct xt_action_param *par);
extern struct list_head target_head;
extern unsigned int nf_nat_func(struct sk_buff *skb, const struct nf_hook_state *state);

struct sock *nl_sk = NULL;

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

static void xt_nat_convert_range(struct nf_nat_range *dst, const struct nf_nat_ipv4_range *src)
{
  memset(&dst->min_addr, 0, sizeof(dst->min_addr));
  memset(&dst->max_addr, 0, sizeof(dst->max_addr));

  dst->flags   = src->flags;
  dst->min_addr.ip = src->min_ip;
  dst->max_addr.ip = src->max_ip;
  dst->min_proto   = src->min;
  dst->max_proto   = src->max;
}

static unsigned int xt_dnat_target_v0(struct sk_buff *skb, const struct xt_action_param *par)
{
  const struct nf_nat_ipv4_multi_range_compat *mr = par->targinfo;
  struct nf_nat_range range;
  enum ip_conntrack_info ctinfo;
  struct nf_conn *ct;

  ct = nf_ct_get(skb, &ctinfo);
  NF_CT_ASSERT(ct != NULL &&
      (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED));

  xt_nat_convert_range(&range, &mr->range[0]);
  return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

static int xt_nat_checkentry_v0(const struct xt_tgchk_param *par)
{
  const struct nf_nat_ipv4_multi_range_compat *mr = par->targinfo;

  if (mr->rangesize != 1) {
    pr_info("%s: multiple ranges no longer supported\n",
        par->target->name);
    return -EINVAL;
  }
  return 0;
}

static unsigned int nat_confirm(struct sk_buff *skb, const struct xt_action_param *par)
{
  printk(KERN_INFO "Passing through NAT NF\n");
  return 0;
}

int set_filter_rule(struct net *net)
{
  unsigned int hook = NF_INET_PRE_ROUTING;
  struct xt_table *table;
  struct xt_table_info *private;
  const void *table_base;
  struct ipt_entry *e, *last_e;
  struct ipt_entry_match * match_proto;
  struct ipt_entry_target * target;
  struct xt_standard_target * st_target;
  struct ipt_udp * udpinfo;
  struct ipt_tcp * tcpinfo;
  unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_ipt_udp, size_ipt_tcp, total_length, total_length1;

  size_ipt_entry = IPT_ALIGN(sizeof(struct ipt_entry));
  size_ipt_entry_match = IPT_ALIGN(sizeof(struct ipt_entry_match));
  size_ipt_entry_target = IPT_ALIGN(sizeof(struct ipt_entry_target));
  size_ipt_udp = IPT_ALIGN(sizeof(struct ipt_udp));
  size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));

  //total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_udp + size_ipt_entry_target;
  total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp + size_ipt_entry_target;

  table = net->ipv4.iptable_filter;
  private = table->private;
  table_base = private->entries;
 
  printk(KERN_INFO "hook number is %d\n", hook);
  printk(KERN_INFO "address of net->ipv4.iptable_filter is 0x%08lx and size is %d\n", (ulong)table, sizeof(table));
  printk(KERN_INFO "address of table_base is 0x%08lx\n", (ulong)table_base);
  printk(KERN_INFO "address of table_base + private->hook_entry[hook] is 0x%08lx\n", (ulong)(table_base + private->hook_entry[hook]));

  //e = (struct ipt_entry *)(table_base + private->hook_entry[hook]);  
  e = kmalloc(total_length, GFP_KERNEL);
  if (e == NULL) {
	  printk(KERN_ERR "Failed to allocate memory");
    return -1;
  }
  printk(KERN_INFO "address of ipt_entry e is 0x%08lx\n", (ulong)e);

  //e->target_offset = size_ipt_entry + size_ipt_entry_match + size_ipt_udp;
  e->target_offset = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp;
  e->next_offset = total_length;

  /* Set matching rules: "-s 156.145.1.3. -d 168.200.1.9" */
  e->ip.src.s_addr = in_aton("0.0.0.0");
  e->ip.smsk.s_addr= in_aton("0.0.0.0");
  //e->ip.dst.s_addr = in_aton("192.168.122.168");
  //e->ip.dst.s_addr = in_aton("10.10.9.4");
  e->ip.dst.s_addr = in_aton("0.0.0.0");
  //e->ip.dmsk.s_addr= in_aton("192.168.122.168"); 
  //e->ip.dmsk.s_addr= in_aton("10.10.9.4"); 
  e->ip.dmsk.s_addr= in_aton("0.0.0.0"); 
  e->ip.proto = IPPROTO_TCP;
  e->ip.invflags = 0;
  e->nfcache = 0;
  strcpy(e->ip.iniface, "ens3");
  strcpy(e->ip.outiface, "ens3");

  /* Set UDP protocol match rules 
  match_proto = (struct ipt_entry_match *)e->elems;
  match_proto->u.match_size = size_ipt_entry_match + size_ipt_udp;
  strcpy(match_proto->u.user.name, "udp");
  match_proto->u.kernel.match->match = udp_mt;
  printk(KERN_INFO "address of match_proto (e->elems) is 0x%08lx, udp_mt is 0x%08lx\n", (ulong)match_proto, (ulong)(match_proto->u.kernel.match->match)); */

  /* Set TCP protocol match rules */
  match_proto = (struct ipt_entry_match *)e->elems;
  match_proto->u.match_size = size_ipt_entry_match + size_ipt_tcp;
  strcpy(match_proto->u.user.name, "tcp");
  match_proto->u.kernel.match->match = tcp_mt;
  printk(KERN_INFO "address of match_proto (e->elems) is 0x%08lx, tcp_mt is 0x%08lx\n", (ulong)match_proto, (ulong)(match_proto->u.kernel.match->match)); 

	  /* UDP match extenstion 
  udpinfo = (struct ipt_udp *)match_proto->data;
  udpinfo->spts[0] = ntohs(0);
  udpinfo->spts[1] = ntohs(0xE7); 
  udpinfo->dpts[0] = ntohs(0);
  udpinfo->dpts[1] = ntohs(0x1c8); */

  /* TCP match extenstion */
  tcpinfo = (struct ipt_tcp *)match_proto->data;
  tcpinfo->spts[0] = ntohs(0);
  tcpinfo->spts[1] = ntohs(0xE7); 
  tcpinfo->dpts[0] = ntohs(0);
  tcpinfo->dpts[1] = ntohs(0x1c8);
  tcpinfo->flg_mask = 0;
  tcpinfo->flg_cmp = 0;
  tcpinfo->invflags =0;

  /* ipt_entry_target struct */
  //target = (struct ipt_entry_target *)(e->elems + size_ipt_entry_match + size_ipt_udp);
  target = (struct ipt_entry_target *)((void *)e + size_ipt_entry + size_ipt_entry_match + size_ipt_tcp);
  printk(KERN_INFO "address of e->elems is 0x%08lx\n", (ulong)e->elems);
  printk(KERN_INFO "address of ipt_entry_target t is 0x%08lx\n", (ulong)target);
  target->u.target_size = size_ipt_entry_target;
  strcpy(target->u.user.name, "NFC");

  memcpy(table_base, e, total_length);

  /* Set the last rule to stop the rule checking iteration */
  //total_length1 = size_ipt_entry + size_ipt_entry_target;
  total_length1 = size_ipt_entry + IPT_ALIGN(sizeof(struct xt_standard_target));
  last_e = kmalloc(total_length1, GFP_KERNEL);

  last_e->target_offset = size_ipt_entry;
  last_e->next_offset = total_length1;

  /* Set last matching rule (ACCEPT) */
  last_e->ip.src.s_addr = in_aton("0.0.0.0");
  last_e->ip.smsk.s_addr= in_aton("0.0.0.0"); 
  last_e->ip.dst.s_addr = in_aton("0.0.0.0");
  last_e->ip.dmsk.s_addr= in_aton("0.0.0.0"); 
  last_e->ip.proto = IPPROTO_IP;
  last_e->ip.invflags = 0;
  last_e->nfcache = 0;
  strcpy(last_e->ip.iniface, "ens3");
  strcpy(last_e->ip.outiface, "ens3");

  //target = (struct ipt_entry_target *)(last_e->elems);
  //st_target = (struct xt_standard_target *)((void *)last_e + last_e->target_offset);
  //st_target = (struct xt_standard_target *)(last_e + last_e->target_offset);
  st_target = (struct xt_standard_target *)((void *)last_e + size_ipt_entry);
  st_target->verdict = -2;
  //st_target->verdict = -3;
  //st_target->verdict = -1;
  st_target->target.u.target_size = size_ipt_entry_target;
  strcpy(st_target->target.u.user.name, "ACCEPT"); 

  memcpy(table_base + total_length, last_e, total_length1);
  printk(KERN_INFO "address of ipt_entry last_e is 0x%08lx\n", (ulong)(table_base + total_length));
  printk(KERN_INFO "address of ipt_entry_target t is 0x%08lx\n", (ulong)(table_base + total_length + last_e->target_offset));

  return 0;
}

int set_nat_rule(struct net *net)
{
  unsigned int hook = NF_INET_PRE_ROUTING;
  struct xt_table *table;
  struct xt_table_info *private;
  const void *table_base;
  struct ipt_entry *e, *last_e;
  struct ipt_entry_match * match_proto;
  struct ipt_entry_target * target;
  struct xt_standard_target * st_target;
  struct ipt_udp * udpinfo;
  struct ipt_tcp * tcpinfo;
  unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_ipt_udp, size_ipt_tcp, total_length, total_length1;
  struct xt_action_param *par;
  struct nf_nat_ipv4_multi_range_compat mr;
  struct xt_target nat_target;
  struct ipt_replace *repl;
  struct xt_table *test_table;
  
  register_nf_target(nf_nat_func, -200, "NAT");

  /* register nat table 
  printk(KERN_INFO "Going to register table in %u\n", net->ns.inum);
  repl = ipt_alloc_initial_table(&nf_nat_ipv4_table);
  if (repl == NULL) {
    printk(KERN_INFO "Could not allocate table\n");
    return -ENOMEM;
  }
  //net->ipv4.nat_table = ipt_register_table(net, &nf_nat_ipv4_table, repl);
  //the nat table is already allocated in iptable_nat.ko!!!
  if(!(net->ipv4.nat_table)) {
    printk(KERN_INFO "no member nat_table\n");
  }
  printk(KERN_INFO "address of net->ipv4.nat_table is 0x%08lx\n", net->ipv4.nat_table);
  //test_table = ipt_register_table(net, &nf_nat_ipv4_table, repl);
  printk(KERN_INFO "address of nat_table is 0x%08lx and size is %d\n", test_table, sizeof(test_table));
  kfree(repl);
  */

  table = net->ipv4.nat_table;
  private = table->private;
  table_base = private->entries;

  printk(KERN_INFO "Read the nat table\n");

#if 0 
  //printk(KERN_INFO "address of nat table_base is 0x%08lx\n", (ulong)table_base);
  //printk(KERN_INFO "address of nat table_base + private->hook_entry[hook] is 0x%08lx\n", (ulong)(table_base + private->hook_entry[hook]));

  /* target rule for nat (DST) */
  mr.range[0].min_ip = in_aton("10.10.9.4");
  mr.range[0].max_ip = in_aton("10.10.9.4");
  mr.range[0].min.all = ntohs(0x1c8);
  mr.range[0].max.all = ntohs(0x1c8);

  /* target for nat */
  strncpy(nat_target.name, "DNAT", 4);
  nat_target.revision = 0;
  //nat_target.target = xt_dnat_target_v0;
  nat_target.target = nat_confirm;
  nat_target.checkentry = xt_nat_checkentry_v0;
  nat_target.targetsize = sizeof(struct nf_nat_ipv4_multi_range_compat);
  nat_target.family = NFPROTO_IPV4;
  strncpy(nat_target.table, "nat", 3);
  //nat_target.hooks = (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_OUT);
  nat_target.hooks = (1 << NF_INET_PRE_ROUTING);

  size_ipt_entry = IPT_ALIGN(sizeof(struct ipt_entry));
  size_ipt_entry_match = IPT_ALIGN(sizeof(struct ipt_entry_match));
  size_ipt_entry_target = IPT_ALIGN(sizeof(struct ipt_entry_target));
  size_ipt_udp = IPT_ALIGN(sizeof(struct ipt_udp));
  size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));

  //total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_udp + size_ipt_entry_target;
  total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp + size_ipt_entry_target;
  
  e = kmalloc(total_length, GFP_KERNEL);
  if (e == NULL) {
	  printk(KERN_ERR "Failed to allocate memory");
    return -1;
  }

  //e->target_offset = size_ipt_entry + size_ipt_entry_match + size_ipt_udp;
  e->target_offset = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp;
  e->next_offset = total_length;

  /* Set matching rules: "-s 156.145.1.3. -d 168.200.1.9" */
  e->ip.src.s_addr = in_aton("0.0.0.0");
  e->ip.smsk.s_addr= in_aton("0.0.0.0");
  //e->ip.dst.s_addr = in_aton("192.168.122.168");
  e->ip.dst.s_addr = in_aton("10.10.9.4");
  //e->ip.dmsk.s_addr= in_aton("192.168.122.168"); 
  e->ip.dmsk.s_addr= in_aton("10.10.9.4"); 
  e->ip.proto = IPPROTO_TCP;
  e->ip.invflags = 0;
  e->nfcache = 0;
  strcpy(e->ip.iniface, "ens3");
  strcpy(e->ip.outiface, "ens3");

  /* Set UDP protocol match rules 
  match_proto = (struct ipt_entry_match *)e->elems;
  match_proto->u.match_size = size_ipt_entry_match + size_ipt_udp;
  strcpy(match_proto->u.user.name, "udp");
  match_proto->u.kernel.match->match = udp_mt;
  printk(KERN_INFO "address of match_proto (e->elems) is 0x%08lx, udp_mt is 0x%08lx\n", (ulong)match_proto, (ulong)(match_proto->u.kernel.match->match)); */

  /* Set TCP protocol match rules */
  match_proto = (struct ipt_entry_match *)e->elems;
  match_proto->u.match_size = size_ipt_entry_match + size_ipt_tcp;
  strcpy(match_proto->u.user.name, "tcp");
  match_proto->u.kernel.match->match = tcp_mt;
  printk(KERN_INFO "address of match_proto (e->elems) is 0x%08lx, tcp_mt is 0x%08lx\n", (ulong)match_proto, (ulong)(match_proto->u.kernel.match->match)); 

	  /* UDP match extenstion 
  udpinfo = (struct ipt_udp *)match_proto->data;
  udpinfo->spts[0] = ntohs(0);
  udpinfo->spts[1] = ntohs(0xE7); 
  udpinfo->dpts[0] = ntohs(0);
  udpinfo->dpts[1] = ntohs(0x1c8); */

  /* TCP match extenstion */
  tcpinfo = (struct ipt_tcp *)match_proto->data;
  tcpinfo->spts[0] = ntohs(0);
  tcpinfo->spts[1] = ntohs(0xE7); 
  tcpinfo->dpts[0] = ntohs(0x1c8);
  tcpinfo->dpts[1] = ntohs(0x1c8);
  tcpinfo->flg_mask = 0;
  tcpinfo->flg_cmp = 0;
  tcpinfo->invflags =0;

  /* ipt_entry_target struct */
  //target = (struct ipt_entry_target *)(e->elems + size_ipt_entry_match + size_ipt_udp);
  target = (struct ipt_entry_target *)((void *)e + size_ipt_entry + size_ipt_entry_match + size_ipt_tcp);
  printk(KERN_INFO "address of e->elems is 0x%08lx\n", (ulong)e->elems);
  printk(KERN_INFO "address of ipt_entry_target t is 0x%08lx\n", (ulong)target);
  target->u.target_size = size_ipt_entry_target;
  memcpy(target->data, &mr, sizeof(struct nf_nat_ipv4_multi_range_compat));
  target->u.kernel.target = &nat_target;
  //strcpy(target->u.user.name, "NFC");

  //memcpy(table_base, e, total_length);

  /* Set the last rule to stop the rule checking iteration */
  //total_length1 = size_ipt_entry + size_ipt_entry_target;
  total_length1 = size_ipt_entry + IPT_ALIGN(sizeof(struct xt_standard_target));
  last_e = kmalloc(total_length1, GFP_KERNEL);

  last_e->target_offset = size_ipt_entry;
  last_e->next_offset = total_length1;

  /* Set last matching rule (ACCEPT) */
  last_e->ip.src.s_addr = in_aton("0.0.0.0");
  last_e->ip.smsk.s_addr= in_aton("0.0.0.0"); 
  last_e->ip.dst.s_addr = in_aton("0.0.0.0");
  last_e->ip.dmsk.s_addr= in_aton("0.0.0.0"); 
  last_e->ip.proto = IPPROTO_IP;
  last_e->ip.invflags = 0;
  last_e->nfcache = 0;
  strcpy(last_e->ip.iniface, "ens3");
  strcpy(last_e->ip.outiface, "ens3");

  //st_target = (struct xt_standard_target *)((void *)last_e + last_e->target_offset);
  //st_target = (struct xt_standard_target *)(last_e + last_e->target_offset);
  st_target = (struct xt_standard_target *)((void *)last_e + size_ipt_entry);
  st_target->verdict = -2;
  //st_target->verdict = -3;
  //st_target->verdict = -1;
  st_target->target.u.target_size = size_ipt_entry_target;
  strcpy(st_target->target.u.user.name, "ACCEPT"); 

  //memcpy(table_base + total_length, last_e, total_length1);
  //printk(KERN_INFO "address of ipt_entry last_e is 0x%08lx\n", (ulong)(table_base + total_length));
  //printk(KERN_INFO "address of ipt_entry_target t is 0x%08lx\n", (ulong)(table_base + total_length + last_e->target_offset));

  /* Insert nf_target struct to the list */
  //return register_nf_target(nf_nat_func, -200, "NAT");
#endif
  return 0;
}

static void init_rule(struct sk_buff *skb)
{
  struct nlmsghdr *nlh;
  int pid;
  struct sk_buff *skb_out;
  int msg_size;
  char *msg = "I have set the rules";
  int res;
  struct net *net;
  int err;

  net = current->nsproxy->net_ns;
  printk(KERN_INFO "ns_common's inum is %u (in set_rule module)\n", net->ns.inum);

  if ((err = set_nat_rule(net)) < 0) {
    printk(KERN_ERR "Could not register nat rule\n");
  }

  if ((err = set_filter_rule(net)) < 0) {
    printk(KERN_ERR "Could not register filter rule\n");
  }
  
  msg_size = strlen(msg);

  nlh = (struct nlmsghdr *)skb->data;
  printk(KERN_INFO "Kernel module received msg payload:%s\n", (char *)nlmsg_data(nlh));
  pid = nlh->nlmsg_pid;

  if (!(skb_out = nlmsg_new(msg_size, 0))) {
    printk(KERN_ERR "Failed to allocate new skb\n");
    return;
  } 

  nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
  NETLINK_CB(skb_out).dst_group = 0;
  strncpy(nlmsg_data(nlh), msg, msg_size);

  if ((res = nlmsg_unicast(nl_sk, skb_out, pid)) < 0) {
    printk(KERN_INFO "Error while sending back to user\n");
  }
}

static int __init nf_init(void)
{
  printk("Entering: %s\n", __FUNCTION__);
  struct netlink_kernel_cfg cfg = {
    .input = init_rule,
  };
  nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
  if (!nl_sk) {
    printk(KERN_ALERT "Error crating socket\n");
    return -10;
  }
  pr_info("Set_nat_rule module is inserterd!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
  return 0;
}

static void __exit nf_exit(void)
{
  printk(KERN_INFO "exiting nf module\n");
  netlink_kernel_release(nl_sk);
}

module_init(nf_init);
module_exit(nf_exit);

MODULE_LICENSE("GPL");


