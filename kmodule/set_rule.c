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
#define NETLINK_USER 31

#define IPT_MIN_ALIGN (__alignof__(struct ipt_entry))
#define IPT_ALIGN(s) (((s) + ((IPT_MIN_ALIGN)-1)) & ~((IPT_MIN_ALIGN)-1))
#define ipt_entry_match xt_entry_match
#define ipt_entry_target xt_entry_target
#define ipt_udp xt_udp
#define ipt_tcp xt_tcp

extern __be32 in_aton(const char *str);
extern unsigned int nf1_func(struct sk_buff *skb);
extern int register_nf_target(unsigned int (*nf_func)(struct sk_buff *skb), int priority, char *name);
extern bool udp_mt(const struct sk_buff *skb, struct xt_action_param *par);
extern bool tcp_mt(const struct sk_buff *skb, struct xt_action_param *par);
extern struct list_head target_head;

struct sock *nl_sk = NULL;

int set_rule(struct net *net)
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
  e->ip.dst.s_addr = in_aton("192.168.122.168");
  e->ip.dmsk.s_addr= in_aton("192.168.122.168"); 
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
  //target = (struct ipt_entry_target *)(e->elems + size_ipt_entry_match + size_ipt_tcp);
  //target = (struct ipt_entry_target *)(e + e->target_offset);
  target = (struct ipt_entry_target *)((void *)e + size_ipt_entry + size_ipt_entry_match + size_ipt_tcp);
  printk(KERN_INFO "address of e->elems is 0x%08lx\n", (ulong)e->elems);
  printk(KERN_INFO "address of ipt_entry_target t is 0x%08lx\n", (ulong)target);
  target->u.target_size = size_ipt_entry_target;
  strcpy(target->u.user.name, "NFC");
  //(target->u.kernel.nf_targets->nf_target_num)++;
  //target->u.kernel.nf_targets->nf_target_num = 1;

  //memmove(table_base + private->hook_entry[hook], e, total_length);
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

  /* Insert nf_target struct to the list */
  return register_nf_target(nf1_func, -100, "NF1");
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

  if ((err = set_rule(net)) < 0) {
    printk(KERN_ERR "Could not register target\n");
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
  pr_info("Set_rule module is inserterd!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
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



