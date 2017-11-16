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

extern __be32 in_aton(const char *str);
extern unsigned int nf1_func(struct sk_buff *skb);
extern int register_nf_target(unsigned int (*nf_func)(struct sk_buff *skb), int priority, char *name);
extern bool udp_mt(const struct sk_buff *skb, struct xt_action_param *par);
extern struct list_head target_head;

struct sock *nl_sk = NULL;

int set_rule1(struct net *net)
{
  unsigned int hook = NF_INET_PRE_ROUTING;
  struct xt_table *table;
  struct xt_table_info *private;
  const void *table_base;
  struct ipt_entry *e, *old_e;
  struct ipt_entry_match * match_proto;
  struct ipt_entry_target * target;
  struct ipt_udp * udpinfo;
  unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target,size_ipt_udp, total_length, total_length1, target_offset, next_offset;

  size_ipt_entry = IPT_ALIGN(sizeof(struct ipt_entry));
  size_ipt_entry_match = IPT_ALIGN(sizeof(struct ipt_entry_match));
  size_ipt_entry_target = IPT_ALIGN(sizeof(struct ipt_entry_target));
  size_ipt_udp = IPT_ALIGN(sizeof(struct ipt_udp));

  table = net->ipv4.iptable_filter;
  private = table->private;
  table_base = private->entries;

  old_e = (struct ipt_entry *)(table_base + private->hook_entry[hook]);  
  target_offset = old_e->target_offset;
  next_offset = old_e->next_offset;

  total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_udp + size_ipt_entry_target;
   
  printk(KERN_INFO "hook number is %d\n", hook);
  printk(KERN_INFO "address of table_base is 0x%08lx\n", (ulong)table_base);
  printk(KERN_INFO "address of table_base + private->hook_entry[hook] is 0x%08lx\n", (ulong)(table_base + private->hook_entry[hook]));

  e = kmalloc(total_length, GFP_KERNEL);
  if (e == NULL) {
	  printk(KERN_ERR "Failed to allocate memory");
    return -1;
  }
  printk(KERN_INFO "address of ipt_entry e is 0x%08lx\n", (ulong)e);

  e->target_offset = size_ipt_entry + size_ipt_entry_match + size_ipt_udp;
  e->next_offset = total_length;

  /* Set matching rules: "-s 156.145.1.3. -d 168.200.1.9" */
  /*
  e->ip.src.s_addr = in_aton("192.168.1.1");
  e->ip.smsk.s_addr= in_aton("255.255.255.0"); */
  e->ip.dst.s_addr = in_aton("192.168.122.200");
  e->ip.dmsk.s_addr= in_aton("255.255.255.0"); 
  e->ip.proto = IPPROTO_UDP;
  e->nfcache = 0;
  strcpy(e->ip.iniface, "ens3");

  /* Set protocol-specific match rules */
  match_proto = (struct ipt_entry_match *)e->elems;
  match_proto->u.match_size = size_ipt_entry_match + size_ipt_udp;
  strcpy(match_proto->u.user.name, "udp");

  match_proto->u.kernel.match->match = udp_mt;

  /* UDP match extenstion */
  udpinfo = (struct ipt_udp *)match_proto->data;
  /*
  udpinfo->spts[0] = ntohs(0);
  udpinfo->spts[1] = ntohs(0xE7); */
  udpinfo->dpts[0] = ntohs(0);
  udpinfo->dpts[1] = ntohs(0x1c8);

  /* ipt_entry_target struct */
  target = (struct ipt_entry_target *)(e->elems + size_ipt_entry_match + size_ipt_udp);
  printk(KERN_INFO "address of ipt_entry_target t is 0x%08lx\n", (ulong)target);
  target->u.target_size = size_ipt_entry_target;
  //(target->u.kernel.nf_targets->nf_target_num)++;
  //target->u.kernel.nf_targets->nf_target_num = 1;

  memmove(table_base + total_length, old_e, next_offset);
  memmove(table_base, e, total_length);

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
  printk(KERN_INFO "ns_common's inum is %u (in set_rule1 module)\n", net->ns.inum);

  if ((err = set_rule1(net)) < 0) {
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

