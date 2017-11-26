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

unsigned int nf_iterate(struct list_head *head)
{
  unsigned int verdict;
  struct nf_hook_ops **elemp;

  *elemp = list_entry_rcu(head, struct nf_hook_ops, list);

  list_for_each_entry_continue_rcu((*elemp), head, list) {
    /*if (NF_IP_PRI_FILTER > (*elemp)->priority)
      continue; */

repeat:
    verdict = NF_ACCEPT;
    if (verdict != NF_ACCEPT) {
      if (verdict != NF_REPEAT)
        return verdict;
      goto repeat;
    }
    //return NF_ACCEPT;
  }
  return NF_ACCEPT;
}

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
  struct list_head *hook_list;
  unsigned int pf = NFPROTO_IPV4;
  unsigned int priority = NF_IP_PRI_FILTER;
  struct list_head *i;
  unsigned int last_verdict;

  size_ipt_entry = IPT_ALIGN(sizeof(struct ipt_entry));
  size_ipt_entry_match = IPT_ALIGN(sizeof(struct ipt_entry_match));
  size_ipt_entry_target = IPT_ALIGN(sizeof(struct ipt_entry_target));
  size_ipt_udp = IPT_ALIGN(sizeof(struct ipt_udp));
  size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));

  total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp + size_ipt_entry_target;

  table = net->ipv4.iptable_filter;
  private = table->private;
  table_base = private->entries;

  hook_list = &net->nf.hooks[pf][hook];

  for (i = hook_list->next; i != hook_list; i = i->next) {
    printk(KERN_INFO "loop\n");
  }

  printk(KERN_INFO "hook number is %d\n", hook);
  printk(KERN_INFO "address of table_base is 0x%08lx\n", (ulong)table_base);
  printk(KERN_INFO "address of table_base + private->hook_entry[hook] is 0x%08lx\n", (ulong)(table_base + private->hook_entry[hook]));

  last_verdict = nf_iterate(hook_list);
  printk(KERN_INFO "last_verdict is %u\n", last_verdict);

  return 0;
}

static void init_rule(struct sk_buff *skb)
{
  struct nlmsghdr *nlh;
  int pid;
  struct sk_buff *skb_out;
  int msg_size;
  char *msg = "I have checked";
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



