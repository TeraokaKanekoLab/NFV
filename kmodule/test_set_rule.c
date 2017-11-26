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
#include <linux/netfilter.h>
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

int set_rule(void)
{
  unsigned int hook = NF_INET_PRE_ROUTING;
  struct xt_table *table;
  struct xt_table_info *private;
  const void *table_base;
  struct ipt_entry *e, *last_e;
  struct ipt_entry_match * match_proto;
  struct ipt_entry_target * target, *t, *t1;
  struct xt_standard_target * st_target;
  struct ipt_udp * udpinfo;
  struct ipt_tcp * tcpinfo;
  unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_ipt_udp, size_ipt_tcp, total_length, total_length1;
  int v;
  unsigned int verdict;
  int ret = 0;

  size_ipt_entry = IPT_ALIGN(sizeof(struct ipt_entry));
  size_ipt_entry_match = IPT_ALIGN(sizeof(struct ipt_entry_match));
  size_ipt_entry_target = IPT_ALIGN(sizeof(struct ipt_entry_target));
  size_ipt_udp = IPT_ALIGN(sizeof(struct ipt_udp));
  size_ipt_tcp = IPT_ALIGN(sizeof(struct ipt_tcp));

  //total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_udp + size_ipt_entry_target;
  total_length = size_ipt_entry + size_ipt_entry_match + size_ipt_tcp + size_ipt_entry_target;

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

  t = ipt_get_target(e);

  if (t->u.user.name && (strncmp(t->u.user.name, "NFC", 3) == 0)) {
    printk(KERN_INFO "sucess!!\n");
  } else {
    printk(KERN_INFO "fail\n");
  }

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
  st_target = (struct xt_standard_target *)((void *)last_e + size_ipt_entry);
  printk(KERN_INFO "address of st_target is %u\n", st_target);
  //st_target->verdict = -2;
  st_target->verdict = -1;
  st_target->target.u.target_size = size_ipt_entry_target;
  strcpy(st_target->target.u.user.name, "ACCEPT"); 

  if (t->u.user.name && (strncmp(t->u.user.name, "NFC", 3) == 0)) {
    printk(KERN_INFO "sucess!!\n");
  } else {
    printk(KERN_INFO "fail\n");
  }
  
  t1 = ipt_get_target(last_e);
  printk(KERN_INFO "address of t1 is %u\n", t1);
  v = ((struct xt_standard_target *)t1)->verdict;
  verdict = (unsigned int)(-v) - 1;
  printk(KERN_INFO "verdict is %u\n", verdict);

  if ((verdict & NF_VERDICT_MASK) == NF_DROP) {
    ret = NF_DROP_GETERR(verdict);
    if (ret == 0)
      printk(KERN_INFO "this is eperm\n");
      ret = -EPERM;
  }
  printk(KERN_INFO "ret is %d\n", ret);

  return 0;
}

static int __init nf_init(void)
{
  printk("Entering: %s\n", __FUNCTION__);
  set_rule();
  return 0;
}

static void __exit nf_exit(void)
{
  printk(KERN_INFO "exiting nf module\n");
}

module_init(nf_init);
module_exit(nf_exit);

MODULE_LICENSE("GPL");



