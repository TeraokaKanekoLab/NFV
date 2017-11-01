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
#define NETLINK_USER 31

struct sock *nl_sk_firewall = NULL;
#define PRIORITY NF_FIREWALL

unsigned int firewall(struct sk_buff *skb)
{
  printk(KERN_INFO "Excuting Firewall..\n");
  return 0;
}

static void nf_register(struct sk_buff *skb)
{
  struct nlmsghdr *nlh;
  int pid;
  struct sk_buff *skb_out;
  int msg_size;
  char *msg = "Hello from kernel";
  int res;

  printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

  if (add_target(firewall, PRIORITY, "firewall") < 0) {
    printk(KERN_ERR "Failed to add this network function in the list\n");
    return -1;
  }
  
  msg_size = strlen(msg);

  nlh = (struct nlmsghdr *)skb->data;
  printk(KERN_INFO "netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
  pid = nlh->nlmsg_pid;

  if (!(skb_out = nlmsg_new(msg_size, 0))) {
    printk(KERN_ERR "Failed to allocate new skb\n");
    return;
  } 

  nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
  NETLINK_CB(skb_out).dst_group = 0;
  strncpy(nlmsg_data(nlh), msg, msg_size);

  if ((res = nlmsg_unicast(nl_sk_firewall, skb_out, pid)) < 0) {
    printk(KERN_INFO "Error while sending back to user\n");
  }
}

static int __init nf_init(void)
{
  char *nf_name = "firewall";
  printk("Entering: %s\n", __FUNCTION__);
  struct netlink_kernel_cfg cfg = {
    .input = nf_register,
  };
  nl_sk_firewall = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
  if (!nl_sk_fireall) {
    printk(KERN_ALERT "Error crating socket\n");
    return -10;
  }
  nf_list_add(nf_name);
  return 0;
}

static void __exit nf_exit(void)
{
  printk(KERN_INFO "exiting nf module\n");
  netlink_kernel_release(nl_sk_firewall);
}

module_init(nf_init);
module_exit(nf_exit);

MODULE_LICENSE("GPL");

