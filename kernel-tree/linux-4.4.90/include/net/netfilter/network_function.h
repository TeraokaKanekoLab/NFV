#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/wait.h>
#include <linux/static_key.h>
#include <linux/netfilter_defs.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>

struct nf_target 
{
  struct list_head list;
  unsigned int (*nf_func)(struct sk_buff *skb, const struct nf_hook_state *state);
  int priority;
  char name[20];
};

