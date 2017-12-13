#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>

struct nf_target 
{
  struct list_head list;
  unsigned int (*nf_func)(struct sk_buff *skb, const struct nf_hook_state *state);
  int priority;
  char name[20];
};


