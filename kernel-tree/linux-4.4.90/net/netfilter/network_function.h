#include <linux/list.h>
#include <linux/skbuff.h>

struct nf_target 
{
  struct list_head list;
  unsigned int (*nf_func)(struct sk_buff *skb);
  int priority;
  char name[20];
};


