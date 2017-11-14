#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/types.h>
#include "network_function.h"

/* Important: target_head is the head of the nf target list */
extern struct list_head target_head;

void init_target_list(struct list_head * i)
{
  INIT_LIST_HEAD(i);
}

int register_nf_target(unsigned int (*nf_func)(struct sk_buff *skb), int priority, char *name)
{
  struct list_head *i;
  struct nf_target *new_target = (struct nf_target *)kmalloc(sizeof(struct nf_target), GFP_KERNEL);
  if (new_target == NULL) {
    printk(KERN_INFO "Failed to allocate memory");
    return -1;
  }
  new_target->nf_func = nf_func;
  new_target->priority = priority;
  strcpy(new_target->name, name);
  printk(KERN_INFO "Registered target's name is %s\n", new_target->name);

  for (i = target_head.next; i != &target_head; i = i->next) {
    if (new_target->priority < ((struct nf_target *)i)->priority)
      break;
  }
  list_add(&new_target->list, i->prev);
  return 0;
}

struct list_head *search_target(unsigned int (*nf_func)(struct sk_buff *skb))
{
  struct list_head *i;
  for (i = target_head.next; i != &target_head; i = i->next) {
    if (((struct nf_target *)i)->nf_func == nf_func) {
      return i;
    }
  }
  return NULL;
}

void unregister_nf_target(unsigned int (*nf_func)(struct sk_buff *skb))
{
  struct list_head *i;
  struct nf_target *target;

  i = search_target(nf_func);
  printk(KERN_INFO "Deleting target %s\n", ((struct nf_target *)i)->name);
  list_del(i);
  target = (struct nf_target *)i;
  kfree(target);
}

void show_targets(void)
{
  struct list_head *i;
  for (i = target_head.next; i != &target_head; i = i->next) {
    printk(KERN_INFO "name is %s\n", ((struct nf_target *)i)->name);
  }
}
