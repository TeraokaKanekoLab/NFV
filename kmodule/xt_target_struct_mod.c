#include <uapi/linux/pkt_cls.h>
#include <linux/netlink.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>

struct nf_target {
  struct list_head list;
  unsigned int (*nf_func)(struct sk_buff *skb);
  int priority; 
  char *name;
};

struct list_head target_head;

unsigned int test1(struct sk_buff *skb)
{
  printk(KERN_INFO "this is test 1\n");
  return 0;
}

unsigned int test2(struct sk_buff *skb)
{
  printk(KERN_INFO "this is test 2\n");
  return 0;
}

void init_target_list(struct list_head * i)
{
  INIT_LIST_HEAD(i);
}

int add_target(unsigned int (*nf_func)(struct sk_buff *skb), int priority, char *name)
{
  struct list_head *i;
  struct nf_target *new_target = (struct nf_target *)kmalloc(sizeof(struct nf_target), GFP_USER);
  if (new_target == NULL) {
    printk(KERN_ERR "failed to allocate memory");
    return -1;
  }
  new_target->nf_func = nf_func;
  new_target->priority = priority;
  strcpy(new_target->name, name);

  /* if there is only the first element "target_head", this for sentence doesn't loop, so only list_add will be excuted */
  for (i = target_head.next; i != &target_head; i = i->next) {
    if (new_target->priority < ((struct nf_target *)i)->priority)
      break;
  }
  list_add(&new_target->list, i->prev);
  return 0;
}

void show_targets(void)
{
  struct list_head *i;
  for (i = target_head.next; i != &target_head; i = i->next) {
    printk(KERN_INFO "name is %s\n", ((struct nf_target *)i)->name);
  }
}

static int __init add_init(void)
{
  init_target_list(&target_head);
  add_target(test1, -200, "test1");
  add_target(test2, -100, "test2");
  show_targets();
  return 0;
}

static void __exit add_exit(void)
{
  struct list_head *i;
  for (i = target_head.next; i != &target_head; i = i->next) {
    printk(KERN_INFO "deleting this entry %s\n", ((struct nf_target *)i)->name);
    list_del(i);
	kfree(i);
  }
}

module_init(add_init);
module_exit(add_exit);
