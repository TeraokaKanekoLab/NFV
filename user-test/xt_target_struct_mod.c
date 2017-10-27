#include <linux/types.h>
#include <linux/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "list.h"
#define MAX_TARGET 10

struct sk_buff {
  int value;
};

struct nf_target {
  struct list_head list;
  unsigned int (*nf_func)(struct sk_buff *skb);
  int priority; 
  char *name;
};
struct list_head target_head;

unsigned int test1(struct sk_buff *skb)
{
  printf("this is test 1\n");
  return 0;
}

unsigned int test2(struct sk_buff *skb)
{
  printf("this is test 2\n");
  return 0;
}

void init_target_list(struct list_head * i)
{
  puts("init");
  /* INIT_LIST_HEAD(i); */
  i->prev = i;
  i->next = i;
}

int add_target(unsigned int (*nf_func)(struct sk_buff *skb), int priority, char *name)
{
  struct list_head *i;
  struct nf_target *new_target = (struct nf_target *)malloc(sizeof(struct nf_target));
  if (new_target == NULL) {
    printf("failed to allocate memory");
    return -1;
  }
  new_target->nf_func = nf_func;
  new_target->priority = priority;
  new_target->name = (char *)malloc(sizeof(char) * 20);
  strcpy(new_target->name, name); 
  printf("new_target's name is %s\n", new_target->name);

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
    printf("name is %s\n", ((struct nf_target *)i)->name);
  }
}

void del_targets(void)
{
  struct list_head *i;
  int k, num;
  struct nf_target *free_target[MAX_TARGET];
  for (i = target_head.next, k = 0; i != &target_head; i = i->next, k++) {
    /* printf("deleting this entry %s\n", ((struct nf_target *)i)->name); */
    list_del(i);
    free_target[k] = (struct nf_target *)i;
    i = i->prev;
  }
  for (num = 0; num <= k; num++) {
    free(free_target[num]);
  }
}

struct list_head *search_target(unsigned int (*nf_func)(struct sk_buff *skb))
{
  struct list_head *i;
  for (i = target_head.next; i != &target_head; i = i->next) {
    if (((struct nf_target *)i)->nf_func == nf_func) {
      return i;
    }
  }
}

void del_target(unsigned int (*nf_func)(struct sk_buff *skb))
{
  struct list_head *i;
  struct nf_target *target;

  i = search_target(nf_func);
  printf("deleting target %s\n", ((struct nf_target *)i)->name);
  list_del(i);
  target = (struct nf_target *)i;
  free(target);
}

int main(void)
{
  printf("test for list\n");
  init_target_list(&target_head);
  add_target(test1, -200, "test1");
  add_target(test2, -100, "test2");
  show_targets();
  del_target(test1);
  del_target(test2);
  return 0;
}


