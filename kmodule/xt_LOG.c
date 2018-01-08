#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <uapi/linux/time.h>
#include <uapi/linux/udp.h>

extern __be32 in_aton(const char *str);

unsigned int dns1, dns2, ntp1, ntp2;
unsigned int dns1_th = 83333, ntp1_th = 83333;
struct timespec start_time_dns, start_time_ntp;
unsigned int next_verdict_dns, next_verdict_ntp, verdict_dns, verdict_ntp;
__be32 ipaddr1;
__be32 ipaddr2;


unsigned int nf_log_func(struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct udphdr *hdr;
  __u8 proto;
  __be16 udp_sport, udp_dport;
  __be16 udp_proto_dns, udp_proto_ntp;
  struct timespec curr_time, diff;
  unsigned int hdroff;

  //printk(KERN_INFO "This is LOG\n");

  /* UDP protocol number of DNS, NTP */
  udp_proto_dns = ntohs(0x35);
  udp_proto_ntp = ntohs(0x7b);

  iph = (void *)skb->data;
  proto = iph->protocol;
  hdroff = iph->ihl * 4;
  hdr = (struct udphdr *)(skb->data + hdroff);

  udp_sport = hdr->source;
  udp_dport = hdr->dest;

  /* If UDP protocol */
  if (proto == 0x11) { 
    getnstimeofday(&curr_time);
    //printk(KERN_INFO "curr_time: %ld", curr_time.tv_sec);
    if (udp_dport == udp_proto_dns) {
      //printk(KERN_INFO "UDP/DNS\n");
      if (iph->saddr == ipaddr1) {
        dns1++;
        //diff = timespec_sub(curr_time, start_time_dns);
        diff.tv_sec = curr_time.tv_sec - start_time_dns.tv_sec;
        if (diff.tv_sec < 10) {
          if (dns1 > dns1_th) {
            //printk(KERN_INFO "next_verdict_dns == NF_DROP\n");
            next_verdict_dns = NF_DROP;
          } else {
            //printk(KERN_INFO "next_verdict_dns == NF_ACCEPT\n");
            next_verdict_dns = NF_ACCEPT;
          }
          return verdict_dns;
        } else {
          getnstimeofday(&start_time_dns);
          verdict_dns = next_verdict_dns;
          dns1 = 0;
          return verdict_dns;
        }
      }
    } else if (udp_dport == udp_proto_ntp) {
      //printk(KERN_INFO "UDP/NTP\n");
      if (iph->saddr == ipaddr1) {
        ntp1++;
        diff = timespec_sub(curr_time, start_time_ntp);
        if (diff.tv_sec < 10) {
          if (ntp1 > ntp1_th) {
            //printk(KERN_INFO "next_verdict_ntp == NF_DROP\n");
            next_verdict_ntp = NF_DROP;
          } else {
            //printk(KERN_INFO "next_verdict_dns == NF_ACCEPT\n");
            next_verdict_ntp = NF_ACCEPT;
          }
          return verdict_ntp;
        } else {
          getnstimeofday(&start_time_ntp);
          verdict_ntp = next_verdict_ntp;
          ntp1 = 0;
          return verdict_ntp;
        }
      }
    }
  }

  return 1;
}
EXPORT_SYMBOL(nf_log_func);

static int __init nf0_tg_init(void)
{
  /* return register_nf_target(nf1_func, -100, "NF1"); */
  printk(KERN_INFO "Kernel moduel LOG is inserted\n");

  /* Source addresses */
  ipaddr1 = in_aton("10.10.9.1");
  ipaddr2 = in_aton("10.10.9.9");

  /* Initialize counters to 0 */
  dns1 = 0;
  dns2 = 0;
  ntp1 = 0;
  ntp2 = 0;

  /* Initialize verdict to NF_ACCEPT */
  next_verdict_dns = NF_ACCEPT;
  next_verdict_ntp = NF_ACCEPT;
  verdict_dns = NF_ACCEPT;
  verdict_ntp = NF_ACCEPT;

  /* Initialize start_time */
  getnstimeofday(&start_time_dns);
  getnstimeofday(&start_time_ntp);

  printk(KERN_INFO "start_time_dns: %ld", start_time_dns.tv_sec);
  return 0;
}

static void __exit nf0_tg_exit(void)
{
  printk(KERN_INFO "Kernel moduel LOG is removed\n");
}

module_init(nf0_tg_init);
module_exit(nf0_tg_exit);


