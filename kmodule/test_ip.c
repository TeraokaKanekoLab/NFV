#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

typedef unsigned int __u32;
union nf_inet_addr {
  __u32 ip;
};

int main(void)
{
  union nf_inet_addr u3_min;
  union nf_inet_addr u3_max;
  union nf_inet_addr u3_test;

  u3_min.ip = inet_addr("0.0.0.0");
  u3_max.ip = inet_addr("255.255.255.255");
  u3_test.ip = inet_addr("10.10.9.2");

  if (ntohl(u3_test.ip) >= ntohl(u3_min.ip)) {
    printf("bigger than min\n");
  }
  if (ntohl(u3_test.ip) <= ntohl(u3_max.ip)) {
    printf("smaller than max\n");
  }
  return 0;
}

