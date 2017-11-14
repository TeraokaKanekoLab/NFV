#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main()
{
  int s;
  in_port_t port;
  socklen_t sktlen;
  int count;
  struct sockaddr_in skt;
  char *ip;
  char send_buf[100];

  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    exit(1);
  }
  port = 49152;
  ip = "0.0.0.0";
  memset(&skt, 0, sizeof skt);
  skt.sin_addr.s_addr = inet_addr(ip);
  skt.sin_port = htons(port);
  skt.sin_family = AF_INET;

  for (;;) {
  printf("enter message\n");
  fgets(send_buf, 10, stdin);

  if ((count = sendto(s, send_buf, sizeof send_buf, 0, (struct sockaddr *)&skt, sizeof(skt))) < 0) {
    perror("sendto");
    close(s);
    exit(1);
  }
  sktlen = sizeof skt;
  if ((count = recvfrom(s, send_buf, sizeof send_buf, 0, (struct sockaddr *)&skt, &sktlen)) < 0) {
    perror("recvfrom");
    close(s);
    exit(1);
  }
  printf("recevived following sentence %s\n", send_buf);
  }
    
  close(s);
  return 0;
}
