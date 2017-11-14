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
  int s, s1;
  struct sockaddr_in myskt;
  struct sockaddr_in skt;
  socklen_t sktlen;
  char buf[100];
  char msg[6] = "hello\n";
  int count;
  
  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    exit(1);
  }
  myskt.sin_port = htons(49152);
  myskt.sin_addr.s_addr = htonl(INADDR_ANY);
  if ((bind(s, (struct sockaddr *)&myskt, sizeof myskt)) < 0) {
    perror("bind");
    exit(1);
  }
  if (listen(s, 5) < 0) {
    perror("listen");
    exit(1);
  }
  sktlen = sizeof skt;
  
  for (;;) {
    if ((s1 = accept(s, (struct sockaddr *)&skt, &sktlen)) < 0) {
      perror("accept");
      exit(1);
    }
    
    printf("client's IP address: %s\n", inet_ntoa(skt.sin_addr));
    printf("client's port number: %d\n", ntohs(skt.sin_port));
    
    for (;;) {
      if ((count = recv(s1, buf, sizeof(buf), 0)) < 0) {
	perror("recv");
	exit(1);
      }
      printf("received message: %s\n", buf);
      if (strcmp(buf, "FIN") == 0) {
	close(s1);
	break;
      }
      if ((count = send(s1, buf, sizeof(buf), 0)) < 0) {
	perror("send");
	exit(1);
      }
    }
  }
  close(s);
  return 0;
}
