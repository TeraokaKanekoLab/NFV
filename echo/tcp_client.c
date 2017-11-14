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
	struct sockaddr_in skt;
	int count;
	in_port_t port = 49152;
	char *ip_buf;
	char msg_buf[100];
	char recv_buf[100];
	
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	ip_buf = "127.0.0.1";
	memset(&skt, 0, sizeof skt);
	skt.sin_family = AF_INET;
	skt.sin_port = htons(port);
	skt.sin_addr.s_addr = inet_addr(ip_buf);

	if (connect(s, (struct sockaddr *)&skt, sizeof skt) < 0) {
	  perror("connect");
	  exit(1);
	}
	
	do {
	  printf("input message to send\n");
	  fgets(msg_buf, 30, stdin);
	  
	  if ((int)(*msg_buf) == -1) {
	    if ((count = send(s, "FIN", 4 * sizeof(char), 0)) < 0) {
	      perror("send");
	      exit(1);
	    }
	  } else {
	    if ((count = send(s, msg_buf, sizeof(msg_buf), 0)) < 0) {
	      perror("send");
	      exit(1);
	    }
	  }
	  
	  if ((count= recv(s, recv_buf, sizeof(recv_buf), 0)) < 0) {
	    perror("recv");
	    exit(1);
	  }
	  printf("received message: %s\n", recv_buf);
	} while (strncmp(recv_buf, "FIN", 3) != 0);

	close(s);
	
	return 0;
}
