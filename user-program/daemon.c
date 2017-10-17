#include <sys/socket.h>
#include <linux/netlink.h>
#define MAX_PAYLOAD 1024

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nhl = NULL;
struct iovec iov;
int sock;
struct msghdr msg;

void main()
{
  if ((sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER)) < 0) {
    reutrn -1;
  }

  memset(&src_addr, 0, sizeof(struct sockaddr_nl));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();

  bind(sock, (struct sockaddr *)&src_addr, sizeof(struct sockaddr_nl));

  memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
  dest_addr.nl_family = AF_NETLINK;
  dest_addr.nl_pid = 0;
  dest_addr.nl_groups = 0;

  nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
  memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
  nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_flags = 0;

  strcpy(NLMSG_DATA(nlh), "Hello\n");
  
  iov.iov_base = (void *)nlh;
  iov.iov_len = nlh->nlmsg_len;
  msg.msg_name = sizeof(struct sockaddr_nl);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  printf("seding message to kernel\n");
  sendmsg(sock, &msg, 0);
  printf("waiting for message from kernel\n");

  /* Read message from kernel */
  recvmsg(sock, &msg, 0);
  printf("received message payload: %s\n", NLMSG_DATA(nlh));
  close(sock);

}



