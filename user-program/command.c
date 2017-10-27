#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#define VAR_MAX 100 
#define VAR_SIZE 100

/* Usage: ./nf add nf_module */
int main(int argc, char *argv[])
{
  char *command[VAR_MAX];
  int i, len;
  char *module_path = (char *)malloc(sizeof(char) * 100);
  strcpy(module_path, "/home/hannah/nfv/kmodule/");
  char *temp = (char *)malloc(sizeof(char) * 30);
  char *temp1 = (char *)malloc(sizeof(char) * 30);

  for (i = 0; i < VAR_MAX; i++) {
    command[i] = (char *)malloc(sizeof(char) * VAR_SIZE);
  }

  if (strcmp(argv[1], "add") == 0) {
    command[0] = "insmod";
    if (argc >= 3) {
      temp = strcat(module_path, argv[2]);
      temp = strcat(temp, ".ko");
      strncpy(command[1], temp, strlen(temp));
    }
  } else if (strcmp(argv[1], "remove") == 0) {
    command[0] = "rmmod";
    if (argc >= 3) {
      strncpy(command[1], argv[2], strlen(argv[2]));
    }
  }

  command[2] = NULL;
  if (execvp(command[0], command) < 0) {
    perror("execvp");
  }
 
  printf("Successfuly loaded kernel module: %s\n", temp);
  return 0; 
}
