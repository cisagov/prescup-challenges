/*
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080

#define MAXDATASIZE 100

int main(int argc, char *argv[])
{
  int sockfd, numbytes;
  char buf[MAXDATASIZE];
  struct sockaddr_in their_addr;
  char *sendbuf;

  if (argc != 3) {
    fprintf(stderr, "usage: hostname filename\n");
    exit(1);
  }

  sendbuf = malloc(sizeof(argv[2]));
  strncpy(sendbuf, argv[2], strlen(argv[2]));
  sendbuf[strlen(argv[2])] = '\0';

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  their_addr.sin_family = AF_INET;
  their_addr.sin_port = htons(PORT);
  their_addr.sin_addr.s_addr = inet_addr(argv[1]);
  bzero(&(their_addr.sin_zero), 8);

  if (connect(sockfd, (struct sockaddr *)&their_addr, \
        sizeof(struct sockaddr)) == -1) {
    perror("connect");
    exit(1);
  }
  if (send(sockfd, sendbuf, strlen(sendbuf), 0) == -1) {
    perror("send");
    exit(1);
  }
  if ((numbytes = recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
    perror("recv");
    exit(1);
  }

  buf[numbytes] = '\0';

  puts(buf);

  close(sockfd);

  return 0;
}
