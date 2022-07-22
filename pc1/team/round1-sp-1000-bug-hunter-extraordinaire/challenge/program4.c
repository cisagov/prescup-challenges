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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#define MAXBUF 10*1024

int get_stdin(char *buf, int maxlen) {
  int i = 0;
  int n;

  while ((n = read(STDIN_FILENO, buf + i, maxlen - i)) > 0) {
    i += n;
    if (i == maxlen)
      break;
  }

  if (n != 0) {
    perror("Error reading stdin");
    exit(1);
  }

  return i;
}

int main(int argc, char **argv) {
  int sk;
  struct sockaddr_in server;
  char buf[MAXBUF];
  int buf_len;
  int n_sent;
  int n_read;

  if (argc != 3) {
    printf("Usage: %s <server name> <port number>\n", argv[0]);
    exit(0);
  }

  if ((sk = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("Problem creating socket\n");
    exit(1);
  }

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(argv[1]);
  server.sin_port = htons(atoi(argv[2]));

  buf_len = get_stdin(buf, MAXBUF);

  n_sent = sendto(sk, buf, buf_len, 0,
      (struct sockaddr*) &server, sizeof(server));

  if (n_sent < 0) {
    perror("Problem sending data");
    exit(1);
  }

  if (n_sent != buf_len) {
    printf("Sendto sent %d bytes\n", n_sent);
  }

  n_read = recvfrom(sk, buf, MAXBUF, 0, NULL, NULL);
  if (n_read < 0) {
    perror("Problem in recvfrom");
    exit(1);
  }

  if (write(STDOUT_FILENO, buf, n_read) < 0) {
    perror("Problem writing to stdout");
    exit(1);
  }
  printf("\n");

  return 0;
}
