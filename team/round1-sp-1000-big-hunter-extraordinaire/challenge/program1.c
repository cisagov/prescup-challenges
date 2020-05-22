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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define MAX_LEN 1024

int main (int argc, char** argv)
{
  FILE *stream;
  char *filename = "/etc/redhat-release";
  char buf[MAX_LEN];

  if (argc == 2) {
    if (strlen(argv[1]) >= sizeof(filename)) {
      printf("name too long\n");
    } else {
      strcpy(filename, argv[1]);
    }
  }

  printf("File Name: %s\n", filename);

  stream = fopen(filename, "r");

  if (stream) {
    fgets(buf, MAX_LEN, stream);
    puts(buf);
    fclose(stream);
  }

  return 0;
}
