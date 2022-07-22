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
#include <string.h>
#include <getopt.h>

int main(int argc, char *argv[]) {
  char fn[10], pat[10], temp[100];
  FILE *fp;
  int opt_e = 0;
  int opt_f = 0;

  char opt;
  while ((opt = getopt(argc, argv, "e:f:")) != -1) {
    switch (opt) {
      case 'e':
        strncpy(pat, optarg, sizeof(pat) - 1);
        pat[sizeof(pat) - 1] = '\0';
        opt_e = 1;
        break;
      case 'f':
        strncpy(fn, optarg, sizeof(fn) - 1);
        fn[sizeof(fn) - 1] = '\0';
        opt_f = 1;
        break;
      default:
        return 1;
    }
  }
  if (!opt_e) {
    strncpy(pat, "linux", sizeof(pat) - 1);
    pat[sizeof(pat) - 1] = '\0';
  }
  if (!opt_f) {
    strncpy(fn, "/etc/motd", sizeof(fn) - 1);
    fn[sizeof(fn) - 1] = '\0';
  }

  fp = fopen(fn, "r");
  if (!fp) {
    return 1;
  }
  while (fgets(temp, 200, fp)) {
    if (strstr(temp, pat)) {
      printf("%s", temp);
    }
  }
  fclose(fp);

  return 0;
}
