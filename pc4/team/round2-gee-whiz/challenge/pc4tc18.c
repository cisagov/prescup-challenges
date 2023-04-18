// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

/*
 *
 * pc4tc18.c: listen for tcp 32-char "requests", provide 32-char "answers"
 * (argv. is 32-char "seed" string)
 *
 * build with: 'gcc -o pc4tc18.srv pc4tc18.c -lcrypto -static -Wall'
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <openssl/md5.h>

#define PORT 31337
#define MSGSIZE MD5_DIGEST_LENGTH * 2

int server_func(int sd, const char *seed) {
	char buf[MSGSIZE * 2], err[] = "TIMEOUT\n";
	MD5_CTX mdctx;
	unsigned char sum[MD5_DIGEST_LENGTH];
	struct timeval tv;
	int i;

	/* set 5 second timeout on receiving socket */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	/* optimize for receiving an expected 32-character md5sum string */
	i = MSGSIZE;
	setsockopt(sd, SOL_SOCKET, SO_RCVLOWAT, &i, sizeof(i));
	if (recv(sd, buf, MSGSIZE, 0) != MSGSIZE) {
		send(sd, err, sizeof(err), 0);
		close(sd);
		return -1;
	}

	/* interleave received value with seed */
	memcpy(buf + MSGSIZE + MSGSIZE / 2, buf + MSGSIZE / 2, MSGSIZE / 2);
	memcpy(buf + MSGSIZE / 2, seed, MSGSIZE);

	/* compute md5sum of interleaved string */
	MD5_Init(&mdctx);
	MD5_Update(&mdctx, buf, MSGSIZE * 2);
	MD5_Final(sum, &mdctx);

	/* place ascii-printed md5sum in buf */
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(buf + 2 * i, "%02x", sum[i]);

	/* send resulting md5 string back to client */
	buf[MSGSIZE] = '\n';
	send(sd, buf, MSGSIZE + 1, 0);
	close(sd);
	return 0;
}

int main(int argc, char *argv[]) {
	int cli, srv, opt, ret;
	struct sockaddr_in6 sa;
	pid_t pid;

	if (argc < 2 || strlen(argv[1]) != MSGSIZE) {
		fprintf(stderr, "\nUsage: %s <32-char-key>\n\n", argv[0]);
		return -1;
	}

	srv = socket(AF_INET6, SOCK_STREAM, 0);
	if (srv < 0) {
		fprintf(stderr, "socket creation failed\n");
		return srv;
	}

	opt = 1;
	ret = setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret < 0) {
		fprintf(stderr, "setsockopt (reuseaddr) failed\n");
		return ret;
	}

	bzero(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(PORT);
	sa.sin6_addr = in6addr_any;

	ret = bind(srv, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "bind failed\n");
		return ret;
	}

	ret = listen(srv, 10);
	if (ret < 0) {
		fprintf(stderr, "listen failed\n");
		return ret;
	}

	for (;;) {
		cli = accept(srv, NULL, NULL);
		if (cli < 0) {
			fprintf(stderr, "accept failed\n");
			return cli;
		}

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "fork failed\n");
			return pid;
		} else if (pid == 0) {
			/* child */
			close(srv);
			return server_func(cli, argv[1]);
		}

		/* parent */
		close(cli);
		while (waitpid(-1, NULL, WNOHANG) > 0); /* reap any available */
	}

	return 0;
}
