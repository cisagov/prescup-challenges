// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

/*
 * 09/19/2022, Gabriel Somlo <glsomlo@cert.org>
 *
 * seelax.c: listen for tcp 32-char "requests", provide 32-char "answers"
 *
 * build with: 'gcc -o seelax.srv seelax.c -lcrypto -Wall'
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/wait.h>

#define PORT 31337
#define MSGSIZE MD5_DIGEST_LENGTH * 2
#define CODEXSIZE SHA_DIGEST_LENGTH * 2

#define NMAPS 29

/* sha1 checksum of each map file */
unsigned char map_sha[NMAPS][SHA_DIGEST_LENGTH];
/* scrambled EncryptedCodexC data */
unsigned char ScrambledCodex[SHA_DIGEST_LENGTH];
/* error message string */
char ld_err_str[256];
/* "dongle-check" status */
int load_status = 0;

#define PR_ERR(...) snprintf(ld_err_str, sizeof(ld_err_str), __VA_ARGS__)

/* load and hash floorplan maps */
int load_map(int map_num) {
	int fd;
	ssize_t n;
	char buf[256], fname[32];
	SHA_CTX ctx;

	snprintf(fname, 32, "/mnt/maps/floorplans/fp_%d.png", map_num + 1);
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		PR_ERR("can't open map (%s): %s\n", fname, strerror(errno));
		return -errno;
	}

	SHA1_Init(&ctx);
	while ((n = read(fd, buf, 256)) != 0)
		SHA1_Update(&ctx, buf, n);
	close(fd);
	SHA1_Final(map_sha[map_num], &ctx);

	return 0;
}

/* load the *scrambled* EncryptedCodexC from disk */
int load_scrambled_codex(void) {
	int fd, i;
	char buf[3];
	char *endptr;
	ssize_t n;

	fd = open("/mnt/maps/etc/datafile.txt", O_RDONLY);
	if (fd < 0) {
		PR_ERR("can't open data file: %s\n", strerror(errno));
		return -errno;
	}

	buf[2] = '\0';
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		n = read(fd, buf, 2);
		if (n != 2) {
			PR_ERR("data file too short (%d)\n", i);
			return -ESPIPE;
		}
		ScrambledCodex[i] = strtol(buf, &endptr, 0x10);
		if (*endptr != '\0') {
			PR_ERR("invalid data byte (%d)\n", i);
			return -EINVAL;
		}
	}

	close(fd);

	return 0;
}

int server_func(int sd) {
	char buf[MSGSIZE + CODEXSIZE], EncryptedCodexC[CODEXSIZE + 1];
	char timeout[] = "TIMEOUT\n";
	char unscramble[] = "Unscrambling EncryptedCodexC...\n";
	unsigned char sum[MD5_DIGEST_LENGTH];
	MD5_CTX mdctx;
	struct timeval tv;
	int i, ret = -1;

	/* set 5 second timeout on receiving socket */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	/* optimize for receiving an expected 32-character md5sum string */
	i = MSGSIZE;
	setsockopt(sd, SOL_SOCKET, SO_RCVLOWAT, &i, sizeof(i));
	if (recv(sd, buf, MSGSIZE, 0) != MSGSIZE) {
		send(sd, timeout, sizeof(timeout), 0);
		goto out;
	}

	/* respond with error if maps & codex not loaded */
	if (!load_status) {
		send(sd, ld_err_str, strlen(ld_err_str)+1, 0);
		goto out;
	}

	/* unscramble the codex */
	send(sd, unscramble, sizeof(unscramble), 0);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(EncryptedCodexC + 2 * i, "%02x",
			ScrambledCodex[i] ^ map_sha[10][i]);

	/* interleave received value with EncryptedCodexC */
	memcpy(buf + MSGSIZE / 2 + CODEXSIZE, buf + MSGSIZE / 2, MSGSIZE / 2);
	memcpy(buf + MSGSIZE / 2, EncryptedCodexC, CODEXSIZE);

	/* compute md5sum of interleaved string */
	MD5_Init(&mdctx);
	MD5_Update(&mdctx, buf, MSGSIZE * 2);
	MD5_Final(sum, &mdctx);

	/* place ascii-printed md5sum in buf */
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(buf + 2 * i, "%02x", sum[i]);

	/* send resulting md5 string back to client */
	buf[MSGSIZE] = '\n';
	buf[MSGSIZE + 1] = '\0';
	send(sd, buf, MSGSIZE + 1, 0);
	ret = 0;

out:
	close(sd);
	return ret;
}

int main(int argc, char *argv[]) {
	int cli, srv, opt, ret, i;
	struct sockaddr_in6 sa;
	pid_t pid;

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

		/* check & retry (if needed) map load status before serving */
		if (!load_status) {
			for (i = 0; i < NMAPS; i++) {
				ret = load_map(i);
				if (ret < 0)
					break;
			}
			if (ret == 0)
				ret = load_scrambled_codex();
			if (ret == 0)
				load_status = 1;
		}

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "fork failed\n");
			return pid;
		} else if (pid == 0) {
			/* child */
			close(srv);
			return server_func(cli);
		}

		/* parent */
		close(cli);
		while (waitpid(-1, NULL, WNOHANG) > 0); /* reap any available */
	}

	return 0;
}
