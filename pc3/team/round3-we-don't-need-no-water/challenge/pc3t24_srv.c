/*
 * 10/05/2021, Gabriel Somlo <glsomlo@cert.org>
 *
 * pc3t24_srv.c: listen for tcp 32-char "requests", provide 32-char "answers"
 * (argv. is 32-char "seed" string)
 *
 * build with: 'gcc -o pc3t24_srv pc3t24_srv.c -lcrypto -static -Wall'
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

/* a 128 bit data structure consisting of either 8, 16, 32, or 64 bit chunks;
 */
typedef union {
	uint8_t b[16];
	uint16_t w[8];
	uint32_t d[4];
	uint64_t q[2];
} __attribute__((packed, aligned(8))) bitstring_u_t;

/* expect str to be at least 32 characters long;
 * return 0 if buf was hex and successfully converted;
 * return -1 otherwise;
 */
int str2bsut(char *str, bitstring_u_t *bsut)
{
	int i;
	char buf[3];
	for (i = 0; i < 16; i++) {
		buf[0] = *str++;
		buf[1] = *str++;
		buf[2] = 0;
		if (!(isxdigit(buf[0]) && isxdigit(buf[1]))) {
			return -1;
		}
		bsut->b[i] = strtol(buf, NULL, 0x10);
	}
	return 0;
}

/* expect a non-NULL bsut pointer;
 * return code matching "vulnerability";
 * return 0 if not "vulnerable";
 */
int bsut_verify(bitstring_u_t *bsut)
{
	if ((uint64_t)(bsut->q[0] + bsut->q[1]) == 0) {
		return 4;
	}
	if ((uint32_t)(bsut->d[0] + bsut->d[3]) == 0) {
		return 3;
	}
	if ((uint16_t)(bsut->w[0] + bsut->w[7]) == 0) {
		return 2;
	}
	if ((uint8_t)(bsut->b[0] + bsut->b[15]) == 0) {
		return 1;
	}
	return 0;
}

int server_func(int sd, const char *seed) {
	char buf[MSGSIZE * 2], err[] = "TIMEOUT\n", fail[] = "FAIL\n";
	bitstring_u_t bsut;
	MD5_CTX mdctx;
	unsigned char sum[MD5_DIGEST_LENGTH];
	struct timeval tv;
	int i, ret = 0;

	/* set 5 second timeout on receiving socket */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	/* optimize for receiving an expected 32-character md5sum string */
	i = MSGSIZE;
	setsockopt(sd, SOL_SOCKET, SO_RCVLOWAT, &i, sizeof(i));
	if (recv(sd, buf, MSGSIZE, 0) != MSGSIZE) {
		send(sd, err, sizeof(err), 0);
		ret = -1;
		goto out;
	}

	/* check received string; if "vulnerable", signal server failure */
	if (str2bsut(buf, &bsut) == 0 && bsut_verify(&bsut) != 0) {
		send(sd, fail, sizeof(fail), 0);
		ret = -1;
		goto out;
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
out:
	close(sd);
	return ret;
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
