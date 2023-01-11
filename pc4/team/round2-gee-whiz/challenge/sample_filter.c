// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

/* user_filter.c -- userspace filtering of specific tcp payloads
 *
 * ensure traffic is sent to userspace by netfilter rule, e.g.:
 *     iptables -A FORWARD -p tcp --dport 31337 -j NFQUEUE --queue-num 0 \
 *             [--queue-bypass]
 *
 * compile with:
 *     gcc -o user_filter user_filter.c -Wall -lnetfilter_queue
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <error.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

uint32_t tcp_payload_verdict(const uint8_t *buf, uint32_t len)
{
	uint8_t c;
	while (len--) {
		c = *buf++;
		printf("%c", isprint(c) ? c : '.');
	}
	printf("\n");
	if (strncmp((const char *)buf, "deadbeef", 8) == 0)
		return NF_DROP;
	return NF_ACCEPT;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	uint32_t id, verdict;
	uint8_t *p_data;
	int p_len;

	p_len = nfq_get_payload(nfad, &p_data);
	if (p_len < 0)
		return p_len;

	verdict = NF_ACCEPT;

	/* tcp data starts at offset 52;
	 * we are interested in scanning 32 characters:
	 */
	if (p_len >= 84)
		verdict = tcp_payload_verdict(p_data + 52, 32);

	ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char *argv[])
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int rv, fd;
	char buf[0x1000] __attribute__ ((aligned));

	/* setup: */
	h = nfq_open();
	if (h == NULL)
		error(1, 0, "nfq_open() error\n");
	rv = nfq_bind_pf(h, AF_INET);
	if (rv < 0)
		error(1, 0, "nfq_bind_pf() error\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (qh == NULL)
		error(1, 0, "nfq_create_queue() error\n");
	rv = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
	if (rv < 0)
		error(1, 0, "nfq_set_mode() error\n");
	fd = nfq_fd(h);

	/* main loop: */
	while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		if (nfq_handle_packet(h, buf, rv) != 0)
			break;

	/* teardown: */
	nfq_destroy_queue(qh);
	nfq_close(h);
	return 0;
}
