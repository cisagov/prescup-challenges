// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

/* compile with: gcc -o drvctl drvctl.c -lm -Wall */

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "drvctl.h"

static int check_drvctl(drvctl_t *d, float *gt)
{
	float gx = d->ctl.gx, gy = d->ctl.gy, gz = d->ctl.gz;
	unsigned ms = d->ctl.ms;

	*gt = sqrtf(gx * gx + gy * gy + gz * gz);

	/* 0 duration means it's a test comand, drive not engaged */
	if (ms == 0)
		return 0;

	/* g limits for any non-zero length of time */
	if (ms > 0 && (fabsf(gx) > 6.0 || fabsf(gy) > 6.0 ||
		       gz < -1.5 || gz > 3.0 || *gt > 8.0))
		return -EDOM;

	/* g limits for up to 120s (2m) */
	if (ms > 120000 && (fabsf(gx) > 3.0 || fabsf(gy) > 3.0 ||
		       gz < -1.0 || gz > 2.5 || *gt > 4.0))
		return -EDOM;

	/* g limits for up to 3600s (1h) */
	if (ms > 3600000 && (fabsf(gx) > 2.0 || fabsf(gy) > 2.0 ||
		       gz < -0.5 || gz > 2.0 || *gt > 2.5))
		return -EDOM;

	/* all checks passed, drive command survivable by human crew */
	return 0;
}

static int str_to_float(const char *buf, float *res)
{
	char *ptr;

	errno = 0;
	*res = strtof(buf, &ptr);
	if (errno)
		return -errno;
	if (ptr == buf)
		return -EINVAL;
	return 0;
}

static int str_to_unsigned(const char *buf, unsigned *res)
{
	char *ptr;
	unsigned long val;

	errno = 0;
	val = strtoul(buf, &ptr, 10);
	if (errno)
		return -errno;
	if (ptr == buf)
		return -EINVAL;
	if (val > UINT_MAX)
		return -ERANGE;
	*res = (unsigned)val;
	return 0;
}

#define read_arg(num, field, func) \
	ret = func(argv[num], &d.ctl.field); \
	if (ret) { \
		fprintf(stderr, "\nInvalid " #field ": %s\n", argv[num]); \
		goto err_out; \
	}

int main(int argc, char *argv[]) {
	drvctl_t d;
	float gt;
	int i, ret = -EINVAL;;

	if (argc != 5)
		goto err_out;

	read_arg(1, gx, str_to_float);
	read_arg(2, gy, str_to_float);
	read_arg(3, gz, str_to_float);
	read_arg(4, ms, str_to_unsigned);

	ret = check_drvctl(&d, &gt);
/* DEBUG:
 */
	printf("gx=%f gy=%f gz=%f ms=%u (gt=%f, record size: %lu)\n",
		d.ctl.gx, d.ctl.gy, d.ctl.gz, d.ctl.ms, gt, sizeof(d));
/*
*/
	for (i = 0; i < 16; i++)
		printf("%02x", d.buf[i]);
	printf(" %s\n", ret ? "EX" : "OK");

	return 0;

err_out:
	fprintf(stderr, "\n\tUsage: %s gx gy gz ms\n\n", argv[0]);
	return ret;
}
