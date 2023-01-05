#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/random.h>

/* expect str to have room for at least 33 characters (32 + trailing '\0'); */
inline static
void b2str(const uint8_t *b, char *str)
{
	int i;
	for (i = 0; i < 16; i++) {
		snprintf(str + 2*i, 3, "%02x", b[i]);
	}
}


int main(int argc, char *argv[])
{
	uint8_t __attribute__((aligned(8))) b[16];
	uint16_t *w = (uint16_t *)b;
	uint32_t *d = (uint32_t *)b;
	uint64_t *q = (uint64_t *)b;
	char str[33];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s mode\n", argv[0]);
		return -1;
	}

	/* generate a random bitstring */
	getrandom(b, 16, 0);

	/* introduce desired "vulnerability", if applicable */
	switch (atoi(argv[1])) {
	case 1:
		b[0] = ~b[15] + 1;
		break;
	case 2:
		w[0] = ~w[7] + 1;
		break;
	case 3:
		d[0] = ~d[3] + 1;
		break;
	case 4:
		q[0] = ~q[1] + 1;
		break;
	default:
		break;
	}

	b2str(b, str);
	printf("%s\n", str);
	return 0;
}
