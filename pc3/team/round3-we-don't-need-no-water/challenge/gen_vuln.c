#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/random.h>

/* a 128 bit data structure consisting of either 8, 16, 32, or 64 bit chunks; */
typedef union {
	uint8_t b[16];
	uint16_t w[8];
	uint32_t d[4];
	uint64_t q[2];
} __attribute__((packed, aligned(8))) bitstring_u_t;

/* expect str to have room for at least 33 characters (32 + trailing '\0'); */
inline static
void bsut2str(const bitstring_u_t *bsut, char *str)
{
	int i;
	for (i = 0; i < 16; i++) {
		snprintf(str + 2*i, 3, "%02x", bsut->b[i]);
	}
}

int main(int argc, char *argv[])
{
	bitstring_u_t bsut;
	char str[33];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s mode\n", argv[0]);
		return -1;
	}

	/* generate a random bitstring */
	getrandom(&bsut, sizeof(bsut), 0);

	/* introduce desired "vulnerability", if applicable */
	switch (atoi(argv[1])) {
	case 1:
		bsut.b[0] = ~bsut.b[15] + 1;
		break;
	case 2:
		bsut.w[0] = ~bsut.w[7] + 1;
		break;
	case 3:
		bsut.d[0] = ~bsut.d[3] + 1;
		break;
	case 4:
		bsut.q[0] = ~bsut.q[1] + 1;
		break;
	default:
		break;
	}

	bsut2str(&bsut, str);
	printf("%s\n", str);
	return 0;
}
