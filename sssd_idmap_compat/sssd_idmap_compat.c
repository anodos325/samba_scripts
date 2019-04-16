#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/hash.h>
#include <sys/endian.h>
#include <sys/stdint.h>
#include <sys/types.h>

#define rol32(i32, n) ((i32) << (n) | (i32) >> (32 - (n)))

uint32_t
murmur3(const void *data, size_t len, uint32_t seed)
{
	const uint8_t *bytes;
	uint32_t hash, k;
	size_t res;

	/* initialization */
	bytes = data;
	res = len;
	hash = seed;

	/* main loop */
	while (res >= 4) {
		/* replace with le32toh() if input is aligned */
		k = le32dec(bytes);
		bytes += 4;
		res -= 4;
		k *= 0xcc9e2d51;
		k = rol32(k, 15);
		k *= 0x1b873593;
		hash ^= k;
		hash = rol32(hash, 13);
		hash *= 5;
		hash += 0xe6546b64;
	}

	/* remainder */
	/* remove if input length is a multiple of 4 */
	if (res > 0) {
		k = 0;
		switch (res) {
		case 3:
			k |= bytes[2] << 16;
		case 2:
			k |= bytes[1] << 8;
		case 1:
			k |= bytes[0];
			k *= 0xcc9e2d51;
			k = rol32(k, 15);
			k *= 0x1b873593;
			hash ^= k;
			break;
		}
	}

	/* finalize */
	hash ^= (uint32_t)len;
	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;
	return (hash);
}

int
main(int argc, char *argv[])
{
	uint32_t hash_val = 0;
	int our_slice = 0;
	int max_slices = 10000; 
	int final_value = 0;

	hash_val = murmur3(argv[1], strlen(argv[1]), 0xdeadbeef); 
	our_slice = hash_val % max_slices;
	final_value = our_slice * 200000 +200000;
	printf("Idmap low range is: %d\n", final_value);

	return 0;
}
