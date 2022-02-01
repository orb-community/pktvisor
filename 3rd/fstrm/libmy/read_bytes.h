#ifndef MY_READ_BYTES_H
#define MY_READ_BYTES_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

static inline bool
read_bytes(int fd, uint8_t *buf, size_t bytes_needed)
{
	while (bytes_needed > 0) {
		ssize_t bytes_read;

		bytes_read = read(fd, buf, bytes_needed);
		if (bytes_read == -1 && errno == EINTR)
			continue;
		else if (bytes_read <= 0)
			return false;
		bytes_needed -= bytes_read;
		buf += bytes_read;
	}
	return true;
}

#endif /* MY_READ_BYTES_H */
