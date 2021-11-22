/*
 * Copyright (c) 2013-2014 by Farsight Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "fstrm-private.h"

struct fstrm_unix_writer_options {
	char			*socket_path;
};

struct fstrm__unix_writer {
	bool			connected;
	int			fd;
	struct sockaddr_un	sa;
};

struct fstrm_unix_writer_options *
fstrm_unix_writer_options_init(void)
{
	return my_calloc(1, sizeof(struct fstrm_unix_writer_options));
}

void
fstrm_unix_writer_options_destroy(struct fstrm_unix_writer_options **uwopt)
{
	if (*uwopt != NULL) {
		my_free((*uwopt)->socket_path);
		my_free(*uwopt);
	}
}

void
fstrm_unix_writer_options_set_socket_path(
	struct fstrm_unix_writer_options *uwopt,
	const char *socket_path)
{
	my_free(uwopt->socket_path);
	if (socket_path != NULL)
		uwopt->socket_path = my_strdup(socket_path);
}

static fstrm_res
fstrm__unix_writer_op_open(void *obj)
{
	struct fstrm__unix_writer *w = obj;

	/* Nothing to do if the socket is already connected. */
	if (w->connected)
		return fstrm_res_success;

	/* Open an AF_UNIX socket. Request socket close-on-exec if available. */
#if defined(SOCK_CLOEXEC)
	w->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (w->fd < 0 && errno == EINVAL)
		w->fd = socket(AF_UNIX, SOCK_STREAM, 0);
#else
	w->fd = socket(AF_UNIX, SOCK_STREAM, 0);
#endif
	if (w->fd < 0)
		return fstrm_res_failure;

	/*
	 * Request close-on-exec if available. There is nothing that can be done
	 * if the F_SETFD call to fcntl() fails, so don't bother checking the
	 * return value.
	 *
	 * https://lwn.net/Articles/412131/
	 * [ Ghosts of Unix past, part 2: Conflated designs ]
	 */
#if defined(FD_CLOEXEC)
	int flags = fcntl(w->fd, F_GETFD, 0);
	if (flags != -1) {
		flags |= FD_CLOEXEC;
		(void) fcntl(w->fd, F_SETFD, flags);
	}
#endif

#if defined(SO_NOSIGPIPE)
	/*
	 * Ugh, no signals, please!
	 *
	 * https://lwn.net/Articles/414618/
	 * [ Ghosts of Unix past, part 3: Unfixable designs ]
	 */
	static const int on = 1;
	if (setsockopt(w->fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0) {
		close(w->fd);
		return fstrm_res_failure;
	}
#endif

	/* Connect the AF_UNIX socket. */
	if (connect(w->fd, (struct sockaddr *) &w->sa, sizeof(w->sa)) < 0) {
		close(w->fd);
		return fstrm_res_failure;
	}

	w->connected = true;
	return fstrm_res_success;
}

static fstrm_res
fstrm__unix_writer_op_close(void *obj)
{
	struct fstrm__unix_writer *w = obj;
	if (w->connected) {
		w->connected = false;
		if (close(w->fd) != 0)
			return fstrm_res_failure;
		return fstrm_res_success;
	}
	return fstrm_res_failure;
}

static fstrm_res
fstrm__unix_writer_op_read(void *obj, void *buf, size_t nbytes)
{
	struct fstrm__unix_writer *w = obj;
	if (likely(w->connected)) {
		if (read_bytes(w->fd, buf, nbytes))
			return fstrm_res_success;
	}
	return fstrm_res_failure;
}

static fstrm_res
fstrm__unix_writer_op_write(void *obj, const struct iovec *iov, int iovcnt)
{
	struct fstrm__unix_writer *w = obj;

	size_t nbytes = 0;
	ssize_t written = 0;
	int cur = 0;
	struct msghdr msg = {
		.msg_iov = (struct iovec *) /* Grr! */ iov,
		.msg_iovlen = iovcnt,
	};

	if (unlikely(!w->connected))
		return fstrm_res_failure;

	for (int i = 0; i < iovcnt; i++)
		nbytes += iov[i].iov_len;

	for (;;) {
		do {
			written = sendmsg(w->fd, &msg, MSG_NOSIGNAL);
		} while (written == -1 && errno == EINTR);
		if (written == -1)
			return fstrm_res_failure;
		if (cur == 0 && written == (ssize_t) nbytes)
			return fstrm_res_success;

		while (written >= (ssize_t) msg.msg_iov[cur].iov_len)
		       written -= msg.msg_iov[cur++].iov_len;

		if (cur == iovcnt)
			return fstrm_res_success;

		msg.msg_iov[cur].iov_base = (void *)
			((char *) msg.msg_iov[cur].iov_base + written);
		msg.msg_iov[cur].iov_len -= written;
	}
}

static fstrm_res
fstrm__unix_writer_op_destroy(void *obj)
{
	struct fstrm__unix_writer *w = obj;
	my_free(w);
	return fstrm_res_success;
}

struct fstrm_writer *
fstrm_unix_writer_init(const struct fstrm_unix_writer_options *uwopt,
		       const struct fstrm_writer_options *wopt)
{
	struct fstrm_rdwr *rdwr;
	struct fstrm__unix_writer *uw;

	if (uwopt->socket_path == NULL)
		return NULL;

	if (strlen(uwopt->socket_path) + 1 > sizeof(uw->sa.sun_path))
		return NULL;

	uw = my_calloc(1, sizeof(*uw));
	uw->sa.sun_family = AF_UNIX;
	strncpy(uw->sa.sun_path, uwopt->socket_path, sizeof(uw->sa.sun_path) - 1);

	rdwr = fstrm_rdwr_init(uw);
	fstrm_rdwr_set_destroy(rdwr, fstrm__unix_writer_op_destroy);
	fstrm_rdwr_set_open(rdwr, fstrm__unix_writer_op_open);
	fstrm_rdwr_set_close(rdwr, fstrm__unix_writer_op_close);
	fstrm_rdwr_set_read(rdwr, fstrm__unix_writer_op_read);
	fstrm_rdwr_set_write(rdwr, fstrm__unix_writer_op_write);
	return fstrm_writer_init(wopt, &rdwr);
}
