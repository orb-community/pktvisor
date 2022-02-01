/*
 * Copyright (c) 2013-2014, 2018 by Farsight Security, Inc.
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

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include "fstrm-private.h"

struct fstrm_tcp_writer_options {
	char			*socket_address;
	char			*socket_port;
};

struct fstrm__tcp_writer {
	bool			connected;
	int			fd;
	struct sockaddr_storage	ss;
	socklen_t		ss_len;
};

struct fstrm_tcp_writer_options *
fstrm_tcp_writer_options_init(void)
{
	return my_calloc(1, sizeof(struct fstrm_tcp_writer_options));
}

void
fstrm_tcp_writer_options_destroy(struct fstrm_tcp_writer_options **twopt)
{
	if (*twopt != NULL) {
		my_free((*twopt)->socket_address);
		my_free((*twopt)->socket_port);
		my_free(*twopt);
	}
}

void
fstrm_tcp_writer_options_set_socket_address(
	struct fstrm_tcp_writer_options *twopt,
	const char *socket_address)
{
	my_free(twopt->socket_address);
	if (socket_address != NULL)
		twopt->socket_address = my_strdup(socket_address);
}

void
fstrm_tcp_writer_options_set_socket_port(
	struct fstrm_tcp_writer_options *twopt,
	const char *socket_port)
{
	my_free(twopt->socket_port);
	if (socket_port != NULL)
		twopt->socket_port = my_strdup(socket_port);
}

static fstrm_res
fstrm__tcp_writer_op_open(void *obj)
{
	struct fstrm__tcp_writer *w = obj;

	/* Nothing to do if the socket is already connected. */
	if (w->connected)
		return fstrm_res_success;

	/* Open an Internet socket. Request socket close-on-exec if available. */
#if defined(SOCK_CLOEXEC)
	w->fd = socket(w->ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (w->fd < 0 && errno == EINVAL)
		w->fd = socket(w->ss.ss_family, SOCK_STREAM, 0);
#else
	w->fd = socket(w->ss.ss_family, SOCK_STREAM, 0);
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

	/* Connect the TCP socket. */
	if (connect(w->fd, (struct sockaddr *) &w->ss, w->ss_len) < 0) {
		close(w->fd);
		return fstrm_res_failure;
	}

	w->connected = true;
	return fstrm_res_success;
}

static fstrm_res
fstrm__tcp_writer_op_close(void *obj)
{
	struct fstrm__tcp_writer *w = obj;
	if (w->connected) {
		w->connected = false;
		if (close(w->fd) != 0)
			return fstrm_res_failure;
		return fstrm_res_success;
	}
	return fstrm_res_failure;
}

static fstrm_res
fstrm__tcp_writer_op_read(void *obj, void *buf, size_t nbytes)
{
	struct fstrm__tcp_writer *w = obj;
	if (likely(w->connected)) {
		if (read_bytes(w->fd, buf, nbytes))
			return fstrm_res_success;
	}
	return fstrm_res_failure;
}

static fstrm_res
fstrm__tcp_writer_op_write(void *obj, const struct iovec *iov, int iovcnt)
{
	struct fstrm__tcp_writer *w = obj;

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
fstrm__tcp_writer_op_destroy(void *obj)
{
	struct fstrm__tcp_writer *w = obj;
	my_free(w);
	return fstrm_res_success;
}

static fstrm_res
fstrm__tcp_writer_fill_socket_port(struct fstrm__tcp_writer *w,
				   const struct fstrm_tcp_writer_options *twopt)
{
	uint64_t port = 0;
	char *endptr = NULL;

	port = strtoul(twopt->socket_port, &endptr, 0);
	if (*endptr != '\0' || port > UINT16_MAX) {
		return fstrm_res_failure;
	}

	if (w->ss.ss_family == AF_INET) {
		struct sockaddr_in *sai = (struct sockaddr_in *) &w->ss;
		sai->sin_port = htons(port);
		return fstrm_res_success;
	} else if (w->ss.ss_family == AF_INET6) {
		struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) &w->ss;
		sai6->sin6_port = htons(port);
		return fstrm_res_success;
	}

	return fstrm_res_failure;
}

static fstrm_res
fstrm__tcp_writer_fill_socket_address(struct fstrm__tcp_writer *w,
				      const struct fstrm_tcp_writer_options *twopt)
{
	struct sockaddr_in *sai = (struct sockaddr_in *) &w->ss;
	struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) &w->ss;

	if (inet_pton(AF_INET, twopt->socket_address, &sai->sin_addr) == 1) {
		w->ss.ss_family = AF_INET;
		w->ss_len = sizeof(*sai);
		return fstrm_res_success;
	} else if (inet_pton(AF_INET6, twopt->socket_address, &sai6->sin6_addr) == 1) {
		w->ss.ss_family = AF_INET6;
		w->ss_len = sizeof(*sai6);
		return fstrm_res_success;
	}

	return fstrm_res_failure;
}

struct fstrm_writer *
fstrm_tcp_writer_init(const struct fstrm_tcp_writer_options *twopt,
		       const struct fstrm_writer_options *wopt)
{
	struct fstrm_rdwr *rdwr;
	struct fstrm__tcp_writer *tw;

	if (twopt->socket_address == NULL || twopt->socket_port == NULL)
		return NULL;

	tw = my_calloc(1, sizeof(*tw));

	if (!(fstrm__tcp_writer_fill_socket_address(tw, twopt) == fstrm_res_success &&
	      fstrm__tcp_writer_fill_socket_port(tw, twopt) == fstrm_res_success))
	{
		my_free(tw);
		return NULL;
	}

	rdwr = fstrm_rdwr_init(tw);
	fstrm_rdwr_set_destroy(rdwr, fstrm__tcp_writer_op_destroy);
	fstrm_rdwr_set_open(rdwr, fstrm__tcp_writer_op_open);
	fstrm_rdwr_set_close(rdwr, fstrm__tcp_writer_op_close);
	fstrm_rdwr_set_read(rdwr, fstrm__tcp_writer_op_read);
	fstrm_rdwr_set_write(rdwr, fstrm__tcp_writer_op_write);
	return fstrm_writer_init(wopt, &rdwr);
}
