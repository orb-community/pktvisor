/*
 * Copyright (c) 2014, 2018 by Farsight Security, Inc.
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

#ifndef FSTRM_TCP_WRITER_H
#define FSTRM_TCP_WRITER_H

/**
 * \defgroup fstrm_tcp_writer fstrm_tcp_writer
 *
 * `fstrm_tcp_writer` is an interface for opening an \ref fstrm_writer object
 * that is backed by I/O on a TCP socket.
 *
 * @{
 */

/**
 * Initialize an `fstrm_tcp_writer_options` object, which is needed to
 * configure the socket address and socket port to be opened by the writer.
 *
 * \return
 *	`fstrm_tcp_writer_options` object.
 */
struct fstrm_tcp_writer_options *
fstrm_tcp_writer_options_init(void);

/**
 * Destroy an `fstrm_tcp_writer_options` object.
 *
 * \param twopt
 *	Pointer to `fstrm_tcp_writer_options` object.
 */
void
fstrm_tcp_writer_options_destroy(
	struct fstrm_tcp_writer_options **twopt);

/**
 * Set the `socket_address` option. This is the IPv4 or IPv6 address in
 * presentation format to be connected by the TCP socket.
 *
 * \param twopt
 *	`fstrm_tcp_writer_options` object.
 * \param socket_address
 *	The socket address.
 */
void
fstrm_tcp_writer_options_set_socket_address(
	struct fstrm_tcp_writer_options *twopt,
	const char *socket_address);

/**
 * Set the `socket_port` option. This is the TCP port number to be connected by
 * the TCP socket.
 *
 * \param twopt
 *	`fstrm_tcp_writer_options` object.
 * \param socket_port
 *	The TCP socket port number provided as a character string.
 *	(When converted, the maximum allowed unsigned integer is 65535.)
 */
void
fstrm_tcp_writer_options_set_socket_port(
	struct fstrm_tcp_writer_options *twopt,
	const char *socket_port);

/**
 * Initialize the `fstrm_writer` object. Note that the TCP socket will not
 * actually be opened until a subsequent call to fstrm_writer_open().
 *
 * \param twopt
 *	`fstrm_tcp_writer_options` object. Must be non-NULL, and have the
 *	`socket_address` and `socket_port` options set.
 * \param wopt
 *	`fstrm_writer_options` object. May be NULL, in which chase default
 *	values will be used.
 *
 * \return
 *	`fstrm_writer` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_writer *
fstrm_tcp_writer_init(
	const struct fstrm_tcp_writer_options *twopt,
	const struct fstrm_writer_options *wopt);

/**@}*/

#endif /* FSTRM_TCP_WRITER_H */
