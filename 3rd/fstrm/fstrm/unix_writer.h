/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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

#ifndef FSTRM_UNIX_WRITER_H
#define FSTRM_UNIX_WRITER_H

/**
 * \defgroup fstrm_unix_writer fstrm_unix_writer
 *
 * `fstrm_unix_writer` is an interface for opening an \ref fstrm_writer object
 * that is backed by I/O on a stream-oriented (`SOCK_STREAM`) Unix socket.
 *
 * @{
 */

/**
 * Initialize an `fstrm_unix_writer_options` object, which is needed to
 * configure the socket path to be opened by the writer.
 *
 * \return
 *	`fstrm_unix_writer_options` object.
 */
struct fstrm_unix_writer_options *
fstrm_unix_writer_options_init(void);

/**
 * Destroy an `fstrm_unix_writer_options` object.
 * 
 * \param uwopt
 *	Pointer to `fstrm_unix_writer_options` object.
 */
void
fstrm_unix_writer_options_destroy(
	struct fstrm_unix_writer_options **uwopt);

/**
 * Set the `socket_path` option. This is a filesystem path that will be
 * connected to as an `AF_UNIX` socket.
 *
 * \param uwopt
 *	`fstrm_unix_writer_options` object.
 * \param socket_path
 *	The filesystem path to the `AF_UNIX` socket.
 */
void
fstrm_unix_writer_options_set_socket_path(
	struct fstrm_unix_writer_options *uwopt,
	const char *socket_path);

/**
 * Initialize the `fstrm_writer` object. Note that the `AF_UNIX` socket will not
 * actually be opened until a subsequent call to fstrm_writer_open().
 *
 * \param uwopt
 *	`fstrm_unix_writer_options` object. Must be non-NULL, and have the
 *	`socket_path` option set.
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
fstrm_unix_writer_init(
	const struct fstrm_unix_writer_options *uwopt,
	const struct fstrm_writer_options *wopt);

/**@}*/

#endif /* FSTRM_UNIX_WRITER_H */
