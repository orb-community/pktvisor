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

#ifndef FSTRM_FILE_H
#define FSTRM_FILE_H

/**
 * \defgroup fstrm_file fstrm_file
 *
 * `fstrm_file` contains interfaces for opening \ref fstrm_reader or
 * \ref fstrm_writer objects that are backed by file I/O.
 *
 * @{
 */

/**
 * Initialize an `fstrm_file_options` object, which is needed to configure the
 * file path to be opened by fstrm_file_reader_init() or
 * fstrm_file_writer_init().
 *
 * \return
 *	`fstrm_file_options` object.
 */
struct fstrm_file_options *
fstrm_file_options_init(void);

/**
 * Destroy an `fstrm_file_options` object.
 *
 * \param fopt
 *	Pointer to `fstrm_file_options` object.
 */
void
fstrm_file_options_destroy(struct fstrm_file_options **fopt);

/**
 * Set the `file_path` option. This is a filesystem path to a regular file to be
 * opened for reading or writing.
 *
 * \param fopt
 *	`fstrm_file_options` object.
 * \param file_path
 *	The filesystem path for a regular file.
 */
void
fstrm_file_options_set_file_path(struct fstrm_file_options *fopt,
				 const char *file_path);

/**
 * Open a file containing Frame Streams data for reading.
 *
 * \param fopt
 *	`fstrm_file_options` object. Must be non-NULL, and have the `file_path`
 *	option set.
 * \param ropt
 *	`fstrm_reader_options` object. May be NULL, in which case default values
 *	will be used.
 *
 * \return
 *	`fstrm_reader` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_reader *
fstrm_file_reader_init(const struct fstrm_file_options *fopt,
		       const struct fstrm_reader_options *ropt);

/**
 * Open a file for writing Frame Streams data. The file will be truncated if it
 * already exists.
 *
 * \param fopt
 *	`fstrm_file_options` object. Must be non-NULL, and have the `file_path`
 *	option set.
 * \param wopt
 *	`fstrm_writer_options` object. May be NULL, in which case default values
 *	will be used.
 *
 * \return
 *	`fstrm_writer` object.
 * \retval
 *	NULL on failure.
 */
struct fstrm_writer *
fstrm_file_writer_init(const struct fstrm_file_options *fopt,
		       const struct fstrm_writer_options *wopt);

/**@}*/

#endif /* FSTRM_FILE_H */
