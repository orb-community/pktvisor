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

#include "fstrm-private.h"

#define FSTRM__WRITER_IOVEC_SIZE	256

typedef enum {
	fstrm_writer_state_opening,
	fstrm_writer_state_opened,
	fstrm_writer_state_closed,
	fstrm_writer_state_failed,
} fstrm_writer_state;

struct fstrm_writer_options {
	fs_bufvec		*content_types;
};

struct fstrm_writer {
	fstrm_writer_state	state;
	fs_bufvec		*content_types;
	struct fstrm_rdwr	*rdwr;
	struct fstrm_control	*control_ready;
	struct fstrm_control	*control_accept;
	struct fstrm_control	*control_start;
	struct fstrm_control	*control_finish;

	struct iovec		*iovecs;
	uint32_t		*be32_lens;
};

struct fstrm_writer_options *
fstrm_writer_options_init(void)
{
	return my_calloc(1, sizeof(struct fstrm_writer_options));
}

void
fstrm_writer_options_destroy(struct fstrm_writer_options **wopt)
{
	if (*wopt != NULL) {
		if ((*wopt)->content_types != NULL) {
			for (size_t i = 0; i < fs_bufvec_size((*wopt)->content_types); i++) {
				fs_buf ctype = fs_bufvec_value((*wopt)->content_types, i);
				my_free(ctype.data);
			}
			fs_bufvec_destroy(&(*wopt)->content_types);
		}
		my_free(*wopt);
	}
}

fstrm_res
fstrm_writer_options_add_content_type(
	struct fstrm_writer_options *wopt,
	const void *content_type,
	size_t len_content_type)
{
	if (len_content_type > FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX)
		return fstrm_res_failure;
	if (wopt->content_types == NULL)
		wopt->content_types = fs_bufvec_init(1);
	fs_buf ctype = {
		.len = len_content_type,
		.data = my_malloc(len_content_type),
	};
	memmove(ctype.data, content_type, ctype.len);
	fs_bufvec_add(wopt->content_types, ctype);
	return fstrm_res_success;
}

struct fstrm_writer *
fstrm_writer_init(const struct fstrm_writer_options *wopt,
		  struct fstrm_rdwr **rdwr)
{
	if ((*rdwr)->ops.write == NULL)
		return NULL;

	struct fstrm_writer *w = my_calloc(1, sizeof(*w));

	w->rdwr = *rdwr;
	*rdwr = NULL;
	w->content_types = fs_bufvec_init(1);

	/* Copy options. */
	if (wopt != NULL && wopt->content_types != NULL) {
		for (size_t i = 0; i < fs_bufvec_size(wopt->content_types); i++) {
			fs_buf ctype = fs_bufvec_value(wopt->content_types, i);
			fs_buf ctype_copy = {
				.len = ctype.len,
				.data = my_malloc(ctype.len)
			};
			memmove(ctype_copy.data, ctype.data, ctype.len);
			fs_bufvec_add(w->content_types, ctype_copy);
		}
	}

	w->iovecs = my_calloc(FSTRM__WRITER_IOVEC_SIZE, sizeof(struct iovec));
	w->be32_lens = my_calloc(FSTRM__WRITER_IOVEC_SIZE / 2, sizeof(uint32_t));

	w->state = fstrm_writer_state_opening;
	return w;
}

fstrm_res
fstrm_writer_destroy(struct fstrm_writer **w)
{
	fstrm_res res = fstrm_res_failure;
	if (*w != NULL) {
		if ((*w)->state == fstrm_writer_state_opened)
			res = fstrm_writer_close(*w);

		fstrm_control_destroy(&(*w)->control_finish);
		fstrm_control_destroy(&(*w)->control_start);
		fstrm_control_destroy(&(*w)->control_accept);
		fstrm_control_destroy(&(*w)->control_ready);
		fstrm_rdwr_destroy(&(*w)->rdwr);
		for (size_t i = 0; i < fs_bufvec_size((*w)->content_types); i++) {
			fs_buf ctype = fs_bufvec_value((*w)->content_types, i);
			my_free(ctype.data);
		}
		fs_bufvec_destroy(&(*w)->content_types);
		my_free((*w)->iovecs);
		my_free((*w)->be32_lens);
		my_free(*w);
	}
	return res;
}

static fstrm_res
fstrm__writer_open_bidirectional(struct fstrm_writer *w)
{
	fstrm_res res;

	/* Initialize the READY frame. */
	if (w->control_ready != NULL)
		fstrm_control_reset(w->control_ready);
	else
		w->control_ready = fstrm_control_init();

	res = fstrm_control_set_type(w->control_ready, FSTRM_CONTROL_READY);
	if (res != fstrm_res_success)
		return res;

	for (size_t i = 0; i < fs_bufvec_size(w->content_types); i++) {
		fs_buf ctype = fs_bufvec_value(w->content_types, i);
		res = fstrm_control_add_field_content_type(w->control_ready,
			ctype.data, ctype.len);
		if (res != fstrm_res_success)
			return res;
	}

	/* Write the READY frame. */
	res = fstrm__rdwr_write_control_frame(w->rdwr, w->control_ready);
	if (res != fstrm_res_success)
		return res;

	/* Wait for the ACCEPT frame. */
	res = fstrm__rdwr_read_control(w->rdwr, &w->control_accept, FSTRM_CONTROL_ACCEPT);
	if (res != fstrm_res_success)
		return res;

	/* Match the ACCEPT content type. */
	bool match = true;
	const uint8_t *match_ctype = NULL;
	size_t len_match_ctype = 0;
	for (size_t i = 0; i < fs_bufvec_size(w->content_types); i++) {
		fs_buf ctype = fs_bufvec_value(w->content_types, i);
		res = fstrm_control_match_field_content_type(w->control_accept,
			ctype.data, ctype.len);
		if (res == fstrm_res_success) {
			match_ctype = ctype.data;
			len_match_ctype = ctype.len;
			break;
		} else {
			match = false;
			continue;
		}
	}
	if (!match) {
		/* Content type negotiation failed. */
		return fstrm_res_failure;
	}

	/* Initialize the START frame. */
	if (w->control_start != NULL)
		fstrm_control_reset(w->control_start);
	else
		w->control_start = fstrm_control_init();

	res = fstrm_control_set_type(w->control_start, FSTRM_CONTROL_START);
	if (res != fstrm_res_success)
		return res;

	if (match_ctype != NULL) {
		res = fstrm_control_add_field_content_type(w->control_start,
			match_ctype, len_match_ctype);
		if (res != fstrm_res_success)
			return res;
	}

	/* Write the START frame. */
	res = fstrm__rdwr_write_control_frame(w->rdwr, w->control_start);
	if (res != fstrm_res_success)
		return res;

	return fstrm_res_success;
}

static fstrm_res
fstrm__writer_open_unidirectional(struct fstrm_writer *w)
{
	fstrm_res res;

	/* Initialize the START frame. */
	if (w->control_start != NULL)
		fstrm_control_reset(w->control_start);
	else
		w->control_start = fstrm_control_init();

	res = fstrm_control_set_type(w->control_start, FSTRM_CONTROL_START);
	if (res != fstrm_res_success)
		return res;

	/* Set the content type. */
	if (fs_bufvec_size(w->content_types) > 0) {
		fs_buf ctype = fs_bufvec_value(w->content_types, 0);
		res = fstrm_control_add_field_content_type(w->control_start,
			ctype.data, ctype.len);
		if (res != fstrm_res_success)
			return res;
	}

	/* Write the START frame. */
	res = fstrm__rdwr_write_control_frame(w->rdwr, w->control_start);
	if (res != fstrm_res_success)
		return res;

	return fstrm_res_success;
}

fstrm_res
fstrm_writer_open(struct fstrm_writer *w)
{
	fstrm_res res;

	if (w->state == fstrm_writer_state_opened)
		return fstrm_res_success;

	res = fstrm_rdwr_open(w->rdwr);
	if (res != fstrm_res_success)
		return res;

	if (w->rdwr->ops.read != NULL) {
		/* Bi-directional transport. */
		res = fstrm__writer_open_bidirectional(w);
		if (res != fstrm_res_success)
			return res;
	} else {
		/* Uni-directional transport. */
		res = fstrm__writer_open_unidirectional(w);
		if (res != fstrm_res_success)
			return res;
	}

	w->state = fstrm_writer_state_opened;
	return fstrm_res_success;
}

static fstrm_res
fstrm__writer_maybe_open(struct fstrm_writer *w)
{
	fstrm_res res;

	if (unlikely(w->state == fstrm_writer_state_opening)) {
		res = fstrm_writer_open(w);
		if (res != fstrm_res_success)
			return res;
	}

	return fstrm_res_success;
}

fstrm_res
fstrm_writer_close(struct fstrm_writer *w)
{
	fstrm_res res;

	if (w->state != fstrm_writer_state_opened)
		return fstrm_res_failure;

	w->state = fstrm_writer_state_closed;

	/* Write the STOP frame. */
	res = fstrm__rdwr_write_control(w->rdwr, FSTRM_CONTROL_STOP, NULL);
	if (res != fstrm_res_success) {
		(void)fstrm_rdwr_close(w->rdwr);
		return res;
	}

	if (w->rdwr->ops.read != NULL) {
		/* For bi-directional transports, wait for the FINISH frame. */
		res = fstrm__rdwr_read_control(w->rdwr, &w->control_finish,
			FSTRM_CONTROL_FINISH);
		if (res != fstrm_res_success) {
			(void)fstrm_rdwr_close(w->rdwr);
			return res;
		}
	}

	res = fstrm_rdwr_close(w->rdwr);
	return res;
}

static fstrm_res
fstrm__writer_write_iov(struct fstrm_writer *w, const struct iovec *iov, int iovcnt)
{
	for (int i = 0, iov_idx = 0; i < iovcnt; i++) {
		/* Frame length. */
		w->be32_lens[i] = htonl(iov[i].iov_len);
		w->iovecs[iov_idx].iov_len = sizeof(uint32_t);
		w->iovecs[iov_idx].iov_base = (void *) &w->be32_lens[i];
		iov_idx += 1;

		/* Frame data. */
		memcpy(&w->iovecs[iov_idx], &iov[i], sizeof(struct iovec));
		iov_idx += 1;
	}

	return fstrm_rdwr_write(w->rdwr, w->iovecs, 2 * iovcnt);
}

static fstrm_res
fstrm__writer_write_iov_stupid(struct fstrm_writer *w,
			       const struct iovec *iov, int iovcnt)
{
	fstrm_res res;

	int iov_max = FSTRM__WRITER_IOVEC_SIZE / 2;
	if (iov_max > IOV_MAX)
		iov_max = IOV_MAX;
	assert(iov_max > 0);

	while (iovcnt > 0) {
		int iovcnt_to_write = iov_max;
		if (iovcnt_to_write > iovcnt)
			iovcnt_to_write = iovcnt;

		res = fstrm__writer_write_iov(w, iov, iovcnt_to_write);
		if (res != fstrm_res_success)
			return res;

		iov += iovcnt_to_write;
		iovcnt -= iovcnt_to_write;
	}

	return fstrm_res_success;
}

fstrm_res
fstrm_writer_write(struct fstrm_writer *w, const void *data, size_t len_data)
{
	struct iovec iov = {
		.iov_base = (void *) data,
		.iov_len = len_data,
	};
	return fstrm_writer_writev(w, &iov, 1);
}

fstrm_res
fstrm_writer_writev(struct fstrm_writer *w, const struct iovec *iov, int iovcnt)
{
	fstrm_res res;

	if (unlikely(iovcnt < 1))
		return fstrm_res_success;

	res = fstrm__writer_maybe_open(w);
	if (res != fstrm_res_success)
		return res;

	if (likely(w->state == fstrm_writer_state_opened)) {
		if (likely((2 * iovcnt) <= FSTRM__WRITER_IOVEC_SIZE))
			return fstrm__writer_write_iov(w, iov, iovcnt);
		else
			return fstrm__writer_write_iov_stupid(w, iov, iovcnt);
	}

	return fstrm_res_failure;
}

fstrm_res
fstrm_writer_get_control(struct fstrm_writer *w,
			 fstrm_control_type type,
			 struct fstrm_control **control)
{
	fstrm_res res;

	res = fstrm__writer_maybe_open(w);
	if (res != fstrm_res_success)
		return res;

	*control = NULL;

	switch (type) {
	case FSTRM_CONTROL_ACCEPT:
		*control = w->control_accept;
		break;
	case FSTRM_CONTROL_FINISH:
		*control = w->control_finish;
		break;
	case FSTRM_CONTROL_READY:
		*control = w->control_ready;
		break;
	case FSTRM_CONTROL_START:
		*control = w->control_start;
		break;
	case FSTRM_CONTROL_STOP:
		/* FALLTHROUGH */
	default:
		return fstrm_res_failure;
	}

	return fstrm_res_success;
}
