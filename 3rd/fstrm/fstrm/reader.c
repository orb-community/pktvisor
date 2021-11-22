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
#include "libmy/ubuf.h"

typedef enum {
	fstrm_reader_state_opening,
	fstrm_reader_state_opened,
	fstrm_reader_state_closing,
	fstrm_reader_state_closed,
	fstrm_reader_state_failed,
} fstrm_reader_state;

struct fstrm_reader {
	fstrm_reader_state	state;
	fs_bufvec		*content_types;
	size_t			max_frame_size;
	struct fstrm_rdwr	*rdwr;
	struct fstrm_control	*control_start;
	struct fstrm_control	*control_stop;
	struct fstrm_control	*control_ready;
	struct fstrm_control	*control_accept;
	struct fstrm_control	*control_tmp;
	ubuf			*buf;
};

struct fstrm_reader_options {
	fs_bufvec		*content_types;
	size_t			max_frame_size;
};

static const struct fstrm_reader_options default_fstrm_reader_options = {
	.max_frame_size		= FSTRM_READER_MAX_FRAME_SIZE_DEFAULT,
};

struct fstrm_reader_options *
fstrm_reader_options_init(void)
{
	struct fstrm_reader_options *ropt;
	ropt = my_calloc(1, sizeof(*ropt));
	memmove(ropt, &default_fstrm_reader_options, sizeof(*ropt));
	return ropt;
}

void
fstrm_reader_options_destroy(struct fstrm_reader_options **ropt)
{
	if (*ropt != NULL) {
		if ((*ropt)->content_types != NULL) {
			for (size_t i = 0; i < fs_bufvec_size((*ropt)->content_types); i++) {
				fs_buf ctype = fs_bufvec_value((*ropt)->content_types, i);
				my_free(ctype.data);
			}
			fs_bufvec_destroy(&(*ropt)->content_types);
		}
		my_free(*ropt);
	}
}

fstrm_res
fstrm_reader_options_add_content_type(
	struct fstrm_reader_options *ropt,
	const void *content_type,
	size_t len_content_type)
{
	if (len_content_type > FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX)
		return fstrm_res_failure;
	if (ropt->content_types == NULL)
		ropt->content_types = fs_bufvec_init(1);
	fs_buf ctype = {
		.len = len_content_type,
		.data = my_malloc(len_content_type),
	};
	memmove(ctype.data, content_type, ctype.len);
	fs_bufvec_add(ropt->content_types, ctype);
	return fstrm_res_success;
}

fstrm_res
fstrm_reader_options_set_max_frame_size(
	struct fstrm_reader_options *ropt,
	size_t max_frame_size)
{
	if (max_frame_size < FSTRM_CONTROL_FRAME_LENGTH_MAX ||
	    max_frame_size > UINT32_MAX - 1)
	{
		return fstrm_res_failure;
	}
	ropt->max_frame_size = max_frame_size;
	return fstrm_res_success;
}

struct fstrm_reader *
fstrm_reader_init(const struct fstrm_reader_options *ropt,
		  struct fstrm_rdwr **rdwr)
{
	if (ropt == NULL)
		ropt = &default_fstrm_reader_options;

	if ((*rdwr)->ops.read == NULL)
		return NULL;

	struct fstrm_reader *r = my_calloc(1, sizeof(*r));

	r->rdwr = *rdwr;
	*rdwr = NULL;
	r->content_types = fs_bufvec_init(1);
	r->buf = ubuf_init(FSTRM_CONTROL_FRAME_LENGTH_MAX);

	/* Copy options. */
	r->max_frame_size = ropt->max_frame_size;
	if (ropt->content_types != NULL) {
		for (size_t i = 0; i < fs_bufvec_size(ropt->content_types); i++) {
			fs_buf ctype = fs_bufvec_value(ropt->content_types, i);
			fs_buf ctype_copy = {
				.len = ctype.len,
				.data = my_malloc(ctype.len),
			};
			memmove(ctype_copy.data, ctype.data, ctype.len);
			fs_bufvec_add(r->content_types, ctype_copy);
		}
	}

	r->state = fstrm_reader_state_opening;
	return r;
}

fstrm_res
fstrm_reader_destroy(struct fstrm_reader **r)
{
	fstrm_res res = fstrm_res_failure;
	if (*r != NULL) {
		if ((*r)->state == fstrm_reader_state_opened ||
		    (*r)->state == fstrm_reader_state_closing)
		{
			res = fstrm_reader_close(*r);
		}

		fstrm_control_destroy(&(*r)->control_tmp);
		fstrm_control_destroy(&(*r)->control_accept);
		fstrm_control_destroy(&(*r)->control_ready);
		fstrm_control_destroy(&(*r)->control_stop);
		fstrm_control_destroy(&(*r)->control_start);
		fstrm_rdwr_destroy(&(*r)->rdwr);
		ubuf_destroy(&(*r)->buf);
		for (size_t i = 0; i < fs_bufvec_size((*r)->content_types); i++) {
			fs_buf ctype = fs_bufvec_value((*r)->content_types, i);
			my_free(ctype.data);
		}
		fs_bufvec_destroy(&(*r)->content_types);
		my_free(*r);
	}
	return res;
}

static fstrm_res
fstrm__reader_open_unidirectional(struct fstrm_reader *r)
{
	fstrm_res res;

	/* Read the START frame. */
	res = fstrm__rdwr_read_control(r->rdwr, &r->control_start, FSTRM_CONTROL_START);
	if (res != fstrm_res_success)
		return res;

	/* Match the START content type. */
	bool match = true;
	for (size_t i = 0; i < fs_bufvec_size(r->content_types); i++) {
		fs_buf ctype = fs_bufvec_value(r->content_types, i);
		res = fstrm_control_match_field_content_type(r->control_start,
			ctype.data, ctype.len);
		if (res == fstrm_res_success) {
			match = true;
			break;
		} else {
			match = false;
			continue;
		}
	}
	if (!match) {
		/* Unwanted content type. */
		return fstrm_res_failure;
	}

	r->state = fstrm_reader_state_opened;
	return fstrm_res_success;
}

static fstrm_res
fstrm__reader_open_bidirectional(struct fstrm_reader *r)
{
	fstrm_res res;

	/* Read the READY frame. */
	res = fstrm__rdwr_read_control(r->rdwr, &r->control_ready, FSTRM_CONTROL_READY);
	if (res != fstrm_res_success)
		return res;

	/* Initialize the ACCEPT frame. */
	if (r->control_accept != NULL)
		fstrm_control_reset(r->control_accept);
	else
		r->control_accept = fstrm_control_init();

	res = fstrm_control_set_type(r->control_accept, FSTRM_CONTROL_ACCEPT);
	if (res != fstrm_res_success)
		return res;

	/* Add matching content types from the READY frame to the ACCEPT frame. */
	for (size_t i = 0; i < fs_bufvec_size(r->content_types); i++) {
		fs_buf ctype = fs_bufvec_value(r->content_types, i);
		res = fstrm_control_match_field_content_type(r->control_ready,
			ctype.data, ctype.len);
		if (res == fstrm_res_success) {
			res = fstrm_control_add_field_content_type(r->control_accept,
				ctype.data, ctype.len);
			if (res != fstrm_res_success)
				return res;
		}
	}

	/* Write the ACCEPT frame. */
	res = fstrm__rdwr_write_control_frame(r->rdwr, r->control_accept);
	if (res != fstrm_res_success)
		return res;

	/* Do the rest of the open. */
	return fstrm__reader_open_unidirectional(r);
}

fstrm_res
fstrm_reader_open(struct fstrm_reader *r)
{
	fstrm_res res;

	if (r->state == fstrm_reader_state_opened)
		return fstrm_res_failure;

	res = fstrm_rdwr_open(r->rdwr);
	if (res != fstrm_res_success)
		return res;

	if (r->rdwr->ops.write != NULL) {
		/* Bi-directional transport. */
		res = fstrm__reader_open_bidirectional(r);
		if (res != fstrm_res_success)
			return res;
	} else {
		/* Uni-directional transport. */
		res = fstrm__reader_open_unidirectional(r);
		if (res != fstrm_res_success)
			return res;
	}

	r->state = fstrm_reader_state_opened;
	return fstrm_res_success;
}

static inline fstrm_res
fstrm__reader_read_be32(struct fstrm_reader *r, uint32_t *out)
{
	fstrm_res res;
	uint32_t tmp;

	res = fstrm_rdwr_read(r->rdwr, &tmp, sizeof(tmp));
	if (unlikely(res != fstrm_res_success))
		return res;
	*out = ntohl(tmp);
	return fstrm_res_success;
}

static fstrm_res
fstrm__reader_next_data(struct fstrm_reader *r,
			const uint8_t **data, size_t *len_data)
{
	fstrm_res res = fstrm_res_failure;

	for (;;) {
		uint32_t len;

		/* Read the frame length. */
		res = fstrm__reader_read_be32(r, &len);
		if (unlikely(res != fstrm_res_success))
			goto fail;

		if (likely(len != 0)) {
			/* This is a data frame. */

			/* Enforce maximum frame size. */
			if (unlikely(len > r->max_frame_size))
				goto fail;

			/* Read the data frame. */
			ubuf_clip(r->buf, 0);
			ubuf_reserve(r->buf, len);
			res = fstrm_rdwr_read(r->rdwr, ubuf_ptr(r->buf), len);
			if (unlikely(res != fstrm_res_success))
				goto fail;

			/* Export the data frame to the caller. */
			*data = ubuf_ptr(r->buf);
			*len_data = len;
			return fstrm_res_success;
		} else if (len == 0) {
			/* This is a control frame. */

			/* Read the control frame. */
			fstrm_control_type type;
			if (r->control_tmp == NULL)
				r->control_tmp = fstrm_control_init();
			res = fstrm__rdwr_read_control_frame(r->rdwr,
				r->control_tmp, &type, false);
			if (unlikely(res != fstrm_res_success))
				goto fail;

			/* Break if this is the end of the stream. */
			if (type == FSTRM_CONTROL_STOP) {
				/*
				(void)fstrm__rdwr_write_control(r->rdwr,
					FSTRM_CONTROL_FINISH, NULL);
				*/
				r->state = fstrm_reader_state_closing;
				r->control_stop = r->control_tmp;
				r->control_tmp = NULL;
				return fstrm_res_stop;
			}
		}
	}
fail:
	r->state = fstrm_reader_state_failed;
	return res;
}

static fstrm_res
fstrm__reader_maybe_open(struct fstrm_reader *r)
{
	fstrm_res res;

	if (unlikely(r->state == fstrm_reader_state_opening)) {
		res = fstrm_reader_open(r);
		if (res != fstrm_res_success)
			return res;
	}

	return fstrm_res_success;
}

fstrm_res
fstrm_reader_close(struct fstrm_reader *r)
{
	fstrm_res res;

	if (r->state != fstrm_reader_state_opened &&
	    r->state != fstrm_reader_state_closing)
	{
		return fstrm_res_failure;
	}

	r->state = fstrm_reader_state_closed;

	if (r->rdwr->ops.write != NULL) {
		/* For bi-directional transports, write the FINISH frame. */
		res = fstrm__rdwr_write_control(r->rdwr, FSTRM_CONTROL_FINISH, NULL);
		if (res != fstrm_res_success) {
			(void)fstrm_rdwr_close(r->rdwr);
			return res;
		}
	}

	return fstrm_rdwr_close(r->rdwr);
}

fstrm_res
fstrm_reader_read(struct fstrm_reader *r, const uint8_t **data, size_t *len_data)
{

	fstrm_res res;

	res = fstrm__reader_maybe_open(r);
	if (res != fstrm_res_success)
		return res;

	if (likely(r->state == fstrm_reader_state_opened)) {
		return fstrm__reader_next_data(r, data, len_data);
	} else if (r->state == fstrm_reader_state_closed) {
		return fstrm_res_stop;
	}

	return fstrm_res_failure;
}

fstrm_res
fstrm_reader_get_control(struct fstrm_reader *r,
			 fstrm_control_type type,
			 const struct fstrm_control **control)
{
	fstrm_res res;

	res = fstrm__reader_maybe_open(r);
	if (res != fstrm_res_success)
		return res; 

	*control = NULL;

	switch (type) {
	case FSTRM_CONTROL_START:
		*control = r->control_start;
		break;
	case FSTRM_CONTROL_STOP:
		*control = r->control_stop;
		break;
	case FSTRM_CONTROL_READY:
		*control = r->control_ready;
		break;
	case FSTRM_CONTROL_ACCEPT:
		*control = r->control_accept;
		break;
	case FSTRM_CONTROL_FINISH:
		/* FALLTHROUGH */
	default:
		return fstrm_res_failure;
	}

	return fstrm_res_success;
}
