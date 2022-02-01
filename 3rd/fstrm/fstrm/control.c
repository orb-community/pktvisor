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
 */

#include "fstrm-private.h"

struct fstrm_control {
	fstrm_control_type	type;
	fs_bufvec		*content_types;
};

const char *
fstrm_control_type_to_str(fstrm_control_type type)
{
	switch (type) {
	case FSTRM_CONTROL_ACCEPT:
		return "FSTRM_CONTROL_ACCEPT";
	case FSTRM_CONTROL_START:
		return "FSTRM_CONTROL_START";
	case FSTRM_CONTROL_STOP:
		return "FSTRM_CONTROL_STOP";
	case FSTRM_CONTROL_READY:
		return "FSTRM_CONTROL_READY";
	case FSTRM_CONTROL_FINISH:
		return "FSTRM_CONTROL_FINISH";
	default:
		return "FSTRM_CONTROL_UNKNOWN";
	}
}

const char *
fstrm_control_field_type_to_str(fstrm_control_field f_type)
{
	switch (f_type) {
	case FSTRM_CONTROL_FIELD_CONTENT_TYPE:
		return "FSTRM_CONTROL_FIELD_CONTENT_TYPE";
	default:
		return "FSTRM_CONTROL_FIELD_UNKNOWN";
	}
}

struct fstrm_control *
fstrm_control_init(void)
{
	struct fstrm_control *c;
	c = my_calloc(1, sizeof(*c));
	c->content_types = fs_bufvec_init(1);
	return c;
}

void
fstrm_control_destroy(struct fstrm_control **c)
{
	if (*c != NULL) {
		fstrm_control_reset(*c);
		fs_bufvec_destroy(&(*c)->content_types);
		my_free(*c);
	}
}

void
fstrm_control_reset(struct fstrm_control *c)
{
	for (size_t i = 0; i < fs_bufvec_size(c->content_types); i++) {
		fs_buf buf = fs_bufvec_value(c->content_types, i);
		my_free(buf.data);
	}
	fs_bufvec_reset(c->content_types);
	c->type = 0;
}

fstrm_res
fstrm_control_get_type(const struct fstrm_control *c, fstrm_control_type *type)
{
	switch (c->type) {
	case FSTRM_CONTROL_ACCEPT:	/* FALLTHROUGH */
	case FSTRM_CONTROL_START:	/* FALLTHROUGH */
	case FSTRM_CONTROL_STOP:	/* FALLTHROUGH */
	case FSTRM_CONTROL_READY:	/* FALLTHROUGH */
	case FSTRM_CONTROL_FINISH:
		*type = c->type;
		return fstrm_res_success;
	default:
		return fstrm_res_failure;
	}
}

fstrm_res
fstrm_control_set_type(struct fstrm_control *c, fstrm_control_type type)
{
	switch (type) {
	case FSTRM_CONTROL_ACCEPT:	/* FALLTHROUGH */
	case FSTRM_CONTROL_START:	/* FALLTHROUGH */
	case FSTRM_CONTROL_STOP:	/* FALLTHROUGH */
	case FSTRM_CONTROL_READY:	/* FALLTHROUGH */
	case FSTRM_CONTROL_FINISH:
		c->type = type;
		return fstrm_res_success;
	default:
		return fstrm_res_failure;
	}
}

fstrm_res
fstrm_control_get_num_field_content_type(const struct fstrm_control *c,
					 size_t *n_content_type)
{
	*n_content_type = fs_bufvec_size(c->content_types);

	switch (c->type) {
	case FSTRM_CONTROL_STOP:	/* FALLTHROUGH */
	case FSTRM_CONTROL_FINISH:	/* FALLTHROUGH */
		/*
		 * STOP and FINISH frames may not have any content type fields.
		 */
		*n_content_type = 0;
		break;
	case FSTRM_CONTROL_START:
		/* START frames may not have more than one content type field. */
		if (*n_content_type > 1)
			*n_content_type = 1;
		break;
	default:
		break;
	}

	return fstrm_res_success;
}

fstrm_res
fstrm_control_get_field_content_type(const struct fstrm_control *c,
				     const size_t idx,
				     const uint8_t **content_type,
				     size_t *len_content_type)
{
	if (idx < fs_bufvec_size(c->content_types)) {
		fs_buf buf = fs_bufvec_value(c->content_types, idx);
		*content_type = buf.data;
		*len_content_type = buf.len;
		return fstrm_res_success;
	}
	return fstrm_res_failure;
}

fstrm_res
fstrm_control_add_field_content_type(struct fstrm_control *c,
				     const uint8_t *content_type,
				     size_t len_content_type)
{
	fs_buf ctype;
	ctype.len = len_content_type;
	ctype.data = my_malloc(ctype.len);
	memcpy(ctype.data, content_type, ctype.len);
	fs_bufvec_add(c->content_types, ctype);

	return fstrm_res_success;
}

fstrm_res
fstrm_control_match_field_content_type(const struct fstrm_control *c,
				       const uint8_t *match,
				       const size_t len_match)
{
	fstrm_res res;
	size_t n_ctype = 0;

	/*
	 * STOP and FINISH frames don't have a content type. They never match.
	 */
	if (c->type == FSTRM_CONTROL_STOP || c->type == FSTRM_CONTROL_FINISH)
		return fstrm_res_failure;

	res = fstrm_control_get_num_field_content_type(c, &n_ctype);
	if (res != fstrm_res_success)
		return res;

	if (n_ctype == 0) {
		/* Control frame doesn't set any content type. */
		return fstrm_res_success;
	} else {
		/*
		 * The content type must match one of the control frame's
		 * content types.
		 */

		if (match == NULL) {
			/*
			 * The control frame has at least one content type set,
			 * which cannot match an unset content type.
			 */
			return fstrm_res_failure;
		}

		for (size_t idx = 0; idx < n_ctype; idx++) {
			/*
			 * Check against all the content types in the control
			 * frame.
			 */
			const uint8_t *content_type = NULL;
			size_t len_content_type = 0;

			res = fstrm_control_get_field_content_type(c, idx,
				&content_type, &len_content_type);
			if (res != fstrm_res_success)
				return res;

			if (len_content_type != len_match)
				continue;
			if (memcmp(content_type, match, len_match) == 0) {
				/* Exact match. */
				return fstrm_res_success;
			}
		}
	}

	return fstrm_res_failure;
}

fstrm_res
fstrm_control_decode(struct fstrm_control *c,
		     const void *control_frame,
		     size_t len_control_frame,
		     const uint32_t flags)
{
	const uint8_t *buf = control_frame;
	size_t len = len_control_frame;
	uint32_t val;

	fstrm_control_reset(c);

	if (flags & FSTRM_CONTROL_FLAG_WITH_HEADER) {
		/* Read the outer frame length. */
		if (!fs_load_be32(&buf, &len, &val))
			return fstrm_res_failure;

		/* The outer frame length must be zero, since this is a control frame. */
		if (val != 0)
			return fstrm_res_failure;

		/* Read the control frame length. */
		if (!fs_load_be32(&buf, &len, &val))
			return fstrm_res_failure;

		/* Enforce maximum control frame size. */
		if (val > FSTRM_CONTROL_FRAME_LENGTH_MAX)
			return fstrm_res_failure;

		/*
		 * Require that the control frame length matches the number of
		 * bytes remaining in 'buf'.
		 */
		if (val != len)
			return fstrm_res_failure;
	} else {
		/* Enforce maximum control frame size. */
		if (len_control_frame > FSTRM_CONTROL_FRAME_LENGTH_MAX)
			return fstrm_res_failure;
	}

	/* Read the control frame type. */
	if (!fs_load_be32(&buf, &len, &val))
		return fstrm_res_failure;
	switch (val) {
	case FSTRM_CONTROL_ACCEPT:	/* FALLTHROUGH */
	case FSTRM_CONTROL_START:	/* FALLTHROUGH */
	case FSTRM_CONTROL_STOP:	/* FALLTHROUGH */
	case FSTRM_CONTROL_READY:	/* FALLTHROUGH */
	case FSTRM_CONTROL_FINISH:
		c->type = (fstrm_control_type) val;
		break;
	default:
		return fstrm_res_failure;
	}

	/* Read any control frame fields. */
	while (len > 0) {
		/* Read the control frame field type. */
		if (!fs_load_be32(&buf, &len, &val))
			return fstrm_res_failure;

		switch (val) {
		case FSTRM_CONTROL_FIELD_CONTENT_TYPE: {
			fs_buf c_type;

			/* Read the length of the "Content Type" payload. */
			if (!fs_load_be32(&buf, &len, &val))
				return fstrm_res_failure;
			c_type.len = val;

			/*
			 * Sanity check the length field. It cannot be larger
			 * than 'len', the number of bytes remaining in 'buf'.
			 */
			if (c_type.len > len)
				return fstrm_res_failure;

			/* Enforce limit on "Content Type" payload length. */
			if (c_type.len > FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX)
				return fstrm_res_failure;

			/* Read the "Content Type" payload. */
			c_type.data = my_malloc(c_type.len);
			if (!fs_load_bytes(c_type.data, c_type.len, &buf, &len))
			{
				my_free(c_type.data);
				return fstrm_res_failure;
			}

			/* Insert the "Content Type" field. */
			fs_bufvec_add(c->content_types, c_type);

			break;
		}
		default:
			return fstrm_res_failure;
		}
	}

	/* Enforce limits on the number of "Content Type" fields. */
	const size_t n_ctype = fs_bufvec_size(c->content_types);
	switch (c->type) {
	case FSTRM_CONTROL_START:
		if (n_ctype > 1)
			return fstrm_res_failure;
		break;
	case FSTRM_CONTROL_STOP:
		/* FALLTHROUGH */
	case FSTRM_CONTROL_FINISH:
		if (n_ctype > 0)
			return fstrm_res_failure;
		break;
	case FSTRM_CONTROL_ACCEPT:
		/* FALLTHROUGH */
	case FSTRM_CONTROL_READY:
		/* FALLTHROUGH */
	default:
		break;
	}

	return fstrm_res_success;
}

fstrm_res
fstrm_control_encoded_size(const struct fstrm_control *c,
			   size_t *len_control_frame,
			   const uint32_t flags)
{
	size_t len = 0;

	if (flags & FSTRM_CONTROL_FLAG_WITH_HEADER) {
		/* Escape: 32-bit BE integer. */
		len += sizeof(uint32_t);

		/* Frame length: 32-bit BE integer. */
		len += sizeof(uint32_t);
	}

	/* Control type: 32-bit BE integer. */
	len += sizeof(uint32_t);

	/* "Content Type" fields. */
	for (size_t i = 0; i < fs_bufvec_size(c->content_types); i++) {
		/* Do not add "Content Type" fields to STOP or FINISH frames. */
		if (c->type == FSTRM_CONTROL_STOP ||
		    c->type == FSTRM_CONTROL_FINISH)
		{
			break;
		}

		fs_buf c_type = fs_bufvec_value(c->content_types, i);

		/* FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer. */
		len += sizeof(uint32_t);

		/* Length of the "Content Type" string: 32-bit BE integer. */
		len += sizeof(uint32_t);

		/* Enforce limit on "Content Type" payload length. */
		if (c_type.len > FSTRM_CONTROL_FIELD_CONTENT_TYPE_LENGTH_MAX)
			return fstrm_res_failure;

		/* The "Content Type" payload. */
		len += c_type.len;

		/* Only add one "Content Type" field to START frames. */
		if (c->type == FSTRM_CONTROL_START)
			break;
	}

	/* Sanity check the overall length. */
	if (len > FSTRM_CONTROL_FRAME_LENGTH_MAX)
		return fstrm_res_failure;

	*len_control_frame = len;
	return fstrm_res_success;
}

fstrm_res
fstrm_control_encode(const struct fstrm_control *c,
		     void *control_frame,
		     size_t *len_control_frame,
		     const uint32_t flags)
{
	fstrm_res res;
	size_t encoded_size;

	/* Calculate the size of the control frame. */
	res = fstrm_control_encoded_size(c, &encoded_size, flags);
	if (res != fstrm_res_success)
		return res;

	/*
	 * The caller must have provided a large enough buffer to serialize the
	 * control frame.
	 */
	if (*len_control_frame < encoded_size)
		return fstrm_res_failure;

	/*
	 * Now actually serialize the control frame.
	 */
	size_t len = encoded_size;
	uint8_t *buf = control_frame;

	if (flags & FSTRM_CONTROL_FLAG_WITH_HEADER) {
		/* Escape: 32-bit BE integer. Zero. */
		if (!fs_store_be32(&buf, &len, 0))
			return fstrm_res_failure;

		/*
		 * Frame length: 32-bit BE integer.
		 *
		 * This does not include the length of the escape frame or the length
		 * of the frame length field itself, so subtract 2*4 bytes from the
		 * total length.
		 */
		if (!fs_store_be32(&buf, &len, encoded_size - 2 * sizeof(uint32_t)))
			return fstrm_res_failure;
	}

	/* Control type: 32-bit BE integer. */
	if (!fs_store_be32(&buf, &len, c->type))
		return fstrm_res_failure;

	/* "Content Type" fields. */
	for (size_t i = 0; i < fs_bufvec_size(c->content_types); i++) {
		/* Do not add "Content Type" fields to STOP or FINISH frames. */
		if (c->type == FSTRM_CONTROL_STOP ||
		    c->type == FSTRM_CONTROL_FINISH)
		{
			break;
		}

		fs_buf c_type = fs_bufvec_value(c->content_types, i);

		/* FSTRM_CONTROL_FIELD_CONTENT_TYPE: 32-bit BE integer. */
		if (!fs_store_be32(&buf, &len, FSTRM_CONTROL_FIELD_CONTENT_TYPE))
			return fstrm_res_failure;

		/* Length of the "Content Type" payload: 32-bit BE integer. */
		if (!fs_store_be32(&buf, &len, c_type.len))
			return fstrm_res_failure;

		/* The "Content Type" string itself. */
		if (!fs_store_bytes(&buf, &len, c_type.data, c_type.len))
			return fstrm_res_failure;

		/* Only add one "Content Type" field to START frames. */
		if (c->type == FSTRM_CONTROL_START)
			break;
	}

	*len_control_frame = encoded_size;
	return fstrm_res_success;
}
