/*
 *
 * Authors:     Dimitar Delov, <ddelov@arkoon.net>
 *              Marc Finet, <mfinet@arkoon.net>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2012 Arkoon Network Security
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <errno.h>
#include <assert.h>
#include "libkacontrol.h"
#include "vrrp.h"


#define offsetof(st, m) ((size_t) ( (char *)&((st *)(NULL))->m - (char *)NULL))

/*
 * Error handling
 */
#define error(err, fmt, ...) \
	do {\
		if (err && err->sz) { \
				ssize_t _s = snprintf(err->buff, err->sz, "%s:%d: " fmt, \
					__FUNCTION__, __LINE__, ## __VA_ARGS__); \
				if (_s < 0) { \
					/* NOP ,snprintf() failed */ \
				} else if (_s < err->sz) { \
					err->sz -= _s; \
				} else { \
					/* no more space */ \
					err->sz = 0; \
				} \
		} \
	} while (0)

control_err_t *
control_err_init(control_err_t *err, char *buff, size_t sz)
{
	if (buff)
		buff[0] = '\0';
	err->buff = buff;
	err->sz = sz;
	return err;
}

control_err_t *
control_err_new(size_t sz)
{
	control_err_t *err;
	if (!(err = malloc(sizeof(*err)))) {
		return NULL;
	}
	if ((err->buff = malloc(sz))) {
		free(err);
		return NULL;
	}
	err->sz = sz;
	return err;
}

void
control_err_free(control_err_t *err)
{
	if (err) {
		free(err->buff);
		free(err);
	}
}

/*
 * Buffer part
 */
buffer_t *
buffer_new(size_t sz)
{
	buffer_t *buff;

	if (!(buff = malloc(sizeof(*buff)))) {
		return NULL;
	}
	if (!sz) {
		buff->ptr = NULL;
	} else if (!(buff->ptr = malloc(sz))) {
		free(buff);
		return NULL;
	}
	buff->cur = 0;
	buff->total = sz;
	return buff;
}

char *
buffer_detach(buffer_t *buff)
{
	char *ptr;
	ptr = buff->ptr;
	free(buff);
	return ptr;
}

void
buffer_free(buffer_t *buff)
{
	if (!buff)
		return;
	free(buff->ptr);
	free(buff);
	return;
}

int
buffer_grow(buffer_t *buff, size_t more)
{
	char *tmp;
	if (!(tmp = realloc(buff->ptr, buff->total+more)))
		return 1;
	buff->ptr = tmp;
	buff->total += more;
	return 0;
}

/*
 *
 * Message part
 *
 */

/**
 * Create new msg
 */
control_msg_t *
control_msg_new(cmd_verb verb, flags_t flags)
{
	control_msg_t *msg;
	if (!(msg = malloc(sizeof(*msg)))) {
		return NULL;
	}
	if (!(msg->header = malloc(sizeof(*msg->header)))) {
		free(msg);
		return NULL;
	}
	msg->nb_args = 0;
	msg->args = NULL;
	msg->header->verb = verb;
	msg->header->flags = flags;
	msg->header->total_size = sizeof(msg->header);
	return msg;
}

void
control_msg_free(control_msg_t *msg)
{
	int i;

	if (!msg) {
		return ;
	}

	for (i = 0; i < msg->nb_args; ++i) {
		switch (control_msg_arg_type[msg->args[i].type]) {
		case ARG_STRING:
			free(msg->args[i].u.str);
			break;
		case ARG_INT:
			/* nop */
			break;
		default:
			assert(0);
		}
	}
	free(msg->args);
	free(msg->header);
	free(msg);
}

static int
control_msg_add_arg(control_msg_t *msg, cmd_type type,
	control_err_t *err)
{
	control_msg_arg_t *tmp;

	if (!(tmp = realloc(msg->args, sizeof(msg->args[0]) * (msg->nb_args+1)))) {
		error(err, "realloc %zd failed",
			sizeof(msg->args[0]) * (msg->nb_args+1));
		return -1;
	}
	msg->args = tmp;
	msg->args[msg->nb_args].type = type;
	return 0;
}

int
control_msg_add_arg_int(control_msg_t *msg, cmd_type type, int value,
	control_err_t *err)
{
	assert(control_msg_arg_type[type] == ARG_INT);

	if (control_msg_add_arg(msg, type, err)) {
		return 1;
	}
	msg->args[msg->nb_args].size = sizeof(int) +
		offsetof(control_msg_arg_t, u);
	msg->args[msg->nb_args].u.value = value;
	msg->header->total_size += msg->args[msg->nb_args].size;
	msg->nb_args += 1;
	return 0;
}

int
control_msg_add_arg_string(control_msg_t *msg, cmd_type type,
	const char *string, control_err_t *err)
{
	int sz = strlen(string)+1;
	char *dup;

	assert(control_msg_arg_type[type] == ARG_STRING);

	if (!(dup = strdup(string))) {
		error(err, "failed to dup string needed: %zd", strlen(string));
		return 1;
	}
	if (control_msg_add_arg(msg, type, err)) {
		free(dup);
		return 1;
	}
	msg->args[msg->nb_args].size = sz + offsetof(control_msg_arg_t, u);
	msg->args[msg->nb_args].u.str = dup;
	msg->header->total_size += msg->args[msg->nb_args].size;
	msg->nb_args += 1;
	return 0;
}

control_msg_t *
control_msg_error(cmd_verb verb, const char *error_txt, control_err_t *err)
{
	control_msg_t *msg;

	if (!(msg = control_msg_new(verb, VRRP_RESP_NOK))) {
		error(err, "cannot create new msg");
		goto error;
	}

	if (error_txt && control_msg_add_arg_string(msg, VRRP_CTRL_ERR,
			error_txt, err)) {
		error(err, "cannot add error '%s' to %d reply", error_txt, verb);
		goto error;
	}

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}


/**
 * Encode @msg into @buff (of size @len)
 *
 * Returns:
 *	- > 0: len of buff written (or if > len, size required)
 *	- < 0: error
 */
ssize_t
control_msg_encode(const control_msg_t *msg, char *buff, size_t len,
	control_err_t *err)
{
	control_msg_header_t *header = (control_msg_header_t *)buff;
	size_t off = 0;
	int i;

	/* set header */
	if (len < sizeof(*header)) {
		error(err, "buffer too short for header, needed %zd, got %zd",
			sizeof(*header), len);
		return sizeof(*header);
	}
	*header = *msg->header;
	off = sizeof(*header);

	/* set args */
	for (i = 0; i < msg->nb_args; ++i) {
		control_msg_arg_t *arg = (control_msg_arg_t *)(buff + off);
		size_t value_offset = offsetof(control_msg_arg_t, u);
		void *ptr;
		/* copy type and size */
		if (len < off + value_offset) {
			error(err, "buffer too short for arg #%d, needed %zd", i,
				off + value_offset);
		    return off + value_offset;
		}
		arg->type = msg->args[i].type;
		arg->size = msg->args[i].size;
		off += value_offset;
		/* copy value */
		if (len < off + msg->args[i].size - value_offset) {
			error(err, "buffer too short for arg #%d's value, needed %zd",
				i, off + msg->args[i].size - value_offset);
			return off + msg->args[i].size - value_offset;
		}
		switch (control_msg_arg_type[arg->type]) {
		case ARG_STRING:
			ptr = msg->args[i].u.str;
			break;
		case ARG_INT:
			ptr = &msg->args[i].u.value;
			break;
		default:
			error(err, "invalid argument type for arg #%d: %d", i,
				control_msg_arg_type[arg->type]);
			return -1;
		}
		memcpy(buff + off, ptr, msg->args[i].size - value_offset);
		off += msg->args[i].size - value_offset;
	}

	assert(header->total_size = off);
	return off;
}


char *
control_msg_encode_alloc(const control_msg_t *msg, size_t *len,
	control_err_t *err)
{
		buffer_t *b;

		if (!(b = buffer_new(*len))) {
			error(err, "cannot allocate memory");
			return NULL;
		}

		for (;;) {
			ssize_t encoded;
			if ((encoded = control_msg_encode(msg, b->ptr, b->total, err)) < 0)
				goto error;
			if (encoded > b->total) {
				if (buffer_grow(b, 1024)) {
					error(err, "cannot allocate more memory");
					goto error;
		       }
			} else {
				*len = encoded;
				break;
			}
       }

       return buffer_detach(b);

error:
       buffer_free(b);
       return NULL;
}



/*
 * Create message from @buff of size @len.
 * Sets @*next_size to inform caller how much data should be passed to
 *   control_msg_decode_next()
 */
control_msg_t *
control_msg_decode_header(char *buff, size_t len, size_t *next_size)
{
	control_msg_t *msg;
	control_msg_header_t *header;

	if (len < sizeof(*header)) {
		*next_size = sizeof(*header);
		return NULL;
	}

	header = (control_msg_header_t *)buff;
	if (!(msg = control_msg_new(header->verb, header->flags))) {
		return NULL;
	}

	msg->header->total_size = header->total_size;
	*next_size = header->total_size - sizeof(*header);

	return msg;
}

/*
 * Decode all args from @buff of len @len.
 * Returns:
 * - < 0: error
 * - > 0: nb of char used
 */
ssize_t
control_msg_decode_next(control_msg_t *msg, char *buff, size_t len,
	control_err_t *err)
{
	size_t off;
	control_msg_arg_t *arg;

	if (len < msg->header->total_size - sizeof(*msg->header)) {
		error(err, "invalid size: %zd, needed: %zd", len,
			msg->header->total_size - sizeof(*msg->header));
		return -1;
	}

	off = 0;
	while (off < len) {
		arg = (control_msg_arg_t *)(buff + off);
		size_t value_size;
		void *ptr;
		/* copy type/size */
		if (control_msg_add_arg(msg, arg->type, err)) {
			return -1;
		}
		msg->args[msg->nb_args].size = arg->size;
		value_size = arg->size - offsetof(control_msg_arg_t, u);
		/* copy value */
		switch(control_msg_arg_type[arg->type]) {
		case ARG_INT:
			ptr = &msg->args[msg->nb_args].u.value;
			break;
		case ARG_STRING:
			if (!(msg->args[msg->nb_args].u.str = malloc(value_size))) {
				error(err, "cannot malloc %zd", value_size);
				return -1;
			}
			ptr = msg->args[msg->nb_args].u.str;
			break;
		default:
			error(err, "invalid type %d", control_msg_arg_type[arg->type]);
			return -1;
		}
		memcpy(ptr, &arg->u, arg->size - offsetof(control_msg_arg_t, u.value));
		msg->nb_args += 1;
		off += arg->size;
	}
	return off;
}

/*
 *
 * Control part
 *
 */

struct control_ctx {
	int fd;
};

int
control_get_fd(control_ctx_t *ctx)
{
	return ctx->fd;
}

control_ctx_t *
control_new_ctx(void)
{
	control_ctx_t *ctx;
	if (!(ctx = malloc(sizeof(control_ctx_t)))) {
		return NULL;
	}
	ctx->fd = -1;
	return ctx;
}

void
control_free_ctx(control_ctx_t *ctx)
{
	if (!ctx)
		return;

	if (ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}
	free(ctx);
}

static control_ctx_t *
control_connect_bind(int do_bind, control_err_t *err)
{
	struct sockaddr_un sun;
	control_ctx_t *ctx;
	int sock;

	assert(sizeof(sun.sun_path) > strlen(VRRP_CONTROL_SOCK));

	if (!(ctx = control_new_ctx())) {
		error(err, "failed to create new context");
		return NULL;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		error(err, "failed to create socket: %s", strerror(errno));
		control_free_ctx(ctx);
		return NULL;
	}
	ctx->fd = sock;
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, VRRP_CONTROL_SOCK, strlen(VRRP_CONTROL_SOCK)+1);

	if (do_bind) {
		(void) unlink(sun.sun_path);
		if (bind(ctx->fd, (struct sockaddr *) &sun, sizeof(sun))){
			error(err, "failed to bind: %s", strerror(errno));
			control_free_ctx(ctx);
			return NULL;
		}
		if (listen(ctx->fd, 10)) {
			error(err, "failed to listen: %s", strerror(errno));
			control_free_ctx(ctx);
			return NULL;
		}
	} else {
	    if (connect(ctx->fd, (struct sockaddr *)&sun, sizeof(sun))) {
			error(err, "cannot connect to %s: %s", VRRP_CONTROL_SOCK,
				strerror(errno));
		    control_free_ctx(ctx);
		    return NULL;
	    }
	}
	return ctx;

}

control_ctx_t *
control_connect(control_err_t *err)
{
	return control_connect_bind(0, err);
}

control_ctx_t *
control_bind(control_err_t *err)
{
	return control_connect_bind(1, err);
}

control_ctx_t *
control_accept(const control_ctx_t *father)
{
	control_ctx_t *child;
	int fd;

	if (!(child = control_new_ctx())) {
		return NULL;
	}

	if ((fd = accept(father->fd, NULL, 0)) == -1) {
		control_free_ctx(child);
	}
	child->fd = fd;
	return child;
}

int
control_wait_on_socket(int sk, int timeout, control_err_t *err)
{
	fd_set rd;
	struct timeval tv;
	int r = 0;

	if (!timeout) return 1;

	FD_ZERO(&rd);
	FD_SET(sk, &rd);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	r = select(sk+1, &rd, NULL, NULL, &tv);
	if (r == -1) {
		error(err, "select failed: %s", strerror(errno));
		return -1;
	}
	else if (FD_ISSET(sk, &rd)) {
		return 0;
	}
	else {
		return 1;
	}
}


int
control_send_wait(control_ctx_t *ctx, control_msg_t *msg, control_err_t *err)
{
	char buff[256];
	ssize_t s;
	ssize_t len;
	int fd = control_get_fd(ctx);
	int ret = -1;

	/* encode */
	if ((len = control_msg_encode(msg, buff, sizeof(buff), err)) < 0)
		goto out;

	if (len > sizeof(buff)) {
		error(err, "buffer to small: got %zd, required at least %zd",
			sizeof(buff), len);
		goto out;
	}

	/* send */
	s = send(fd, buff, len, 0);
	if (s == -1) {
		error(err, "failed to send %zd: %s", len, strerror(errno));
		goto out;
	}
	if (s != len) {
		error(err, "failed to send %zd: sent %zd", len, s);
		goto out;
	}

	/* wait for answer */
	if ((ret = control_wait_on_socket(fd, VRRP_CONTROL_SOCK_TIMEOUT, err)) < -1) {
		goto out;
	} else if (ret > 0) {
		error(err, "timeout (%d)", VRRP_CONTROL_SOCK_TIMEOUT);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * Receive header.
 *
 * Returns:
 *  < 0 : read error
 *  = 0 : socket closed()
 *  > 0 : nb of char read
 *			*msg set to allocated msg (or NULL if err)
 *			*next is set to size of message to be read
 */
ssize_t
control_recv_header(control_ctx_t *ctx, control_msg_t **msg, size_t *next,
	control_err_t *err)
{
	char buff[HEADER_SIZE];
	int fd = control_get_fd(ctx);
	ssize_t r;

	/* receive header */
	r = read(fd, buff, HEADER_SIZE);
	if (r == -1) {
		error(err, "failed to read header: %s", strerror(errno));
		goto out;
	}
	if (r == 0) {
		error(err, "connection closed by peer");
		goto out;
	}
	if (r != HEADER_SIZE) {
		error(err, "failed to read header: expected %d, got %zd",
			HEADER_SIZE, r);
		goto out;
	}

	/* parse header */
	if (!(*msg = control_msg_decode_header(buff, r, next))) {
		error(err, "failed to decode header");
		goto out;
	}

out:
	return r;
}

/*
 * Receive args and feed msg
 *
 * Returns nb of char read (or -1 if read error), and set *next with nb of
 * char parsed (i.e. if != of given *next it means an error occured)
 */
ssize_t
control_recv_args(control_ctx_t *ctx, control_msg_t *msg, size_t *next,
	control_err_t *err)
{
	char *args_buffer = NULL;
	int fd = control_get_fd(ctx);
	ssize_t r = -1;

	/* receive args */
	if (!(args_buffer = malloc(*next))) {
		error(err, "failed to malloc for %zd", *next);
		goto out;
	}
	r = read(fd, args_buffer, *next);
	if (r == -1) {
		error(err, "failed to read args: %s", strerror(errno));
		goto out;
	}
	if (r != *next) {
		error(err, "failed to read args: r=%zd, wanted:%zd", r, *next);
		goto out;
	}

	/* parse args */
	*next = control_msg_decode_next(msg, args_buffer, *next, err);

out:
	free(args_buffer);
	return r;
}

control_msg_t *
control_recv_parse(control_ctx_t *ctx, control_err_t *err)
{
	control_msg_t *msg = NULL;
	size_t next;
	size_t orig_next;
	ssize_t r;

	/* receive header */
	if ((r = control_recv_header(ctx, &msg, &next, err)) <= 0 || !msg) {
		goto error;
	}

	/* receive args */
	orig_next = next;
	if ((r = control_recv_args(ctx, msg, &next, err)) != orig_next ||
		next != orig_next) {
		goto error;
	}

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}
