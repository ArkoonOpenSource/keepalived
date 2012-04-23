/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP control (daemon side)
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "vrrp_data.h"
#include "vrrp_control.h"
#include "vrrp.h"
#include "memory.h"
#include "utils.h"
#include "logger.h"
#include "../libkacontrol/libkacontrol.h"

static int vrrp_control_accept(thread_t * thread);
static int vrrp_control_recv_msg(thread_t * thread);
static int vrrp_control_recv_args(thread_t * thread);
static int vrrp_control_send(thread_t * thread);

#define TIMER_CONTROL_SEC (3 * TIMER_HZ)

#define NO_VRRP_INSTANCE "No vrrp instance was found\n"

#define error(fmt,...) \
	log_message(LOG_INFO, "%s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#ifdef _DEBUG_
#define debug(fmt,...) \
	log_message(LOG_INFO, "%s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define debug(fmt,...) do { } while (0)
#endif


static struct
{
	control_ctx_t *cctx;
} control_handle;


typedef struct {
	/* handle connection */
	control_ctx_t *control_ctx;
	/* handle message decoding/building/encoding */
	control_msg_t *msg;
	/* Buffer used for sending. Free'd after sending or in error path */
	char *buffer;
	size_t buffer_sz;
	/* size of next chunk used for reading */
	size_t next;
} vrrp_ctx_t;

static int
update_non_block(int fd, int set /* 1=set 0=unset */)
{
	debug("");

	int flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		error("fcntl(%d,GETFL): %s", fd, strerror(errno));
		return -1;
	}
	if (set) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}

	if (fcntl(fd, F_SETFL, flags) == -1) {
		error("fcntl(%d,SETFL): %s", fd, strerror(errno));
		return -1;
	}
	return 0;
}



/* Open and bind the unix socket return -1 on error */
int
vrrp_control_init(void)
{
	debug("Open control socket");
	control_err_t *err = control_err_new(512);

	if (!(control_handle.cctx = control_bind(err))) {
		error("Failed to bind control: %s", err ? err->buff : "");
		control_err_free(err);
		return -1;
	}
	control_err_free(err);

	thread_add_read(master, vrrp_control_accept, NULL,
		control_get_fd(control_handle.cctx), TIMER_CONTROL_SEC);
	return 0;
}

/* close the unix socket */
int
vrrp_control_close(void)
{
	debug("Close control socket");
	control_free_ctx(control_handle.cctx);
	return 0;
}

static vrrp_ctx_t *
vrrp_control_new(void)
{
	vrrp_ctx_t *vrrp_ctx;

	if (!(vrrp_ctx = malloc(sizeof(*vrrp_ctx)))) {
		error("");
		return NULL;
	}
	vrrp_ctx->buffer = NULL;
	vrrp_ctx->buffer_sz = 0;
	vrrp_ctx->control_ctx = NULL;
	vrrp_ctx->msg = NULL;
	return vrrp_ctx;
}

static void
vrrp_control_free(vrrp_ctx_t *vrrp_ctx)
{
	free(vrrp_ctx->buffer);
	control_msg_free(vrrp_ctx->msg);
	control_free_ctx(vrrp_ctx->control_ctx);
	free(vrrp_ctx);
}

#define ADD_INT(msg, arg, value) \
	do { \
		if (control_msg_add_arg_int(msg, arg, value, NULL)) { \
			error("adding %d", arg); \
			goto error; \
		} \
	} while (0)

#define ADD_STRING(msg, arg, value) \
	do { \
		if (control_msg_add_arg_string(msg, arg, value, NULL)) {\
			error("adding %d", arg); \
			goto error; \
		} \
	} while (0)

static int
vrrp_control_send_answer(vrrp_ctx_t *vrrp_ctx, control_msg_t *answer)
{
	size_t len = 1024;

	if (!(vrrp_ctx->buffer = control_msg_encode_alloc(answer, &len, NULL))) {
		error("Failed to encode answer");
		goto error;
	}
	debug("need to send %zd", len);
	vrrp_ctx->buffer_sz = len;

	thread_add_write(master, vrrp_control_send, vrrp_ctx,
			 control_get_fd(vrrp_ctx->control_ctx),
			 TIMER_CONTROL_SEC);
	return 0;

error:
	return -1;
}

int
vrrp_control_handle_msg(vrrp_ctx_t *vrrp_ctx)
{
	control_msg_t *msg = vrrp_ctx->msg;
	control_msg_t *answer = NULL;

	debug("verb=%d, type=%d", msg->header->verb, msg->args[0].type);
	switch (msg->header->verb) {
	default:
		return -1;
	}

	/* release query */
	control_msg_free(vrrp_ctx->msg);
	vrrp_ctx->msg = NULL;

	if (!answer) {
		debug("No answer to send");
		vrrp_control_free(vrrp_ctx);
	} else {
		if (vrrp_control_send_answer(vrrp_ctx, answer) != 0) {
			vrrp_control_free(vrrp_ctx);
		}
		control_msg_free(answer);
	}

	return 0;
}

static int
vrrp_control_send(thread_t * thread)
{
	vrrp_ctx_t *vrrp_ctx = THREAD_ARG(thread);

	int fd = control_get_fd(vrrp_ctx->control_ctx);
	ssize_t s;

	if (thread->type == THREAD_WRITE_TIMEOUT) {
		error("write timeout");
		goto error;
	}

	s = send(fd, vrrp_ctx->buffer, vrrp_ctx->buffer_sz, 0);

	if (s == -1) {
		error("Failed to send %zd to fd=%d: %s", vrrp_ctx->buffer_sz,
		      fd, strerror(errno));
		goto error;
	}
	if (s != vrrp_ctx->buffer_sz) {
		error("Failed to send %zd to fd=%d: sent %zd",
		      vrrp_ctx->buffer_sz, fd, s);
		goto error;
	}
	/* free buffer: no longer used for sending message */
	free(vrrp_ctx->buffer);
	vrrp_ctx->buffer = NULL;
	vrrp_ctx->buffer_sz = 0;

	/* Re-enable recv */
	thread_add_read(master, vrrp_control_recv_msg, vrrp_ctx, fd,
			TIMER_CONTROL_SEC);
	return 0;

error:
	vrrp_control_free(vrrp_ctx);
	return -1;
}

static int
vrrp_control_recv_msg(thread_t * thread)
{
	vrrp_ctx_t *vrrp_ctx = THREAD_ARG(thread);
	ssize_t r;

	debug("");

	if (thread->type == THREAD_READ_TIMEOUT) {
		goto error;
	}

	r = control_recv_header(vrrp_ctx->control_ctx, &vrrp_ctx->msg,
		&vrrp_ctx->next, NULL);

	if (r < 0) {
		error("read() returned %d: %s", r, strerror(errno));
		goto error;
	}
	if (r == 0) {
		/* peer closed connection */
		goto error;
	}

	if (!vrrp_ctx->msg) {
		error("Failed to parse header");
		goto error;
	}

	thread_add_read(master, vrrp_control_recv_args, vrrp_ctx,
			control_get_fd(vrrp_ctx->control_ctx), TIMER_CONTROL_SEC);
	return 0;

error:
	vrrp_control_free(vrrp_ctx);
	return -1;
}

static int
vrrp_control_recv_args(thread_t *thread)
{
	vrrp_ctx_t *vrrp_ctx = THREAD_ARG(thread);
	ssize_t r;
	size_t next;
	int fd = control_get_fd(vrrp_ctx->control_ctx);

	debug("");

	if (thread->type == THREAD_READ_TIMEOUT) {
		error("read timeout while waiting for args");
		goto error;
	}

	next = vrrp_ctx->next;
	r = control_recv_args(vrrp_ctx->control_ctx, vrrp_ctx->msg, &next, NULL);

	if (r < 0) {
		error("Failed to read args fd=%d: errno=%s", fd,
		      strerror(errno));
		goto error;
	} else if (next != vrrp_ctx->next) {
		error("Failed to read args %zd: rc=%zd", vrrp_ctx->next, next);
		goto error;
	}

	return vrrp_control_handle_msg(vrrp_ctx);

error:
	vrrp_control_free(vrrp_ctx);
	return -1;
}

static int
vrrp_control_accept(thread_t * thread)
{
	vrrp_ctx_t *vrrp_ctx;
	int fd;
	int rc = -1;

	if (thread->type == THREAD_READ_TIMEOUT) {
		rc = 0;
		goto out;
	}

	if (!(vrrp_ctx = vrrp_control_new())) {
		error("Failed to create new control context for accept");
		goto out;
	}

	debug("");

	if (!(vrrp_ctx->control_ctx = control_accept(control_handle.cctx))) {
		error("Failed to accept connecion");
		goto out;
	}

	fd = control_get_fd(vrrp_ctx->control_ctx);

	/* Set socket to non-blocking */
	if (update_non_block(fd, 1) == -1) {
		error("cannot set socket to non-blocking");
	}

	thread_add_read(master, vrrp_control_recv_msg, vrrp_ctx, fd,
			TIMER_CONTROL_SEC);
out:
	/* re-schedule accept */
	thread_add_read(master, vrrp_control_accept, NULL,
		control_get_fd(control_handle.cctx), TIMER_CONTROL_SEC);
	return rc;
}

