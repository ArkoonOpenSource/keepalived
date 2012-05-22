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
#include "vrrp_if.h"
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

/*
 * Info part
 */
static control_msg_t *
vrrp_control_info(vrrp_ctx_t *vrrp_ctx)
{
	control_msg_t *msg;
	control_msg_t *msg_r = vrrp_ctx->msg;
	vrrp_rt *vrrp;
	element e;
	int i, vrid = 0;

	if (LIST_ISEMPTY(vrrp_data->vrrp)) {
		return control_msg_error(VRRP_GET_INFO, NO_VRRP_INSTANCE, NULL);
	}

	if (!(msg = control_msg_new(VRRP_GET_INFO, VRRP_RESP_OK)))
		goto error;

	for (i=0; i < msg_r->nb_args; i++) {
		if (msg_r->args[i].type == VRRP_CTRL_VRID) {
			vrid = MSG_GET_INT(msg_r, i);
			break;
		}
	}

	for(e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		if ((vrid > 0) && (vrid != vrrp->vrid))
			continue;

		ADD_STRING(msg, VRRP_CTRL_IF_NAME, IF_NAME(vrrp->ifp));
		ADD_STRING(msg, VRRP_CTRL_INAME, vrrp->iname);
		ADD_INT(msg, VRRP_CTRL_VRID, vrrp->vrid);
		ADD_INT(msg, VRRP_CTRL_STATE, vrrp->state);
		ADD_INT(msg, VRRP_CTRL_INIT_STATE, vrrp->init_state);
		ADD_INT(msg, VRRP_CTRL_RUN_PRIO, vrrp->effective_priority);
		ADD_INT(msg, VRRP_CTRL_NOPREEMPT, vrrp->nopreempt);
		if (vrrp->nopreempt == 0) {
			ADD_INT(msg, VRRP_CTRL_PREEMPT_DELAY, vrrp->preempt_delay / TIMER_HZ);
		}
		ADD_INT(msg, VRRP_CTRL_ADV_INTERVAL, vrrp->adver_int / TIMER_HZ);
		ADD_INT(msg, VRRP_CTRL_GARP_DELAY, vrrp->garp_delay / TIMER_HZ);
	}

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}

/*
 * GROUP
 */
static int
vrrp_control_add_group(control_msg_t *msg, vrrp_sgroup *vgroup)
{
	element e;

	ADD_STRING(msg, VRRP_CTRL_GNAME, vgroup->gname);

	for (e = LIST_HEAD(vgroup->index_list); e; ELEMENT_NEXT(e)) {
		vrrp_rt *vrrp = ELEMENT_DATA(e);
		ADD_STRING(msg, VRRP_CTRL_INAME, vrrp->iname);
	}
	if (vgroup->notify_exec) {
		if (vgroup->script_backup)
			ADD_STRING(msg, VRRP_CTRL_NOTIFY_BACKUP, vgroup->script_backup);
		if (vgroup->script_master)
			ADD_STRING(msg, VRRP_CTRL_NOTIFY_MASTER, vgroup->script_master);
		if (vgroup->script_fault)
			ADD_STRING(msg, VRRP_CTRL_NOTIFY_FAULT, vgroup->script_fault);
	}

	/* live values */
	ADD_INT(msg, VRRP_CTRL_STATE, vgroup->state);

	return 0;

error:
	return 1;
}

/*
 * GROUPS
 */
static control_msg_t *
vrrp_control_get_groups(vrrp_ctx_t *vrrp_ctx)
{
	control_msg_t *msg;
	element e;

	if (LIST_ISEMPTY(vrrp_data->vrrp_sync_group)) {
		return control_msg_error(VRRP_GET_GROUPS, "No vrrp group was found\n",
			NULL);
	}

	if (!(msg = control_msg_new(VRRP_GET_GROUPS, VRRP_RESP_OK)))
		goto error;

	for (e = LIST_HEAD(vrrp_data->vrrp_sync_group); e; ELEMENT_NEXT(e)) {
		vrrp_sgroup *vgroup = ELEMENT_DATA(e);

		if (vrrp_control_add_group(msg, vgroup))
			goto error;
	}

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}

/*
 * Virtual IPs
 */
static control_msg_t *
vrrp_control_vips(vrrp_ctx_t *vrrp_ctx)
{
	control_msg_t *msg;
	vrrp_rt *vrrp;
	element e, e1;
	ip_address *ip;
	char addr_str[INET6_ADDRSTRLEN];

	if (LIST_ISEMPTY(vrrp_data->vrrp)) {
		return control_msg_error(VRRP_GET_ADDR, NO_VRRP_INSTANCE, NULL);
	}

	if (!(msg = control_msg_new(VRRP_GET_ADDR, VRRP_RESP_OK)))
		goto error;

	for(e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);
		ADD_STRING(msg, VRRP_CTRL_INAME, vrrp->iname);
		if (!VRRP_VIP_ISSET(vrrp) || LIST_ISEMPTY(vrrp->vip)) {
			ADD_STRING(msg, VRRP_CTRL_ADDR6, "None");
		} else {
			for (e1 = LIST_HEAD(vrrp->vip); e1; ELEMENT_NEXT(e1)) {
				ip = ELEMENT_DATA(e1);
				switch (IP_FAMILY(ip)) {
					case AF_INET6:
						inet_ntop(AF_INET6, &ip->u.sin6_addr, addr_str, INET6_ADDRSTRLEN);
						ADD_STRING(msg, VRRP_CTRL_ADDR6, addr_str);
						break;
					case AF_INET:
						inet_ntop(AF_INET, &ip->u.sin.sin_addr, addr_str, INET_ADDRSTRLEN);
						ADD_STRING(msg, VRRP_CTRL_ADDR, addr_str);
						break;
					default:
						goto error;
				}
			}
		}
	}

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}

/*
 * Set priority actions
 */

static int
vrrp_control_set_manual_priority(int prio)
{
	int err = 0;
	element e;
	vrrp_rt *vrrp;

	if (prio < -1 || prio > 255)
		return -1;

	log_message(LOG_INFO, "set manual priority to %d for all VRRP instances",
		prio);

	for(e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp = ELEMENT_DATA(e);

		if (vrrp->sync) {
			log_message(LOG_INFO, "VRRP_Instance(%s) Cannot set"
				" manual priority because of sync group",
				vrrp->iname);
			continue;
		}

		if (vrrp->manual_priority == prio)
			err = 1;
		else
			vrrp->manual_priority = prio;
	}

	return err;
}

static control_msg_t *
vrrp_control_setprio(vrrp_ctx_t *vrrp_ctx)
{
	control_msg_t *msg = vrrp_ctx->msg;
	control_msg_t *answer;
	int ret;

	if (msg->nb_args != 1)
		return NULL;

	if (LIST_ISEMPTY(vrrp_data->vrrp))
		return control_msg_error(VRRP_SET_PRIO, NO_VRRP_INSTANCE, NULL);

	ret = vrrp_control_set_manual_priority(MSG_GET_INT(msg, 0));
	if (ret == -1)
		return control_msg_error(VRRP_SET_PRIO, "Invalid priority value\n",
			NULL);

	if (!(answer = control_msg_new(VRRP_SET_PRIO, VRRP_RESP_OK)))
		return NULL;

	ADD_INT(answer, VRRP_CTRL_PRIO, ret);

	return answer;

error:
	control_msg_free(answer);
	return NULL;
}

/*
 * TRACKING
 */
static int
vrrp_control_interface_tracking(control_msg_t *msg, vrrp_rt *vrrp)
{
	element e;
	int found = 0;
	for (e = LIST_HEAD(vrrp->track_ifp); e; ELEMENT_NEXT(e)) {
		tracked_if *tip = ELEMENT_DATA(e);
		if (!tip->ifp)
			continue;
		found = 1;
		ADD_STRING(msg, VRRP_CTRL_IF_NAME, tip->ifp->ifname);
		if (tip->weight < 0 && !IF_ISUP(tip->ifp)) {
			ADD_INT(msg, VRRP_CTRL_IFUP, 0);
			ADD_INT(msg, VRRP_CTRL_WEIGHT, tip->weight);
		} else {
			ADD_INT(msg, VRRP_CTRL_IFUP, 1);
		}
	}

	return found;

error:
	return -1;
}

static int
vrrp_control_script_tracking(control_msg_t *msg, vrrp_script *vscript)
{
	ADD_STRING(msg, VRRP_CTRL_SNAME, vscript->sname);
	ADD_STRING(msg, VRRP_CTRL_SCRIPT_COMMAND, vscript->script);
	ADD_INT(msg, VRRP_CTRL_SCRIPT_RISE, vscript->rise);
	ADD_INT(msg, VRRP_CTRL_SCRIPT_FALL, vscript->fall);
	ADD_INT(msg, VRRP_CTRL_SCRIPT_RESULT, vscript->result);
	ADD_INT(msg, VRRP_CTRL_WEIGHT, vscript->weight);
	return 0;

error:
	return 1;
}

static control_msg_t *
vrrp_control_get_tracking(vrrp_ctx_t *vrrp_ctx)
{
	control_msg_t *msg;
	element e;

	if (!(msg = control_msg_new(VRRP_GET_TRACKING, VRRP_RESP_OK)))
		goto error;

	/* Interface tracking */
	for (e = LIST_HEAD(vrrp_data->vrrp); e; ELEMENT_NEXT(e)) {
		vrrp_rt *vrrp = ELEMENT_DATA(e);
		int rc = vrrp_control_interface_tracking(msg, vrrp);

		if (rc < 0)
			goto error;

		/* stop at first if group to avoid duplicates */
		if (vrrp->sync && rc == 1)
			break;
	}

	/* Script tracking */
	for (e = LIST_HEAD(vrrp_data->vrrp_script); e; ELEMENT_NEXT(e)) {
		vrrp_script *vscript = ELEMENT_DATA(e);

		if (vrrp_control_script_tracking(msg, vscript))
			goto error;
	}

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}

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
	case VRRP_GET_INFO:
		answer = vrrp_control_info(vrrp_ctx);
		break;
	case VRRP_GET_GROUPS:
		answer = vrrp_control_get_groups(vrrp_ctx);
		break;
	case VRRP_GET_TRACKING:
		answer = vrrp_control_get_tracking(vrrp_ctx);
		break;
	case VRRP_GET_ADDR:
		answer = vrrp_control_vips(vrrp_ctx);
		break;
	case VRRP_SET_PRIO:
		answer = vrrp_control_setprio(vrrp_ctx);
		break;
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

