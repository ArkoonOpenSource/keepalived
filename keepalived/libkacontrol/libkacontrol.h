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

#ifndef _CONTROL_H
#define _CONTROL_H

#include <stdint.h>

#define VRRP_CONTROL_SOCK			"/var/run/keepalived-vrrp-control"
#define VRRP_CONTROL_SOCK_TIMEOUT	3

#define ALL_VRIDS	0

#define	VRRP_NONE		0x0000
#define	VRRP_REQ		0x0001
#define	VRRP_RESP_OK	0x0002
#define	VRRP_RESP_NOK	0x0004
#define	VRRP_NOREPLY	0x0008

/* VRRP state machine -- rfc2338.6.4 */
#define VRRP_CONTROL_STATE_INIT			0	/* rfc2338.6.4.1 */
#define VRRP_CONTROL_STATE_BACK			1	/* rfc2338.6.4.2 */
#define VRRP_CONTROL_STATE_MAST			2	/* rfc2338.6.4.3 */


typedef enum CMD_VERB
{
	VRRP_GET_INFO,
} cmd_verb;

typedef enum CMD_TYPE
{
	VRRP_CTRL_NONE,
	VRRP_CTRL_ERR,
	VRRP_CTRL_IF_NAME,
	VRRP_CTRL_INAME,
	VRRP_CTRL_VRID,
	VRRP_CTRL_INIT_STATE,
	VRRP_CTRL_STATE,
	VRRP_CTRL_ADDR6,
	VRRP_CTRL_ADDR,
	VRRP_CTRL_RUN_PRIO,
	VRRP_CTRL_NOPREEMPT,
	VRRP_CTRL_PREEMPT_DELAY,
	VRRP_CTRL_ADV_INTERVAL,
	VRRP_CTRL_GARP_DELAY,
} cmd_type;

typedef enum
{
	ARG_INT,
	ARG_STRING,
} arg_type_t;

static const arg_type_t control_msg_arg_type[] =
{
	[VRRP_CTRL_NONE] = ARG_INT,
	[VRRP_CTRL_ERR] = ARG_STRING,
	[VRRP_CTRL_IF_NAME] = ARG_STRING,
	[VRRP_CTRL_INAME] = ARG_STRING,
	[VRRP_CTRL_VRID] = ARG_INT,
	[VRRP_CTRL_INIT_STATE] = ARG_INT,
	[VRRP_CTRL_STATE] = ARG_INT,
	[VRRP_CTRL_ADDR6] = ARG_STRING,
	[VRRP_CTRL_ADDR] = ARG_STRING,
	[VRRP_CTRL_RUN_PRIO] = ARG_INT,
	[VRRP_CTRL_NOPREEMPT] = ARG_INT,
	[VRRP_CTRL_PREEMPT_DELAY] = ARG_INT,
	[VRRP_CTRL_ADV_INTERVAL] = ARG_INT,
	[VRRP_CTRL_GARP_DELAY] = ARG_INT,
};

typedef uint32_t flags_t;

#define HEADER_SIZE (3 * 4)

typedef struct control_msg_header
{
	uint32_t total_size;
	flags_t flags;
	cmd_verb verb;
} __attribute__((packed)) control_msg_header_t;

typedef struct control_msg_arg
{
	uint32_t size;
	cmd_type type;
	union {
		int value;
		char *str;
	} u;
} __attribute__((packed)) control_msg_arg_t;

#define MSG_GET_INT(msg, i)	((msg)->args[i].u.value)
#define MSG_GET_STRING(msg, i)	((msg)->args[i].u.str)

/* Control message */
struct control_msg_header;
struct control_msg_arg;
typedef struct {
	struct control_msg_header *header;
	int nb_args;
	struct control_msg_arg *args;
} control_msg_t;

/* Error part */
typedef struct {
	char *buff;
	size_t sz;
} control_err_t;
control_err_t *control_err_init(control_err_t *err, char *buff, size_t sz);
control_err_t *control_err_new(size_t sz);
void control_err_free(control_err_t *err);

/* Message part */
control_msg_t *control_msg_new(cmd_verb, cmd_type);
void control_msg_free(control_msg_t *msg);
int control_msg_add_arg_int(control_msg_t *msg, cmd_type type, int value,
	control_err_t *err);
int control_msg_add_arg_string(control_msg_t *msg, cmd_type type,
	const char *, control_err_t *err);
control_msg_t *control_msg_error(cmd_verb verb, const char *error, control_err_t *err);
ssize_t control_msg_encode(const control_msg_t *msg, char *buff, size_t len, control_err_t *err);
control_msg_t *control_msg_decode_header(char *buff, size_t len, size_t *next_size);
ssize_t control_msg_decode_next(control_msg_t *msg, char *buff, size_t len, control_err_t *err);
char * control_msg_encode_alloc(const control_msg_t *msg, size_t *len, control_err_t *err);

/* Connection part */

typedef struct control_ctx control_ctx_t;

control_ctx_t *control_connect(control_err_t *err);
control_ctx_t *control_bind(control_err_t *err);
control_ctx_t *control_accept(const control_ctx_t *);
void control_free_ctx(control_ctx_t *);
int control_get_fd(control_ctx_t *);

ssize_t control_recv_header(control_ctx_t *ctx, control_msg_t **msg,
	size_t *next, control_err_t *err);
ssize_t control_recv_args(control_ctx_t *ctx, control_msg_t *msg, size_t *next,
	control_err_t *err);
int control_send_wait(control_ctx_t *ctx, control_msg_t *msg,
	control_err_t *err);
control_msg_t *control_recv_parse(control_ctx_t *ctx, control_err_t *err);

/* Dynamic buffer */

typedef struct {
	char *ptr;
	size_t cur;
	size_t total;
} buffer_t;

buffer_t * buffer_new(size_t sz);
char * buffer_detach(buffer_t *buff);
void buffer_free(buffer_t *buff);
int buffer_grow(buffer_t *buff, size_t more);

#endif
