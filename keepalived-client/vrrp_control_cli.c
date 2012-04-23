/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        VRRP control (keepalived client side)
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



#define debug(fmt,...) \
	fprintf(stderr, "%s:%d: " fmt "\n", __FUNCTION__, __LINE__, ## __VA_ARGS__)

#define error(fmt,...) \
	fprintf(stderr, "ERROR(%s:%d): " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define fill_buff(b, size_b, used, fmt, ...) \
	used = snprintf(b, size_b, fmt, ##__VA_ARGS__); \
	size_b -= used; \
	b += used;

/*
 * Dynamic buffer
 */

#define BUFF_SIZE	1024


#define BUFF_ADD(b, fmt, ...) \
	do { \
		int try = 1; \
		do { \
			ssize_t len = snprintf(b->ptr + b->cur, b->total - b->cur, \
					fmt, ##__VA_ARGS__); \
			if (len >= 0 && len < b->total - b->cur) { \
				b->cur += len; \
				try = 0; \
			} else if (len < 0 || buffer_grow(b, len)) { \
				goto error; \
			} \
		} while (try--); \
	} while (0)

#define BUFF_ADD_NL(b, fmt, ...) \
	BUFF_ADD(b, fmt "\n", ##__VA_ARGS__) \

#define BUFF_MSG_YESNO(b, msg, i, s) \
	BUFF_ADD_NL(b, s ": %-3s", MSG_GET_INT(msg, i) ? "Yes" : "No")

#define BUFF_MSG_INT(b, msg, i, s) \
	BUFF_ADD_NL(b, s ": %d", MSG_GET_INT(msg, i))

#define BUFF_MSG_STRING(b, msg, i, s) \
	BUFF_ADD_NL(b, s ": %s", MSG_GET_STRING(msg, i))

/*
 * Actions
 */

typedef struct {
	int argc;
	char **argv;
	control_ctx_t *cctx;
	control_err_t *err;
} action_ctx_t;


typedef struct {
	const char *name;
	const char *description;
	control_msg_t *(*send)(action_ctx_t *);
	char *(*recv)(action_ctx_t *, control_msg_t *);
} action_t;



static const char *
print_state(int vrrp_state, int translate)
{
	switch(vrrp_state) {
	case VRRP_STATE_MAST:
		return "MASTER";
	case VRRP_STATE_BACK:
		return "BACKUP";
	case VRRP_STATE_FAULT:
		return translate ? "Disconnected" : "FAULT";
	case VRRP_STATE_INIT:
		return "INIT";
	case VRRP_STATE_GOTO_MASTER:
		return "GOTO_MASTER";
	case VRRP_STATE_LEAVE_MASTER:
		return "LEAVE_MASTER";
	case VRRP_STATE_GOTO_FAULT:
		return "GOTO_FAULT";
	}
	return "Invalid State";
}

static char *
check_recv_msg(control_msg_t *msg, cmd_verb verb)
{
	if (msg->header->verb != verb)
		return strdup("ERR: Unknown response received\n");

	if (msg->nb_args == 0)
		return strdup("ERR: Wrong response format; no arguments found\n");

	if (msg->header->flags & VRRP_RESP_NOK) {
		if (msg->nb_args != 1)
			return strdup("ERR: Wrong response format\n");

		switch (msg->args[0].type) {
			case VRRP_CTRL_ERR:
				return strdup(MSG_GET_STRING(msg, 0));
			default:
				return strdup("Request failed!\n");
		}
	}

	return NULL;
}

/*
 * Groups
 */
control_msg_t *
send_groups(action_ctx_t *actx)
{
	control_msg_t *msg;

	if (!(msg = control_msg_new(VRRP_GET_GROUPS, VRRP_REQ)))
		goto error;

	if (control_msg_add_arg_int(msg, VRRP_CTRL_NONE, 0, actx->err))
		goto error;

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}

char *
recv_groups(action_ctx_t *actx, control_msg_t *msg)
{
	buffer_t *b;
	int instance = 0;
	int i;
	char *check;

	if (check = check_recv_msg(msg, VRRP_GET_GROUPS))
		return check;

	if (!(b = buffer_new(BUFF_SIZE)))
		goto error;

	for (i = 0; i < msg->nb_args; i++) {
		switch (msg->args[i].type) {
		case VRRP_CTRL_GNAME:
			BUFF_MSG_STRING(b, msg, i, "VRRP Group");
			break;
		case VRRP_CTRL_INAME:
			if (!instance++)
				BUFF_ADD_NL(b, "   Virtual Routers in group:");
			BUFF_ADD_NL(b, "      %s", MSG_GET_STRING(msg, i));
			break;
		case VRRP_CTRL_NOTIFY_BACKUP:
			BUFF_MSG_STRING(b, msg, i,"   Notify Backup");
			break;
		case VRRP_CTRL_NOTIFY_MASTER:
			BUFF_MSG_STRING(b, msg, i,"   Notify Master");
			break;
		case VRRP_CTRL_NOTIFY_FAULT:
			BUFF_MSG_STRING(b, msg, i,"   Notify Fault ");
			break;
		case VRRP_CTRL_STATE:
			BUFF_ADD_NL(b, "   Status       : %s",
					print_state(MSG_GET_INT(msg, i), 0));
			break;
		default:
			error("unhandled type %d", msg->args[i].type);
		}
	}

	return buffer_detach(b);

error:
	buffer_free(b);
	return NULL;
}

/*
 * Tracking
 */
const char *
print_script_result(int result, int rise, int fall)
{
	switch (result) {
	case VRRP_SCRIPT_STATUS_INIT:
		return "INIT";
	case VRRP_SCRIPT_STATUS_INIT_GOOD:
		return "INIT/GOOD";
	case VRRP_SCRIPT_STATUS_DISABLED:
		return "DISABLED";
	}
	return (result >= rise ? "GOOD" : "BAD");
}

char *
recv_tracking(action_ctx_t *actx, control_msg_t *msg)
{
	buffer_t *b;
	int instance = 0;
	int i;
	int fall;
	int rise;

	if (!(b = buffer_new(BUFF_SIZE)))
		goto error;

	for (i = 0; i < msg->nb_args; i++) {
		switch (msg->args[i].type) {
		case VRRP_CTRL_IF_NAME:
			BUFF_MSG_STRING(b, msg, i, "Interface");
			break;
		case VRRP_CTRL_IFUP:
			BUFF_ADD_NL(b, "   Result\t: %s", MSG_GET_INT(msg, i) ? "UP" : "DOWN");
			break;
		case VRRP_CTRL_WEIGHT:
			BUFF_MSG_INT(b, msg, i, "   Offset\t");
			break;
		case VRRP_CTRL_SNAME:
			BUFF_MSG_STRING(b, msg, i, "VRRP Script");
			break;
		case VRRP_CTRL_SCRIPT_COMMAND:
			BUFF_ADD_NL(b, "   Command\t: \"%s\"", MSG_GET_STRING(msg, i));
			rise = -1;
			fall = -1;
			break;
		case VRRP_CTRL_SCRIPT_RISE:
			rise = MSG_GET_INT(msg, i);
			BUFF_MSG_INT(b, msg, i, "   Rise\t\t");
			break;
		case VRRP_CTRL_SCRIPT_FALL:
			fall = MSG_GET_INT(msg, i);
			BUFF_MSG_INT(b, msg, i, "   Fall\t\t");
			break;
		case VRRP_CTRL_SCRIPT_RESULT:
			BUFF_ADD_NL(b, "   Result\t: %s (%d)",
				print_script_result(MSG_GET_INT(msg, i), rise, fall),
				MSG_GET_INT(msg, i));
			break;
		default:
			error("unhandled type %d", msg->args[i].type);
		}
	}

	return buffer_detach(b);

error:
	buffer_free(b);
	return NULL;
}

control_msg_t *
send_tracking(action_ctx_t *actx)
{
	control_msg_t *msg;

	if (!(msg = control_msg_new(VRRP_GET_TRACKING, VRRP_REQ)))
		return NULL;

	if (control_msg_add_arg_int(msg, VRRP_CTRL_NONE, 0, actx->err))
		goto error;

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}



/*
 * Info (instances)
 */
static const char *fmt_info[] =
{
	[VRRP_CTRL_IF_NAME] = "Interface : %s",
	[VRRP_CTRL_INAME] = "\n   Instance name\t: %-12s",
	[VRRP_CTRL_VRID] = "\t\tVRID\t\t: %d",
	[VRRP_CTRL_STATE] = "\n   State\t\t: %-12s",
	[VRRP_CTRL_INIT_STATE] = "\t\tInit state\t: %s",
	[VRRP_CTRL_RUN_PRIO] = "\n   Running Priority\t: %-12d",
	[VRRP_CTRL_ADDR6] = "\n   Master IPv6\t\t: %s",
	[VRRP_CTRL_ADDR] = "\n   Master IPv4\t\t: %s",
	[VRRP_CTRL_NOPREEMPT] = "\n   Preempt\t\t: %-12s",
	[VRRP_CTRL_PREEMPT_DELAY] = "\t\tDelay to preempt: %d seconds",
	[VRRP_CTRL_ADV_INTERVAL] = "\n   Advert interval\t: %d seconds",
	[VRRP_CTRL_GARP_DELAY] = "\n   NA delay\t\t: %d seconds\n",
};


control_msg_t *
send_info(action_ctx_t *actx)
{
	control_msg_t *msg;
	int vrid;

	if (!(msg = control_msg_new(VRRP_GET_INFO, VRRP_REQ)))
		return NULL;

	if (actx->argc == 1) {
		vrid = atoi(actx->argv[0]);
		control_msg_add_arg_int(msg, VRRP_CTRL_VRID, vrid, actx->err);
	}
	else {
		if (control_msg_add_arg_int(msg, VRRP_CTRL_NONE, 0, actx->err))
			goto error;
	}

	return msg;

error:
	control_msg_free(msg);
	return NULL;
}

char *
recv_info(action_ctx_t *actx, control_msg_t *msg)
{
	buffer_t *b;
	unsigned int i;
	const char *boost_str;
	char *check;

	if (check = check_recv_msg(msg, VRRP_GET_INFO))
		return check;

	if (!(b = buffer_new(BUFF_SIZE)))
		goto error;


	for(i=0; i < msg->nb_args; ++i) {
		switch (msg->args[i].type) {
			case VRRP_CTRL_INIT_STATE:
			case VRRP_CTRL_STATE:
				BUFF_ADD(b, fmt_info[msg->args[i].type],
						print_state(MSG_GET_INT(msg, i), 0));
				break;
			case VRRP_CTRL_NOPREEMPT:
				BUFF_ADD(b, fmt_info[msg->args[i].type],
						MSG_GET_INT(msg, i) ? "Disabled" : "Enabled");
				break;
			default:
				switch(control_msg_arg_type[msg->args[i].type]) {
					case ARG_INT:
						BUFF_ADD(b, fmt_info[msg->args[i].type],
								MSG_GET_INT(msg, i));
						break;
					case ARG_STRING:
						BUFF_ADD(b, fmt_info[msg->args[i].type],
								MSG_GET_STRING(msg, i));
						break;
					default:
						BUFF_ADD(b, "Unknown message type");
				}
		}
	}

	return buffer_detach(b);

error:
	buffer_free(b);
	return NULL;
}

/*
 * Get virtual IPs
 */
control_msg_t *
send_vips(action_ctx_t *actx)
{
       control_msg_t *msg;

       if (!(msg = control_msg_new(VRRP_GET_ADDR, VRRP_REQ)))
               return NULL;

       if (control_msg_add_arg_int(msg, VRRP_CTRL_NONE, 0, actx->err))
               goto error;

       return msg;

error:
       control_msg_free(msg);
       return NULL;
}

char *
recv_vips(action_ctx_t *actx, control_msg_t *msg)
{
	buffer_t *b;
	unsigned int i;
	char *check;

	if (check = check_recv_msg(msg, VRRP_GET_ADDR))
		return check;

	if (!(b = buffer_new(BUFF_SIZE)))
		goto error;

	for(i=0; i < msg->nb_args; ++i) {
		switch (msg->args[i].type) {
			case VRRP_CTRL_INAME:
				BUFF_ADD_NL(b, "Instance %s:", MSG_GET_STRING(msg, i));
				break;
			case VRRP_CTRL_ADDR:
			case VRRP_CTRL_ADDR6:
				BUFF_ADD_NL(b, "   %s", MSG_GET_STRING(msg, i));
				break;
			default:
				BUFF_ADD_NL(b, "Unknown message type");
		}
	}

	return buffer_detach(b);

error:
	buffer_free(b);
	return NULL;
}

int cli_action(control_ctx_t *ctx, const action_t *action, int argc,
	char *argv[], control_err_t *err)
{
	control_msg_t *msg = NULL;
	action_ctx_t actx;
	char *output = NULL;
	int ret = 1;

	actx.cctx = ctx;
	actx.argc = argc;
	actx.argv = argv;
	actx.err = err;

	/* prepare msg */
	if (!(msg = action->send(&actx))) {
		error("%s: action send failed: %s", action->name, err->buff);
		goto out;
	}

	/* encode, send and wait */
	if (control_send_wait(ctx, msg, err)) {
		error("%s: failed to send action: %s", action->name, err->buff);
		goto out;
	}

	control_msg_free(msg);
	msg = NULL;

	/* receive and parse answer */
	if (!(msg = control_recv_parse(ctx, err))) {
		error("failed to receive answer: %s", err->buff);
		goto out;
	}

	/* interpret it */
	if (!(output = action->recv(&actx, msg))) {
		error("%s: action recv error: %s", action->name, err->buff);
		goto out;
	}
	printf("%s", output);
	ret = 0;

out:
	control_msg_free(msg);
	free(output);
	return ret;
}

action_t actions[] = {
	{"info", "dump information", send_info, recv_info},
	{"groups", "show groups information", send_groups, recv_groups},
	{"vips", "show virtual IP addresses", send_vips, recv_vips},
	{"tracking", "show tracking information", send_tracking, recv_tracking},
};

static void print_list_command(FILE *f)
{
	int i;
	fprintf(f, "Commands:\n");
	for (i = 0; i < sizeof(actions)/sizeof(actions[0]); i++) {
		fprintf(f, "  %-12s\t%s\n", actions[i].name, actions[i].description);
	}
	return;
}

static void
print_help(const char *prog, FILE *f)
{
	fprintf(f, "Usage: %s [-h|-v|-l]\n", prog);
	fprintf(f, "       %s <command> [command-options]*\n", prog);
	fprintf(f, "\nOptions:\n");
	fprintf(f, "  -h      Display this help\n");
	fprintf(f, "  -v      Display program version\n");
	fprintf(f, "  -l      Display list of commands\n");
	fprintf(f, "\n");
	print_list_command(f);
	return;
}

int
main(int argc, char *argv[])
{
	char err_buf[1024];
	control_ctx_t *ctx;
	const char *command;
	action_t *action = NULL;
	int i;
	int opt;
	control_err_t err;

	control_err_init(&err, err_buf, sizeof(err_buf));

	/* parse global options */
	while ((opt = getopt(argc, argv, "+hlv")) != -1) {
		switch (opt) {
		case 'h':
			print_help(argv[0], stdout);
			exit(0);
			break;
		case 'l':
			print_list_command(stdout);
			exit(0);
			break;
		case 'v':
			fprintf(stdout, "%s %s\n", argv[0], VERSION_DATE);
			exit(0);
			break;
		default:
			print_help(argv[0], stderr);
			exit(EXIT_FAILURE);
		}
	}

	/* find / check command */
	command = argv[optind];

	if (!command) {
		fprintf(stderr, "Error: Missing command\n\n");
		print_help(argv[0], stderr);
		exit(1);
	}

	for (i = 0; i < sizeof(actions)/sizeof(actions[0]); i++) {
		if (strcmp(command, actions[i].name) == 0) {
			action = &actions[i];
		}
	}

	if (!action) {
		fprintf(stderr, "Error: Invalid command \"%s\"\n\n", command);
		print_help(argv[0], stderr);
		exit(2);
	}

	if (!(ctx = control_connect(&err))) {
		error("%s", err.buff);
		return 1;
	}

	return cli_action(ctx, action, argc-optind-1, &argv[optind+1], &err);
}
