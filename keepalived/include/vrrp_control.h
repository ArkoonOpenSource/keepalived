/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
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

#ifndef _VRRP_CONTROL_H
#define _VRRP_CONTROL_H

#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

int vrrp_control_init(void);
int vrrp_control_close(void);

#endif
