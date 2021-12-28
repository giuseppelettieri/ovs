/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETDEV_NETHUNS_H
#define NETDEV_NETHUNS_H 1

#ifdef HAVE_NETHUNS

#define NETHUNS_SOCKET NETHUNS_SOCKET_XDP
#include <nethuns/nethuns.h>

void free_nethuns_buf(struct dp_packet *p);

#else /* !HAVE_NETHUNS */

#include "openvswitch/compiler.h"

struct dp_packet;

static inline void
free_nethuns_buf(struct dp_packet *p OVS_UNUSED)
{
    /* Nothing. */
}

#endif /* HAVE_NETHUNS */
#endif /* netdev-nethuns.h */
