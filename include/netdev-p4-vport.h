/*
 * Copyright (C) 2015-2016 Hewlett-Packard Enterprise Development, L.P.
 * All Rights Reserved.
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
 *
 * File: netdev-bcmsdk-vport.h
 */

#ifndef NETDEV_P4_VPORT_H
#define NETDEV_P4_VPORT_H 1

#include "openvswitch/types.h"

struct netdev_tunnel_config;

#define UDP_PORT_MIN 32768
#define UDP_PORT_MAX 61000

#define P4_HANDLE_IS_VALID(_h)  ((_h) != SWITCH_API_INVALID_HANDLE)

#define DEFAULT_P4_DEVICE 0

#endif /* NETDEV_P4_VPORT_H */
