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
 * File: netdev-p4-vport.h
 */

#ifndef NETDEV_P4_VPORT_H
#define NETDEV_P4_VPORT_H 1

#include "openvswitch/types.h"
#include "p4-switch.h"
#include "types.h"

struct netdev_tunnel_config;

#define UDP_PORT_MIN 32768
#define UDP_PORT_MAX 61000

#define P4_HANDLE_IS_VALID(_h)  ((_h) != SWITCH_API_INVALID_HANDLE)

#define DEFAULT_P4_DEVICE 0

void
netdev_set_egress_handle(struct netdev *netdev_, switch_handle_t egress_handle);

switch_handle_t
netdev_get_egress_handle(struct netdev *netdev_);

void
netdev_set_access_iface_handle(struct netdev *netdev_, switch_handle_t access_iface_handle);

void
netdev_set_tunnel_iface_handle(struct netdev *netdev_, switch_handle_t tunnel_iface_handle);

void
netdev_set_logical_nw_handle(struct netdev *netdev_, switch_handle_t logical_nw_handle);

void
netdev_set_nexthop_handle(struct netdev *netdev_, switch_handle_t nexthop_handle);

switch_handle_t
netdev_get_access_iface_handle(struct netdev *netdev_);

switch_handle_t
netdev_get_tunnel_iface_handle(struct netdev *netdev_);

switch_handle_t
netdev_get_logical_nw_handle(struct netdev *netdev_);

switch_handle_t
netdev_get_nexthop_handle(struct netdev *netdev_);

switch_handle_t
p4_ops_vport_create_tunnel(struct ofbundle *bundle, struct netdev *netdev);

int
ops_vport_tunnel_add_neighbor(struct ofbundle *bundle, struct netdev *netdev,
                                      struct ops_neighbor *nbor);

void
netdev_sim_get_port_number(struct netdev *netdev, int *port_number);

#endif /* NETDEV_P4_VPORT_H */
