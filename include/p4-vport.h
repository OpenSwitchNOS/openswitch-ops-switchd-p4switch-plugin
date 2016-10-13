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
 * File: p4_vport.h
 */

#ifndef __P4_VPORT_H__
#define __P4_VPORT_H__ 1

#include "bridge.h"
struct netdev;

int   p4_vport_lsw_create(int hw_unit, uint32_t vni);

int   p4_vport_bind_all_ports_on_vlan(int vni, int vlan);
int   p4_vport_unbind_all_ports_on_vlan(int vni, int vlan);
int   p4_vport_bind_port_on_vlan(int vni, int vlan, struct port *port);
int   p4_vport_unbind_port_on_vlan(int vni, int vlan, struct port *port);
#endif /* __P4_VPORT_H__ */
