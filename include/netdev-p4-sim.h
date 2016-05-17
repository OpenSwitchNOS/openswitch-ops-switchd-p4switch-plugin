/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2016 Barefoot Networks Inc.
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

#ifndef NETDEV_P4_SIM_H
#define NETDEV_P4_SIM_H 1

#include "netdev-provider.h"
#include "p4-switch.h"

#define STR_EQ(s1, s2)      ((s1 != NULL) && (s2 != NULL) && \
                             (strlen((s1)) == strlen((s2))) && \
                             (!strncmp((s1), (s2), strlen((s2)))))

#define MAX_CMD_BUF 1024
/* SIM provider API. */
void netdev_sim_register(void);
extern int netdev_get_device_port_handle(struct netdev *netdev_,
                int32_t *device, switch_handle_t *port_handle);

extern int netdev_get_port_rmac_handle(struct netdev *netdev_,
                switch_handle_t *rmac_handle);

extern int
netdev_sim_get_etheraddr(const struct netdev *netdev,
                         struct eth_addr *mac);

extern void
netdev_sim_get_subintf_vlan(struct netdev *netdev,
                            switch_vlan_t *vlan);

extern switch_handle_t
netdev_get_hostif_handle(struct netdev *netdev_);

extern switch_handle_t
netdev_get_rmac_handle(struct netdev *netdev_);

extern switch_handle_t
netdev_get_subinterface_parent_rmac_handle(struct netdev *netdev_);

#endif /* netdev-p4-sim.h */
