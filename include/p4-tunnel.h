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
 * File: p4-tunnel.h
 */

#ifndef P4_TUNNEL_H
#define P4_TUNNEL_H 1


#include "openvswitch/types.h"

struct netdev;


#define TUNNEL_KEY_MIN 0
#define TUNNEL_KEY_MAX 0xFFFFFF  /* 24 bit VNI */

#define VALID_TUNNEL_KEY(key) \
        ((key >= TUNNEL_KEY_MIN) && (key <= TUNNEL_KEY_MAX))
#define MAC_IS_ZERO(mac)  \
                   (((mac)[0] | (mac)[1] | (mac)[2] | \
                     (mac)[3] | (mac)[4] | (mac)[5]) == 0)

enum events {
    HOST_ADD,     /* Host add event from PI */
    HOST_DELETE,  /* Host delete event from PI */
    ROUTE_ADD,    /* Route add event from PI */
    ROUTE_DELETE  /* Route delete event from PI */
};
enum tnl_state {
    TNL_UNDEFINED,       /* After successful malloc */
    TNL_INIT,            /* When configuration is set */
    TNL_CREATED,         /* When tunnel is created */
    TNL_DOWN,            /* Tunnel is bound but route is down */
    TNL_UP,              /* When tunnel is successfully bound to net port,
                          * and vport is created */
};

/*
 *  The P4 program programs two different tables one for the inner MAC and outer MAC
 *  for L2 VXLAN routing, and inner IP and outer IP for GRE.
 *  So two tables are needed to create two handles to program these two tables.
 *  Neighbor 1 - programs that it is L3 Tunnel Neighbor in case of GRE.
 *  Neighbor 2 - programs the rewrite indices.
 *
 */
typedef struct tunnel_node_ {
    struct hmap_node hmap_t_node;
    uint32_t remote_ip;            /* Tunnel destination IP */
    switch_handle_t tunnel_handle; /* Tunnel interface handle */
    switch_handle_t nhop_handle;  /* Nexthop handle of the tunnel nexthop entry */
    switch_handle_t neighbor1_handle; /* Neighbor 1 table entry handle */
    switch_handle_t neighbor2_handle; /* Neighbor 2 table entry handle */
    struct netdev *netdev;
} tunnel_node;

tunnel_node * tnl_insert(struct netdev *dev, uint32_t ip_addr);
void tnl_remove(struct netdev *netdev);
void p4_vport_update_host_chg(int event, char *ip_addr, int l3_egress_id);
void p4_vport_update_route_chg(int event, char* route_prefix);


#endif /* P4_TUNNEL_H */
