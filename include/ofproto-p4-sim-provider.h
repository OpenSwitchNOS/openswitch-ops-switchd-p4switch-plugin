
/*
 * (c) Copyright 2015 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
 *
 */

#ifndef OFPROTO_P4_SIM_PROVIDER_H
#define OFPROTO_P4_SIM_PROVIDER_H 1

#include "ofproto/ofproto-provider.h"
#include "p4-switch.h"

#define OPS_ROUTE_HASH_MAXSIZE 64
#define MAX_NEXTHOPS_PER_ROUTE 16

struct sim_provider_rule {
    struct rule up;
    struct ovs_mutex stats_mutex;
    uint32_t recirc_id;
};

struct sim_provider_group {
    struct ofgroup up;
    struct ovs_mutex stats_mutex;
    uint64_t packet_count OVS_GUARDED;  /* Number of packets received. */
    uint64_t byte_count OVS_GUARDED;    /* Number of bytes received. */
};

struct ofp4vlan {
    struct hmap_node hmap_node;
    uint32_t vid;
    int32_t ref_count;
    switch_handle_t vlan_handle;    /* P4 vlan handle */
};

struct ofbundle {
    struct hmap_node hmap_node; /* In struct ofproto's "bundles" hmap. */
    struct sim_provider_node *ofproto;  /* Owning ofproto. */

    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Configuration. */
    struct ovs_list ports;      /* Contains "struct ofport"s. */

    enum port_vlan_mode vlan_mode;      /* VLAN mode */
    int vlan;                   /* native vlan */
    unsigned long *trunks;      /* Bitmap of allowed trunked VLANs */
    bool allow_all_trunks;      /* user did not specify trunks bitmap => allow all vlans */
    struct lacp *lacp;          /* LACP if LACP is enabled, otherwise NULL. */
    struct bond *bond;          /* Nonnull iff more than one port. Provides hash info and other */
    bool use_priority_tags;     /* Use 802.1p tag for frames in VLAN 0? */

    bool is_vlan_routing_enabled;   /* If VLAN routing is enabled on this bundle. */
    bool is_bridge_bundle;      /* If the bundle is internal for the bridge. */

    bool is_lag;                /* lag or just single port */
    /* p4 information */
    int32_t port_type;
    int32_t tag_mode;
    switch_handle_t port_lag_handle; /* p4 api handle for port or lag
                                      * (or port when only 1 member) */
    switch_handle_t if_handle;  /* p4 api interface handle */

    char *ip4_address;
    char *ip6_address;

    bool filter_created;
    switch_vlan_t subintf_vlan; /* Vlan id for subinterface */
};

struct sim_provider_ofport {
    struct hmap_node odp_port_node;
    struct ofport up;

    odp_port_t odp_port;
    struct ofbundle *bundle;    /* Bundle that contains this port, if any. */
    struct ovs_list bundle_node;        /* In struct ofbundle's "ports" list. */
    struct cfm *cfm;            /* Connectivity Fault Management, if any. */
    struct bfd *bfd;            /* BFD, if any. */
    bool may_enable;            /* May be enabled in bonds. */
    bool is_tunnel;             /* This port is a tunnel. */
    bool is_layer3;             /* This is a layer 3 port. */
    long long int carrier_seq;  /* Carrier status changes. */
    struct sim_provider_ofport_node *peer;      /* Peer if patch port. */

    /* Spanning tree. */
    struct stp_port *stp_port;  /* Spanning Tree Protocol, if any. */
    enum stp_state stp_state;   /* Always STP_DISABLED if STP not in use. */
    long long int stp_state_entered;

    /* Rapid Spanning Tree. */
    struct rstp_port *rstp_port;        /* Rapid Spanning Tree Protocol, if
                                         * any. */
    enum rstp_state rstp_state; /* Always RSTP_DISABLED if RSTP not in use. */

    /* Queue to DSCP mapping. */
    struct ofproto_port_queue *qdscp;
    size_t n_qdscp;

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.) This is
     * deprecated.  It is only for compatibility with broken device */
    ofp_port_t realdev_ofp_port;
    int vlandev_vid;

    bool iptable_rules_added;   /* If IP table rules added to drop L2 traffic.
                                 */
};

struct sim_provider_node {
    struct hmap_node all_sim_provider_node;     /* In 'all_ofproto_provider'. */
    struct ofproto up;

    uint64_t dump_seq;          /* Last read of dump_seq(). */

    /* Special OpenFlow rules. */
    struct sim_provider_rule *miss_rule;        /* Sends flow table misses to
                                                 * controller. */
    struct sim_provider_rule *no_packet_in_rule;        /* Drops flow table
                                                         * misses. */
    struct sim_provider_rule *drop_frags_rule;  /* Used in OFPC_FRAG_DROP
                                                 * mode. */

    /* Bridging. */
    struct netflow *netflow;
    struct hmap bundles;        /* Contains "struct ofbundle"s. */
    struct mac_learning *ml;
    struct mcast_snooping *ms;
    bool has_bonded_bundles;
    bool lacp_enabled;
    struct mbridge *mbridge;

    struct ovs_mutex stats_mutex;
    struct netdev_stats stats OVS_GUARDED;      /* All packets rx/tx on a port */

    /* Spanning tree. */
    struct stp *stp;
    long long int stp_last_tick;

    /* Rapid Spanning Tree. */
    struct rstp *rstp;
    long long int rstp_last_tick;

    /* VLAN splinters. */
    struct ovs_mutex vsp_mutex;
    struct hmap realdev_vid_map OVS_GUARDED;    /* (realdev,vid) -> vlandev. */
    struct hmap vlandev_map OVS_GUARDED;        /* vlandev -> (realdev,vid). */

    /* Ports. */
    struct sset ports;          /* Set of standard port names. */
    struct sset ghost_ports;    /* Ports with no datapath port. */
    uint64_t change_seq;        /* Connectivity status changes. */

    unsigned long *vlan_intf_bmp;       /* 4096 bitmap of vlan interfaces */

    bool vrf;                   /* Specifies whether specific ofproto instance
                                 * is backing up VRF and not bridge */
    switch_handle_t vrf_handle; /* vrf id handle */
};

struct sim_provider_port_dump_state {
    uint32_t bucket;
    uint32_t offset;
    bool ghost;

    struct ofproto_port port;
    bool has_port;
};

struct ops_route {
    struct hmap_node node;
    switch_handle_t vrf_handle;
    char *prefix;
    bool is_ipv6_addr;
    int n_nexthops;
    struct hmap nexthops;
    switch_handle_t handle;
    bool ecmp_enabled;
};

struct ops_nexthop {
    struct hmap_node node;
    char *id;
    switch_handle_t nhop_handle;
};

/* Not used yet by P4 plugin. */
enum { N_TABLES = 1 };
enum { TBL_INTERNAL = N_TABLES - 1 };   /* Used for internal hidden rules. */

extern const struct ofproto_class ofproto_sim_provider_class;
#endif /* OFPROTO_P4_SIM_PROVIDER_H */
