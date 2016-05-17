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

#include <errno.h>

#include "config.h"
#include "ofproto/ofproto-provider.h"
#include "ofproto/bond.h"
#include "ofproto/tunnel.h"
#include "bundle.h"
#include "coverage.h"
#include "netdev.h"
#include "smap.h"
#include "timer.h"
#include "seq.h"
#include "unaligned.h"
#include "vlan-bitmap.h"
#include "openvswitch/vlog.h"
#include "ofproto-p4-sim-provider.h"
#include "vswitch-idl.h"

#include "netdev-p4-sim.h"
#include <netinet/ether.h>
#include <assert.h>

VLOG_DEFINE_THIS_MODULE(P4_ofproto_provider_sim);

#define MAX_CMD_LEN             2048
#define SWNS_EXEC               "/sbin/ip netns exec swns"

#define VLAN_BITMAP_SIZE        4096
#define P4_HANDLE_IS_VALID(_h)  ((_h) != SWITCH_API_INVALID_HANDLE)

static void p4_switch_vlan_port_delete (struct ofbundle *bundle, int32_t vlan);
static void p4_switch_interface_delete (struct ofbundle *bundle);

static void rule_get_stats(struct rule *, uint64_t * packets,
                           uint64_t * bytes, long long int *used);
static void bundle_remove(struct ofport *);
static struct sim_provider_ofport *get_ofp_port(const struct sim_provider_node
                                                *ofproto, ofp_port_t ofp_port);

static struct hmap l3_route_table;
static int g_vlans_ref;
static struct hmap g_vlans; // global vlan map that is shared across L2 vlans and vlan intf

void
p4_ofproto_init()
{
    g_vlans_ref = 0;
}

static int
port_ip_reconfigure(struct ofproto *ofproto, struct ofbundle *bundle,
                    const struct ofproto_bundle_settings *s);

static struct sim_provider_ofport *
sim_provider_ofport_cast(const struct ofport *ofport)
{
    return ofport ?
        CONTAINER_OF(ofport, struct sim_provider_ofport, up) : NULL;
}

static struct sim_provider_ofport *
sim_provider_bundle_ofport_cast(const struct ovs_list *lnode)
{
    return lnode ?
        CONTAINER_OF(lnode, struct sim_provider_ofport, bundle_node) : NULL;
}

static inline struct sim_provider_node *
sim_provider_node_cast(const struct ofproto *ofproto)
{
    ovs_assert(ofproto->ofproto_class == &ofproto_sim_provider_class);

    return CONTAINER_OF(ofproto, struct sim_provider_node, up);
}

/* All existing ofproto provider instances, indexed by ->up.name. */
static struct hmap all_sim_provider_nodes =
HMAP_INITIALIZER(&all_sim_provider_nodes);

/* Factory functions. */

static void
init(const struct shash *iface_hints)
{
    return;
}

static void
enumerate_types(struct sset *types)
{
    struct sim_provider_node *ofproto;

    sset_add(types, "system");
    sset_add(types, "vrf");
}

static int
enumerate_names(const char *type, struct sset *names)
{
    struct sim_provider_node *ofproto;
    const char *port_type;

    sset_clear(names);
    HMAP_FOR_EACH(ofproto, all_sim_provider_node, &all_sim_provider_nodes) {
        if (strcmp(type, ofproto->up.type)) {
            continue;
        }
        sset_add(names, ofproto->up.name);
    }

    return 0;
}

static int
del(const char *type OVS_UNUSED, const char *name OVS_UNUSED)
{
    return 0;
}

static const char *
port_open_type(const char *datapath_type OVS_UNUSED, const char *port_type)
{
    if (port_type && ((strcmp(port_type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0) ||
            (strcmp(port_type, OVSREC_INTERFACE_TYPE_VLANSUBINT) == 0))) {
        return port_type;
    }
    return "system";
}

/* Basic life-cycle. */

static struct ofproto *
alloc(void)
{
    struct sim_provider_node *ofproto = xzalloc(sizeof *ofproto);

    return &ofproto->up;
}

static void
dealloc(struct ofproto *ofproto_)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);

    free(ofproto);
}

static int
p4_ofproto_install_l3_acl()
{
    switch_status_t rc = SWITCH_STATUS_SUCCESS;
    switch_api_hostif_rcode_info_t api_rcode_info;

    VLOG_INFO("install_l3_acl");
    memset(&api_rcode_info, 0x0, sizeof(switch_api_hostif_rcode_info_t));

    api_rcode_info.channel = SWITCH_HOSTIF_CHANNEL_NETDEV;
    api_rcode_info.priority = 1000;
    api_rcode_info.action = SWITCH_ACL_ACTION_COPY_TO_CPU;

    api_rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_ARP_REQUEST;
    rc = switch_api_hostif_reason_code_create(
                             0x0,
                             &api_rcode_info);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for arp request : rc %d",
            rc);
    }

    api_rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_ARP_RESPONSE;
    rc = switch_api_hostif_reason_code_create(
                             0x0,
                             &api_rcode_info);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for arp response : rc %d",
            rc);
    }

    api_rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_OSPF;
    rc = switch_api_hostif_reason_code_create(
                             0x0,
                             &api_rcode_info);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for ospf : rc %d",
            rc);
    }

    api_rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_OSPFV6;
    rc = switch_api_hostif_reason_code_create(
                             0x0,
                             &api_rcode_info);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for ospfv6 : rc %d",
            rc);
    }

    api_rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_IPV6_NEIGHBOR_DISCOVERY;
    rc = switch_api_hostif_reason_code_create(
                             0x0,
                             &api_rcode_info);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for ipv6_nd : rc %d",
            rc);
    }

    api_rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_L3_REDIRECT;
    rc = switch_api_hostif_reason_code_create(
                             0x0,
                             &api_rcode_info);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create reason_code l3_redirect: rc %d",
            rc);
    }
    return 0;
}

static int
p4_ofproto_uninstall_l3_acl()
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    status = switch_api_hostif_reason_code_delete(
                             0x0,
                             SWITCH_HOSTIF_REASON_CODE_ARP_REQUEST);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for arp request");
    }

    status = switch_api_hostif_reason_code_delete(
                             0x0,
                             SWITCH_HOSTIF_REASON_CODE_ARP_RESPONSE);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for arp response");
    }

    status = switch_api_hostif_reason_code_delete(
                             0x0,
                             SWITCH_HOSTIF_REASON_CODE_OSPF);

    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for ospf");
    }

    status = switch_api_hostif_reason_code_delete(
                             0x0,
                             SWITCH_HOSTIF_REASON_CODE_OSPFV6);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to create acl for ospfv6");
    }

    return 0;
}

static int
construct(struct ofproto *ofproto_)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct shash_node *node, *next;

    VLOG_INFO("Ofproto->construct - name %s type %s",
                ofproto->up.name, ofproto->up.type);

    ofproto->vrf = false;
    ofproto->netflow = NULL;
    ofproto->stp = NULL;
    ofproto->rstp = NULL;
    ofproto->dump_seq = 0;
    hmap_init(&ofproto->bundles);
    if (++g_vlans_ref == 1) {
        hmap_init(&g_vlans);
    }
    ofproto->ms = NULL;
    ofproto->has_bonded_bundles = false;
    ofproto->lacp_enabled = false;
    ofproto_tunnel_init();
    ovs_mutex_init_adaptive(&ofproto->stats_mutex);
    ovs_mutex_init(&ofproto->vsp_mutex);

    sset_init(&ofproto->ports);
    sset_init(&ofproto->ghost_ports);
    ofproto->change_seq = 0;

    hmap_insert(&all_sim_provider_nodes, &ofproto->all_sim_provider_node,
                hash_string(ofproto->up.name, 0));

    memset(&ofproto->stats, 0, sizeof ofproto->stats);
    ofproto->vlan_intf_bmp = bitmap_allocate(VLAN_BITMAP_SIZE);
    ofproto_init_tables(ofproto_, N_TABLES);
    ofproto->up.tables[TBL_INTERNAL].flags = OFTABLE_HIDDEN | OFTABLE_READONLY;

    if (!strcmp(ofproto_->type, "vrf")) {
        ofproto->vrf = true;
        VLOG_DBG("VRF name %s\n", ofproto_->name);
        ofproto->vrf_handle = switch_api_vrf_create(0, 1);
        p4_ofproto_install_l3_acl();
        hmap_init(&l3_route_table);
    }

    ofproto_init_max_ports(ofproto_, MAX_P4_SWITCH_PORTS);

    return 0;
}

static void
destruct(struct ofproto *ofproto_ OVS_UNUSED)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char ovs_delbr[80];

    if (ofproto->vrf == true) {
        struct ops_route *ops_routep = NULL;
        HMAP_FOR_EACH(ops_routep, node, &l3_route_table) {
            hmap_destroy(&ops_routep->nexthops);
        }

        hmap_destroy(&l3_route_table);

        p4_ofproto_uninstall_l3_acl();
    }

    hmap_remove(&all_sim_provider_nodes, &ofproto->all_sim_provider_node);

    hmap_destroy(&ofproto->bundles);
    if (--g_vlans_ref == 0) {
        hmap_destroy(&g_vlans);
    }

    sset_destroy(&ofproto->ports);
    sset_destroy(&ofproto->ghost_ports);

    ovs_mutex_destroy(&ofproto->stats_mutex);
    ovs_mutex_destroy(&ofproto->vsp_mutex);

    return;
}

static int
run(struct ofproto *ofproto_ OVS_UNUSED)
{
    return 0;
}

static void
wait(struct ofproto *ofproto_ OVS_UNUSED)
{
    return;
}

static void
query_tables(struct ofproto *ofproto,
             struct ofputil_table_features *features,
             struct ofputil_table_stats *stats)
{
    return;
}

static void
set_table_version(struct ofproto *ofproto_, cls_version_t version)
{
    return;
}

static struct ofport *
port_alloc(void)
{
    struct sim_provider_ofport *port = xzalloc(sizeof *port);

    return &port->up;
}

static void
port_dealloc(struct ofport *port_)
{
    struct sim_provider_ofport *port = sim_provider_ofport_cast(port_);

    free(port);
}

static int
port_construct(struct ofport *port_)
{
    (void)port_;
    return 0;
}

static void
port_destruct(struct ofport *port_ OVS_UNUSED)
{
    return;
}

static void
port_reconfigured(struct ofport *port_, enum ofputil_port_config old_config)
{
    return;
}

static bool
cfm_status_changed(struct ofport *ofport_)
{
    return false;
}

static bool
bfd_status_changed(struct ofport *ofport_ OVS_UNUSED)
{
    return false;
}

static struct ofbundle *
bundle_lookup(const struct sim_provider_node *ofproto, void *aux)
{
    struct ofbundle *bundle;

    HMAP_FOR_EACH_IN_BUCKET(bundle, hmap_node, hash_pointer(aux, 0),
                            &ofproto->bundles) {
        if (bundle->aux == aux) {
            return bundle;
        }
    }
    return NULL;
}

static struct ofp4vlan *
p4vlan_lookup(uint32_t vid)
{
    struct ofp4vlan *p4vlan;
    HMAP_FOR_EACH_IN_BUCKET(p4vlan, hmap_node, hash_int(vid, 0), &g_vlans) {
        if (p4vlan->vid == vid) {
            return p4vlan;
        }
    }
    return NULL;
}

static struct ofp4vlan *
p4vlan_create(uint32_t vid)
{
    struct ofp4vlan *p4vlan;

    p4vlan = p4vlan_lookup(vid);
    if (p4vlan) {
        p4vlan->ref_count++;
        VLOG_INFO("p4vlan_create: Add reference to p4vlan %d, ref %d",
                    vid, p4vlan->ref_count);
        return p4vlan;
    }
    p4vlan = xmalloc(sizeof(struct ofp4vlan));
    p4vlan->vid = vid;
    p4vlan->ref_count = 1;
    p4vlan->vlan_handle = switch_api_vlan_create(0, vid);
    VLOG_INFO("switch_api_vlan_create %d handle 0x%x", vid,
                p4vlan->vlan_handle);
    hmap_insert(&g_vlans, &p4vlan->hmap_node, hash_int(vid, 0));
    return p4vlan;
}

static void
p4vlan_delete(uint32_t vid)
{
    struct ofp4vlan *p4vlan;

    p4vlan = p4vlan_lookup(vid);
    ovs_assert(p4vlan);
    if (p4vlan == NULL) {
        return;
    }
    if (--p4vlan->ref_count) {
        // someone is still using it
        VLOG_INFO("p4vlan_delete: p4vlan %d is in use %d", vid,
                    p4vlan->ref_count);
        return;
    }
    ovs_assert(p4vlan->ref_count >= 0);

    VLOG_INFO("p4vlan_delete: p4vlan deleted %d", p4vlan->ref_count);
    switch_api_vlan_delete(0, p4vlan->vlan_handle);
    hmap_remove(&g_vlans, &p4vlan->hmap_node);
    free(p4vlan);
}

static void
enable_port_in_iptables(const char *port_name)
{
}

static void
disable_port_in_iptables(const char *port_name)
{
}

static void
p4_lag_port_update (switch_handle_t lag_handle,
                    struct sim_provider_ofport *port, bool add)
{
    int32_t device = 0;
    switch_handle_t port_handle;
    switch_port_t port_id;
    switch_status_t rc = 0;

    netdev_get_device_port_handle(port->up.netdev, &device,
                           &port_handle);
    VLOG_INFO("p4_lag_port_update: lag 0x%x port 0x%x add %d",
                    lag_handle, port_handle, add);
    if (add) {
        rc = switch_api_lag_member_add(0, lag_handle, SWITCH_API_DIRECTION_BOTH,
                                    handle_to_id(port_handle));
    } else {
        rc = switch_api_lag_member_delete(0, lag_handle, SWITCH_API_DIRECTION_BOTH,
                                    handle_to_id(port_handle));
    }
    if (rc) {
        VLOG_ERR("p4_lag_port_update failed for lag 0x%x port 0x%x add %d : rc %d",
                    lag_handle, port_handle, add, rc);
    }
}

static void
bundle_del_port(struct sim_provider_ofport *port)
{
    struct ofbundle *bundle = port->bundle;

    list_remove(&port->bundle_node);
    port->bundle = NULL;

    if (bundle && bundle->is_lag) {
        p4_lag_port_update(bundle->port_lag_handle, port, false/*add*/);
    }
}

static bool
bundle_add_port(struct ofbundle *bundle, ofp_port_t ofp_port)
{
    struct sim_provider_ofport *port;

    port = get_ofp_port(bundle->ofproto, ofp_port);
    if (!port) {
        return false;
    }

    if (port->bundle != bundle) {
        if (port->bundle) {
            bundle_remove(&port->up);
        }

        port->bundle = bundle;
        list_push_back(&bundle->ports, &port->bundle_node);
        /* if lag is already create in h/w, add member port to it */
        if (bundle->is_lag) {
            p4_lag_port_update(bundle->port_lag_handle, port, true/*add*/);
        }
    }

    return true;
}

static void
p4_vlan_if_bundle_l3_filters_update(struct sim_provider_node *ofproto,
                                    struct ofbundle *bundle, bool create)
{
    struct ofp4vlan *p4vlan = NULL;
    struct sim_provider_ofport *port = NULL;
    switch_packet_tx_key_t tx_key;
    switch_packet_tx_action_t tx_action;
    switch_packet_rx_key_t rx_key;
    switch_packet_rx_action_t rx_action;
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if (ofproto->vrf == false) {
        return;
    }
    if (!create && (bundle->port_type != SWITCH_API_INTERFACE_L3_VLAN) &&
        !bundle->filter_created) {
        // no need to delete - incorrect interface type or filter is not
        // installed
        return;
    }
    if (create && bundle->filter_created) {
        return;
    }

    VLOG_INFO("p4_vlan_if_bundle_l3_filters_update: %s - create = %d\n",
                bundle->name, create);

    port = list_is_empty(&bundle->ports) ? NULL :
            sim_provider_bundle_ofport_cast(list_front(&bundle->ports));
    if (!port) {
        VLOG_ERR("No port associated with the bundle %s\n", bundle->name);
    }

    if (bitmap_is_set(ofproto->vlan_intf_bmp, bundle->vlan)) {
        p4vlan = p4vlan_lookup(bundle->vlan);
    } else if(create) {
        p4vlan = p4vlan_create(bundle->vlan);
        bitmap_set1(ofproto->vlan_intf_bmp, bundle->vlan);
    }
    if (p4vlan == NULL) {
        VLOG_ERR("vlan handle get failed for vlan %d", bundle->vlan);
        return;
    }

    VLOG_INFO("vlan_handle %lx for vlan id %d", p4vlan->vlan_handle, bundle->vlan);
    memset(&tx_key, 0x0, sizeof(tx_key));
    memset(&tx_action, 0x0, sizeof(tx_action));

    tx_key.handle_valid = true;
    tx_key.hostif_handle = netdev_get_hostif_handle(port->up.netdev);
    tx_key.vlan_valid = true;
    tx_key.vlan_id = bundle->vlan;
    tx_key.priority = 900;

    if (create) {
        tx_action.handle = p4vlan->vlan_handle;
        tx_action.bypass_flags = SWITCH_BYPASS_NONE;
        status = switch_api_packet_net_filter_tx_create(0, &tx_key, &tx_action);
        VLOG_INFO("net filter tx created w/ host if %lx", tx_key.hostif_handle);
    } else {
        status = switch_api_packet_net_filter_tx_delete(0, &tx_key);
        VLOG_INFO("net filter tx deleted w/ host if %lx", tx_key.hostif_handle);
    }

    ovs_assert(status == SWITCH_STATUS_SUCCESS);

    // install filter to send all packets with L3 reason codes to
    // bridge_normal interface with vlan tag
    memset(&rx_key, 0x0, sizeof(rx_key));
    memset(&rx_action, 0x0, sizeof(rx_action));
    rx_key.port_valid = false;
    rx_key.port_lag_valid = false;
    rx_key.handle_valid = true;
    rx_key.handle = p4vlan->vlan_handle;
    rx_key.reason_code = SWITCH_HOSTIF_REASON_CODE_L3_START; // on power of 2 boundary
    rx_key.reason_code_mask = SWITCH_HOSTIF_REASON_CODE_L3_START; // just check the L3 bit in the reason code
    rx_key.reason_code_valid = true;
    rx_key.priority = 900;

    if (create) {
        // for vlan intf, port->up.handle points to bridge_normal hostif
        rx_action.hostif_handle = netdev_get_hostif_handle(port->up.netdev);
        rx_action.vlan_id = bundle->vlan;
        rx_action.vlan_action = SWITCH_PACKET_VLAN_ADD;
        status = switch_api_packet_net_filter_rx_create(0, &rx_key, &rx_action);
        VLOG_INFO("net filter rx created w/ host if %lx", rx_action.hostif_handle);
    } else {
        status = switch_api_packet_net_filter_rx_delete(0, &rx_key);
        VLOG_INFO("net filter rx deleted");
    }
    ovs_assert(status == SWITCH_STATUS_SUCCESS);
    if (create) {
        bundle->filter_created = true;
    } else {
        bundle->filter_created = false;
    }
}

/* Freeing up bundle and its members on heap */
static void
bundle_destroy(struct ofbundle *bundle)
{
    struct sim_provider_node *ofproto = bundle->ofproto;
    struct ofp4vlan *p4vlan;
    struct sim_provider_ofport *port = NULL, *next_port = NULL;

    VLOG_DBG("bundle_destroy %s", bundle->name);
    if (bundle->is_bridge_bundle) {
        return;
    }

    if (ofproto->vrf && bundle->port_type == SWITCH_API_INTERFACE_L3_VLAN) {
        p4_vlan_if_bundle_l3_filters_update(ofproto, bundle, false/*delete*/);
        p4vlan_delete(bundle->vlan);
        bitmap_set0(ofproto->vlan_intf_bmp, bundle->vlan);
    }

    LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
        bundle_del_port(port);
    }

    hmap_remove(&ofproto->bundles, &bundle->hmap_node);

    p4_switch_interface_delete(bundle);

    if (bundle->name) {
        free(bundle->name);
    }
    if (bundle->trunks) {
        free(bundle->trunks);
    }

    free(bundle);
}

static void
vlan_mode_to_port_type(int32_t vlan_mode, int32_t *port_type, int32_t *tag_mode)
{
    ovs_assert(port_type && tag_mode);
    *port_type = SWITCH_API_INTERFACE_L2_VLAN_TRUNK;
    *tag_mode =  SWITCH_VLAN_PORT_UNTAGGED; /* XXX support other types */
    if (vlan_mode == PORT_VLAN_ACCESS) {
        *port_type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
        *tag_mode = SWITCH_VLAN_PORT_UNTAGGED;
    } else if (vlan_mode == PORT_VLAN_TRUNK) {
        /* XXX - only untagged mode is support */
    } else if (vlan_mode == PORT_VLAN_NATIVE_TAGGED) {
        /* XXX */
    } else if (vlan_mode == PORT_VLAN_NATIVE_UNTAGGED) {
        /* XXX - only untagged mode is support */
    } else {
        *port_type = SWITCH_API_INTERFACE_NONE;
    }
    return;
}

static int
p4_switch_vlan_port_create (struct ofbundle *bundle, int32_t vlan)
{
    struct ofp4vlan *p4vlan;
    struct sim_provider_node *ofproto = bundle->ofproto;
    switch_status_t rc = 0;

    p4vlan = p4vlan_lookup(vlan);
    if (p4vlan && bundle->if_handle) {
        switch_vlan_port_t vlan_port;

        vlan_port.handle = bundle->if_handle;
        vlan_port.tagging_mode = bundle->tag_mode;
        VLOG_INFO("switch_api_vlan_ports_add - vlan %d, hdl 0x%x, if_hdl 0x%x",
                    p4vlan->vid, p4vlan->vlan_handle, vlan_port.handle);
        if (rc = switch_api_vlan_ports_add(0, p4vlan->vlan_handle, 1, &vlan_port)) {
            VLOG_ERR("switch_api_vlan_ports_add - failed : rc %d", rc);
            return -1;
        }
        return 0;
    }
    return -1;
}

static void
p4_switch_vlan_port_delete (struct ofbundle *bundle, int32_t vlan)
{
    struct ofp4vlan *p4vlan;
    struct sim_provider_node *ofproto = bundle->ofproto;
    switch_status_t rc = 0;

    p4vlan = p4vlan_lookup(vlan);
    if (p4vlan && bundle->if_handle) {
        switch_vlan_port_t vlan_port;

        vlan_port.handle = bundle->if_handle;
        vlan_port.tagging_mode = bundle->tag_mode;
        VLOG_INFO("switch_api_vlan_ports_remove - vlan %d, hdl 0x%x, port hdl 0x%x",
                    p4vlan->vid, p4vlan->vlan_handle, vlan_port.handle);
        if (rc =
            switch_api_vlan_ports_remove(0, p4vlan->vlan_handle, 1, &vlan_port)) {
            VLOG_ERR("switch_api_vlan_ports_remove - failed : rc %d", rc);
        }
    }
    return;
}

static void
p4_switch_interface_create (struct ofbundle *bundle)
{
    switch_api_interface_info_t i_info;
    struct sim_provider_ofport *port = NULL;
    struct sim_provider_node *ofproto = bundle->ofproto;
    int32_t device = 0;

    ovs_assert(!P4_HANDLE_IS_VALID(bundle->if_handle));
    memset(&i_info, 0, sizeof(switch_api_interface_info_t));

    port = sim_provider_bundle_ofport_cast(list_front(&bundle->ports));
    netdev_get_device_port_handle(port->up.netdev, &device,
                                    &bundle->port_lag_handle);

    if (bundle->is_lag) {
        bundle->port_lag_handle = switch_api_lag_create(device);
        if (bundle->port_lag_handle == SWITCH_API_INVALID_HANDLE) {
            VLOG_ERR("p4_switch_interface_create:lag_create() Failed");
            return;
        }
        struct sim_provider_ofport *next_port = NULL, *port = NULL;

        LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
            p4_lag_port_update(bundle->port_lag_handle, port, true/*add*/);
        }
    }

    if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS ||
        bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
        i_info.type = bundle->port_type;
        i_info.u.port_lag_handle = bundle->port_lag_handle;
    } else if (bundle->port_type == SWITCH_API_INTERFACE_L3 ||
               bundle->port_type == SWITCH_API_INTERFACE_L3_VLAN ||
               bundle->port_type == SWITCH_API_INTERFACE_L3_PORT_VLAN) {
        i_info.type = bundle->port_type;
        i_info.ipv4_unicast_enabled = TRUE;
        i_info.ipv6_unicast_enabled = TRUE;
        i_info.vrf_handle = ofproto->vrf_handle;
        i_info.rmac_handle = netdev_get_rmac_handle(port->up.netdev);

        if (bundle->port_type == SWITCH_API_INTERFACE_L3_PORT_VLAN) {
            i_info.rmac_handle = netdev_get_subinterface_parent_rmac_handle(port->up.netdev);
            netdev_sim_get_subintf_vlan(port->up.netdev, &bundle->subintf_vlan);
            VLOG_DBG("%s subinterface vlan %d", __FUNCTION__, bundle->subintf_vlan);

            if(!bundle->subintf_vlan) {
                /* If vlan id is still emtpy, interface cannot be created yet */
                VLOG_DBG("switch_api_interface_create - type %d, vlan empty. "
                          "Not creating subinterface",
                            i_info.type, i_info.u.port_lag_handle);
                return;
            }

            i_info.u.port_vlan.port_lag_handle = bundle->port_lag_handle;
            i_info.u.port_vlan.vlan_id = bundle->subintf_vlan;

            VLOG_INFO("switch_api_interface_create - type %d, port_handle 0x%x vlan %d",
                        i_info.type, i_info.u.port_vlan.port_lag_handle,
                        i_info.u.port_vlan.vlan_id);
        } else if (bundle->port_type == SWITCH_API_INTERFACE_L3_VLAN) {
            i_info.u.vlan_id = bundle->vlan;
            VLOG_INFO("switch_api_interface_create - type %d, vlan_id %d",
                        i_info.type, i_info.u.vlan_id);
        } else {
            i_info.u.port_lag_handle = bundle->port_lag_handle;
            VLOG_INFO("switch_api_interface_create - type %d, port_handle 0x%x",
                        i_info.type, i_info.u.port_lag_handle);
        }
    } else {
        ovs_assert(0);
    }

    bundle->if_handle = switch_api_interface_create(device, &i_info);
    if (bundle->if_handle == SWITCH_API_INVALID_HANDLE) {
        VLOG_ERR("switch_api_interface_create - failed");
    }
    VLOG_INFO("switch_api_interface_create - if_handle 0x%x",
                bundle->if_handle);
    return;
}

static void
p4_switch_interface_delete (struct ofbundle *bundle)
{
    if (!P4_HANDLE_IS_VALID(bundle->if_handle)) {
        return;
    }
    if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) {
        VLOG_DBG("switch_api_interface_delete(access) - if_handle 0x%x",
                    bundle->if_handle);
        if (bundle->vlan != -1) {
            /* delete native/default vlan */
            p4_switch_vlan_port_delete(bundle, bundle->vlan);
            bundle->vlan = -1;
        }
    } else if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
        int b;
        if (bundle->trunks) {
            /* Delete pv mappings for all trunk vlans */
            for (b=0; b<VLAN_BITMAP_SIZE; b++) {
                if (bundle->trunks && bitmap_is_set(bundle->trunks, b)) {
                    VLOG_DBG("delete trunk vlan %d", b);
                    p4_switch_vlan_port_delete(bundle, b);
                }
            }
        }
        VLOG_DBG("switch_api_interface_delete (trunk) - if_handle 0x%x",
                    bundle->if_handle);
    } else {
        VLOG_DBG("switch_api_interface_delete (L3) - if_handle 0x%x",
                    bundle->if_handle);
    }

    switch_api_interface_delete(0, bundle->if_handle);
    bundle->if_handle = SWITCH_API_INVALID_HANDLE;
    return;
}

static void
p4_switch_interface_port_to_lag (struct ofbundle *bundle)
{
    switch_handle_t port_if_handle, lag_if_handle;
    int b;

    VLOG_INFO("Convert bundle from single port to lag %s", bundle->name);
    /* XXX: Make-before-break to avoid traffic interruption */
    port_if_handle = bundle->if_handle;
    bundle->if_handle = SWITCH_API_INVALID_HANDLE;
    bundle->is_lag = true;
    /* create lag, add members and new interface with lag */
    p4_switch_interface_create(bundle);
    lag_if_handle = bundle->if_handle;

    /* add already configured vlans to the lag_bundle from bundle->trunks
     * and remove them from port bundle
     */
    for (b=0; b<VLAN_BITMAP_SIZE; b++) {
        if (bitmap_is_set(bundle->trunks, b)) {
            struct ofp4vlan *p4vlan;
            struct sim_provider_node *ofproto = bundle->ofproto;

            /* XXX: delete vlan port before add .. need to fix it in switchapi */
            bundle->if_handle = port_if_handle;
            p4_switch_vlan_port_delete(bundle, b);

            p4vlan = p4vlan_lookup(b);

            if (!p4vlan) {
                continue;
            }

            /* switch the if_handle to re-use in create function */
            bundle->if_handle = lag_if_handle;
            if (p4vlan->vid == bundle->vlan &&
                    bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
                switch_api_interface_native_vlan_set(bundle->if_handle, p4vlan->vlan_handle);
            }
            p4_switch_vlan_port_create(bundle, b);
        }
    }
    /* restore the if_handle */
    bundle->if_handle = lag_if_handle;
    /* delete port_if_handle */
    switch_api_interface_delete(0, port_if_handle);
}

/* Bundles. */
static int
bundle_set(struct ofproto *ofproto_, void *aux,
           const struct ofproto_bundle_settings *s)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    const struct ofport *ofport = NULL;
    bool ok = false;
    int ofp_port, i = 0, n = 0;
    char cmd_str[MAX_CMD_LEN];
    struct ofbundle *bundle;
    unsigned long *trunks = NULL;
    int rc = 0;
    int32_t new_port_type = 0;
    int32_t tag_mode = 0;
    const char *type = NULL;
    struct sim_provider_ofport *port = NULL;
    bool skip_interface = false;
    bool interface_recreate = false;
    switch_vlan_t subintf_vlan_id = 0;

    bundle = bundle_lookup(ofproto, aux);
    if (s == NULL) {
        VLOG_INFO("bundle_set: settings==NULL => destroy");
        if (bundle) {
            bundle_destroy(bundle_lookup(ofproto, aux));
        }
        return 0;
    }
    VLOG_INFO("bundle_set: name %s, n_slaves %d, vlan_mode %d, vlan %d, AUX = 0x%p, trunks = %p",
                s->name, s->n_slaves, s->vlan_mode, s->vlan, aux,
                s->trunks);
    if (!bundle) {
        VLOG_INFO("bundle_set: New bundle name %s, aux 0x%p", s->name, aux);
        bundle = xmalloc(sizeof (struct ofbundle));

        bundle->ofproto = ofproto;
        hmap_insert(&ofproto->bundles, &bundle->hmap_node,
                    hash_pointer(aux, 0));
        bundle->aux = aux;
        bundle->name = NULL;

        list_init(&bundle->ports);
        bundle->vlan_mode = PORT_VLAN_ACCESS;
        bundle->vlan = -1;
        bundle->trunks = bitmap_allocate(VLAN_BITMAP_SIZE);
        bundle->allow_all_trunks = false;
        bundle->bond = NULL;
        bundle->is_vlan_routing_enabled = false;
        bundle->is_bridge_bundle = false;
        bundle->tag_mode =  SWITCH_VLAN_PORT_UNTAGGED;
        bundle->port_type = SWITCH_API_INTERFACE_NONE;
        bundle->is_lag = false;
        bundle->if_handle = SWITCH_API_INVALID_HANDLE;
        bundle->port_lag_handle = SWITCH_API_INVALID_HANDLE;
        bundle->ip4_address = NULL;
        bundle->ip6_address = NULL;
        bundle->filter_created = false;
    }

    if (!bundle->name || strcmp(s->name, bundle->name)) {
        if (bundle->name) {
            free(bundle->name);
        }
        bundle->name = xstrdup(s->name);
    }

    ok = true;
    for (i = 0; i < s->n_slaves; i++) {
        if (!bundle_add_port(bundle, s->slaves[i])) {
            ok = false;
        }
    }

    if (!ok || list_size(&bundle->ports) != s->n_slaves) {
        struct sim_provider_ofport *next_port = NULL, *port = NULL;

        LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
            for (i = 0; i < s->n_slaves; i++) {
                if (s->slaves[i] == port->up.ofp_port) {
                    goto found;
                }
            }
            bundle_del_port(port);
found:     ;
        }
    }
    ovs_assert(list_size(&bundle->ports) <= s->n_slaves);

    if (list_is_empty(&bundle->ports)) {
        return 0;
    }

    VLOG_INFO("Bridge/VRF name=%s type=%s bundle=%s",
             ofproto->up.name, ofproto->up.type, bundle->name);

    if(strcmp(bundle->name, "bridge_normal") == 0) {
        /* Setup system_Acl for the bridge
         * switchapi supports creating system_acls to redirect
         * certain tpye of packets to CPU.
         * Setup these ACLs to for STP, LLDP, LACP packets by default.
         */
        switch_api_hostif_rcode_info_t rcode_info;
        memset(&rcode_info, 0, sizeof(rcode_info));

        VLOG_INFO("Setup cpu redirect for stp, lldp and lacp packets");
        rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_STP;
        rcode_info.action = SWITCH_ACL_ACTION_REDIRECT_TO_CPU;
        rcode_info.priority = 0;
        rcode_info.channel = SWITCH_HOSTIF_CHANNEL_NETDEV;
        rcode_info.hostif_group_id = 0;
        switch_api_hostif_reason_code_create(0, &rcode_info);

        rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_LACP;
        switch_api_hostif_reason_code_create(0, &rcode_info);

        rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_LLDP;
        switch_api_hostif_reason_code_create(0, &rcode_info);

        bundle->is_bridge_bundle = true;
        bundle->filter_created = false;

        return 0;
    }

    port = get_ofp_port(bundle->ofproto, s->slaves[0]);
    if (!port) {
        VLOG_ERR("slave is not in the ports\n");
        return 0;
    }


    /* Need to check the old and new bundle parmeters to handle transitions
     * Old          :   New
     * Access, v1   : Access, v2 -> delete pv1, create pv2
     * Access, v1   : Trunk -> delete pv1, delete intf, create intf, create all trunks
     * Trunk, v1    : Trunk, v2 -> delete pv1, create pv2
     * Trunk, vlans1: Trunk vlans2 -> delete pv(remove), create pv(added)
     * Trunk        : Access, v1 -> delete pv(all), delete intf, create intf, create pv1
     */

    type = netdev_get_type(port->up.netdev);
    ovs_assert(type);

    if (ofproto->vrf == false) {
        /* XXX tag_mode is not supported yet. It is always untagged for native vlans */
        if (strcmp(type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0) {
            // skip internal interfaces (vlan intf) on bridge-normal
            // vlan interface is an L3 interface and is valid only on a vrf.
            // switchd seems to be creating it on bride-normal as well..
            // just create one to keep upper layers happy, no further processing is needed
            bundle->port_type = new_port_type = SWITCH_API_INTERFACE_L3_VLAN;
            bundle->vlan = s->vlan;
            skip_interface = true;
        } else {
            vlan_mode_to_port_type(s->vlan_mode, &new_port_type, &tag_mode);
        }
    } else {
        /* If this bundle is attached to VRF bundle, then it is an L3 interface
         * XXX: Handle vlan internal interface bundle
         */
        if (strcmp(type, OVSREC_INTERFACE_TYPE_VLANSUBINT) == 0) {
            new_port_type = SWITCH_API_INTERFACE_L3_PORT_VLAN;
            netdev_sim_get_subintf_vlan(port->up.netdev, &subintf_vlan_id);
            /* Subinterface vlan changed or interface was never created */
            if(subintf_vlan_id !=  bundle->subintf_vlan ||
                bundle->if_handle == SWITCH_API_INVALID_HANDLE) {
                interface_recreate = true;
            }

        } else if (strcmp(type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0) {
            new_port_type = SWITCH_API_INTERFACE_L3_VLAN;
            bundle->vlan = s->vlan;
            // create the net filters, it implicitly creates vlan if not already
            // created
            p4_vlan_if_bundle_l3_filters_update(ofproto, bundle, true/*create*/);
        } else {
            new_port_type = SWITCH_API_INTERFACE_L3;
        }
    }
    bundle->vlan_mode = s->vlan_mode;
    bundle->tag_mode = tag_mode;

    if (skip_interface) {
        VLOG_INFO("Skip further processing for %s", bundle->name);
        return 0;
    }

    if (bundle->port_type != new_port_type || interface_recreate) {
        /* delete old interface and associated vlan_port */
        p4_switch_interface_delete(bundle);
        bundle->port_type = new_port_type;
        if (!bundle->is_lag && s->n_slaves > 1) {
            bundle->is_lag = true;
        }
        p4_switch_interface_create(bundle);
    }
    /* Check if we have more than 1 member to create LAG in the hardware
     * h/w LAG resources are not consumed until we have >1 members (slaves)
     * Once LAG is created in the h/w it is not removed when mebers drop to 1
     * XXX this optimization will be done later if required
     * XXX hash configuration for traffic distribution is not supported
     */
    if (!bundle->is_lag && s->n_slaves > 1) {
        p4_switch_interface_port_to_lag(bundle);
    }
    if (!bundle->is_lag && s->n_slaves == 1) {
        /* XXX check single port swap case - need to delete and recreate
         * P4 interface with new port handle
         */
    }

    /* bundle->trunks bitmap bit is set if -
     * - native_vlan (always added to trunks bitmap even if not added by the user)
     * - user specified allowed vlan list (s->trunks)
     * - all the vlans programmed in the h/w due to allow_all sematics
     * Bits corresponding to native vlan and user specified vlans are always set even if
     * vlan is not currently programmed in the h/w (race condition between set_vlan and
     * bundle_set).
     */
    if (bundle->vlan != s->vlan) {
        struct ofp4vlan *p4vlan;

        VLOG_DBG("bundle_set - native vlan changed from %d to %d", bundle->vlan, s->vlan);
        if (bundle->vlan != -1) {
            /* delete it. If part of user specified vlans, will be added again later */
            p4_switch_vlan_port_delete(bundle, bundle->vlan);
            bitmap_set0(bundle->trunks, bundle->vlan);
            bundle->vlan = -1;
        }
        if (s->vlan != -1) {
            p4vlan = p4vlan_lookup((uint32_t)s->vlan);
            if (bitmap_is_set(bundle->trunks, s->vlan)) {
                /* we need to perform vlan_port_add after setting native vlan
                 * delete it here and re-create after setting native vlan
                 */
                p4_switch_vlan_port_delete(bundle, s->vlan);
                bitmap_set0(bundle->trunks, s->vlan);
            }
            if (p4vlan && new_port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
                switch_api_interface_native_vlan_set(bundle->if_handle, p4vlan->vlan_handle);
            }
            p4_switch_vlan_port_create(bundle, s->vlan);
            /* add native vlan to trunks bitmap */
            bitmap_set1(bundle->trunks, s->vlan);
        }
        bundle->vlan = s->vlan;
    }
    if (new_port_type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) {
        /* Access(natvie) vlan is handled above */
    } else if (new_port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
        int b;
        /* remove pv mapping for the vlans removed and add for the new ones */
        bundle->allow_all_trunks = (s->trunks == NULL);
        for (b=0; b<VLAN_BITMAP_SIZE; b++) {
            bool vlan_old = false;
            bool vlan_new = false;

            if (bundle->vlan == b) {
                continue;
            }
            if (bitmap_is_set(bundle->trunks, b))
            {
                vlan_old = true;
            }
            if (!s->trunks || bitmap_is_set(s->trunks, b))
            {
                /* s->trunks == NULL => all vlans are allowed */
                vlan_new = true;
            }
            if (vlan_old != vlan_new) {
                if (vlan_old) {
                    VLOG_INFO("bundle_set - Delete old trunk vlan %d", b);
                    p4_switch_vlan_port_delete(bundle, b);
                    bitmap_set0(bundle->trunks, b);
                }
                if (vlan_new) {
                    int vlan_add_err = 0;
                    /* Try to add new vlan if it is created via set_vlan()
                     * if not, remember it for future addition
                     */
                    vlan_add_err = p4_switch_vlan_port_create(bundle, b);
                    if (!vlan_add_err || s->trunks) {
                        /* add to bit map if it was specified by the user
                         * or was added successfully
                         */
                        bitmap_set1(bundle->trunks, b);
                    }
                }
            }
        }
    } else if (new_port_type == SWITCH_API_INTERFACE_L3 ||
               new_port_type == SWITCH_API_INTERFACE_L3_PORT_VLAN ||
               new_port_type == SWITCH_API_INTERFACE_L3_VLAN) {
        port_ip_reconfigure(ofproto_, bundle, s);
    } else {
        VLOG_ERR("un-supported interface type");
        return EINVAL;
    }
    return rc;
}

static int
bundle_get(struct ofproto *ofproto_, void *aux, int *bundle_handle)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ofbundle *bundle;

    bundle = bundle_lookup(ofproto, aux);
    if (bundle && P4_HANDLE_IS_VALID(bundle->if_handle)) {
        *bundle_handle = bundle->if_handle;
    } else {
        *bundle_handle = -1;
    }
    return 0;
}

static void
bundle_remove(struct ofport *port_)
{
    struct sim_provider_ofport *port = sim_provider_ofport_cast(port_);
    struct ofbundle *bundle = port->bundle;

    if (bundle) {
        VLOG_INFO("bundle_remove port bundle %s port %s", bundle->name,
                    netdev_get_name(port_->netdev));
        bundle_del_port(port);
    }
}

static void
p4_bundles_vlan_update (struct sim_provider_node *ofproto, struct ofp4vlan *p4vlan, bool add)
{
    /* iterate over all bundles and add new port_vlan mapping for the new vlan
     * skip over the non-L2 bundles and special bridge_normal bundle
     */
    struct ofbundle *bundle;
    int max_bundles = hmap_count(&ofproto->bundles);
    int l2_bundles = 0;
    switch_vlan_port_t *vlan_port;
    switch_status_t rc = 0;

    vlan_port = xmalloc(max_bundles * sizeof(switch_vlan_port_t));
    ovs_assert(vlan_port);

    HMAP_FOR_EACH(bundle, hmap_node, &ofproto->bundles) {
        if (ofproto->vrf || bundle->is_bridge_bundle ||
            bundle->port_type == SWITCH_API_INTERFACE_L3_VLAN) {
            continue;
        }
        if (add) {
            if ((bundle->vlan != p4vlan->vid) &&
                (!bundle->allow_all_trunks &&
                !bitmap_is_set(bundle->trunks, p4vlan->vid))) {
                continue;
            }
            if ((bundle->vlan == p4vlan->vid) &&
                (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK)) {
                switch_api_interface_native_vlan_set(bundle->if_handle,
                                                        p4vlan->vlan_handle);
            }
            /* all vlans created (even if due to allow_all are added to trunks bitmap */
            bitmap_set1(bundle->trunks, p4vlan->vid);
        } else {
            /* check if this vlan was added */
            if (!bitmap_is_set(bundle->trunks, p4vlan->vid)) {
                continue;
            }
            if (bundle->allow_all_trunks) {
                /* remove the bit only if this was added due to allow_all setting */
                bitmap_set0(bundle->trunks, p4vlan->vid);
            }
        }
        vlan_port[l2_bundles].handle = bundle->if_handle;
        vlan_port[l2_bundles].tagging_mode = bundle->tag_mode;
        l2_bundles++;
    }
    if (l2_bundles == 0) {
        VLOG_DBG("p4_bundles_vlan_update - no bundles found");
        free(vlan_port);
        return;
    }
    if (add) {
        VLOG_INFO("switch_api_vlan_ports_add vlan %d hdl 0x%x, n_ports %d",
                        p4vlan->vid, p4vlan->vlan_handle, l2_bundles);
        if (rc =
            switch_api_vlan_ports_add(0, p4vlan->vlan_handle, l2_bundles, vlan_port)) {
            VLOG_ERR("switch_api_vlan_ports_add - failed %d", rc);
        }
    } else {
        VLOG_INFO("switch_api_vlan_ports_remove vlan_hdl 0x%x, n_ports %d",
                        p4vlan->vlan_handle, l2_bundles);
        if (rc =
            switch_api_vlan_ports_remove(0, p4vlan->vlan_handle, l2_bundles, vlan_port)) {
            VLOG_ERR("switch_api_vlan_ports_remove - failed %d", rc);
        }
    }
    free(vlan_port);
}

static int
set_vlan(struct ofproto *ofproto_, int vid, bool add)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ofp4vlan *p4vlan;

    if (add) {
        // XXX: call it vlan bitmap
        if (bitmap_is_set(ofproto->vlan_intf_bmp, vid)) {
            VLOG_ERR("set_vlan: add vid %d, already exists", vid);
            return EEXIST;
        }
        VLOG_INFO("set_vlan: vid %d", vid);
        p4vlan = p4vlan_create((uint32_t)vid);
        if (p4vlan == NULL) {
            VLOG_ERR("set_vlan: add vid %d create failed", vid);
            return -1;
        }
        /* add vlan to all applicable bundles */
        p4_bundles_vlan_update(ofproto, p4vlan, true/*add*/);
        bitmap_set1(ofproto->vlan_intf_bmp, vid);
    } else {
        p4vlan = p4vlan_lookup((uint32_t)vid);
        if (p4vlan == NULL) {
            VLOG_ERR("set_vlan: remove vid %d, does not exists", vid);
            return EINVAL;
        }
        VLOG_INFO("set_vlan: remove vid %d", vid);
        /* remove vlan from all applicable bundles */
        p4_bundles_vlan_update(ofproto, p4vlan, false/*add*/);
        p4vlan_delete((uint32_t)vid);
        bitmap_set0(ofproto->vlan_intf_bmp, vid);
    }
    return 0;
}

/* Mirrors. */
static int
mirror_get_stats__(struct ofproto *ofproto OVS_UNUSED, void *aux OVS_UNUSED,
                   uint64_t * packets OVS_UNUSED, uint64_t * bytes OVS_UNUSED)
{
    return 0;
}

static bool
is_mirror_output_bundle(const struct ofproto *ofproto_ OVS_UNUSED,
                        void *aux OVS_UNUSED)
{
    return false;
}

static void
forward_bpdu_changed(struct ofproto *ofproto_ OVS_UNUSED)
{
    return;
}

/* Ports. */

static struct sim_provider_ofport *
get_ofp_port(const struct sim_provider_node *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(&ofproto->up, ofp_port);

    return ofport ? sim_provider_ofport_cast(ofport) : NULL;
}

static int
port_query_by_name(const struct ofproto *ofproto_, const char *devname,
                   struct ofproto_port *ofproto_port)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    const char *type = netdev_get_type_from_name(devname);

    VLOG_DBG("port_query_by_name - %s", devname);

    /* We must get the name and type from the netdev layer directly. */
    if (type) {
        const struct ofport *ofport;

        ofport = shash_find_data(&ofproto->up.port_by_name, devname);
        ofproto_port->ofp_port = ofport ? ofport->ofp_port : OFPP_NONE;
        ofproto_port->name = xstrdup(devname);
        ofproto_port->type = xstrdup(type);
        VLOG_DBG("get_ofp_port name= %s type= %s flow# %d",
                 ofproto_port->name, ofproto_port->type,
                 ofproto_port->ofp_port);
        return 0;
    }
    return ENODEV;

}

static int
port_add(struct ofproto *ofproto_, struct netdev *netdev)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    const char *devname = netdev_get_name(netdev);

    VLOG_INFO("port_add: %s", devname);
    sset_add(&ofproto->ports, devname);

    return 0;
}

static int
port_del(struct ofproto *ofproto_, ofp_port_t ofp_port)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct sim_provider_ofport *ofport = get_ofp_port(ofproto, ofp_port);
    const char *netdev_name = NULL;

    if (ofport == NULL) {
        VLOG_ERR("port_del - 0x%x invalid port", ofp_port);
        return 0;
    }
    ovs_assert(ofport);
    netdev_name = netdev_get_name(ofport->up.netdev);
    VLOG_DBG("port_del: %d, name = %s", ofp_port, netdev_name);
    if (!sset_find_and_delete(&ofproto->ports, netdev_name)) {
        VLOG_ERR("port_del - %s does not exists", netdev_name);
        return ENODEV;
    }
    return 0;
}

static int
port_get_stats(const struct ofport *ofport_, struct netdev_stats *stats)
{
    struct sim_provider_ofport *ofport = sim_provider_ofport_cast(ofport_);
    int error = 0;

    VLOG_INFO("port_get_stats for %s", netdev_get_name(ofport->up.netdev));

    /* XXX Currently this function is not being called by switchd - Add it when needed */

    return error;
}

static int
port_dump_start(const struct ofproto *ofproto_ OVS_UNUSED, void **statep)
{
    VLOG_DBG("%s", __FUNCTION__);
    *statep = xzalloc(sizeof (struct sim_provider_port_dump_state));
    return 0;
}

static int
port_dump_next(const struct ofproto *ofproto_, void *state_,
               struct ofproto_port *port)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct sim_provider_port_dump_state *state = state_;
    const struct sset *sset;
    struct sset_node *node;

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
        state->has_port = false;
    }
    sset = state->ghost ? &ofproto->ghost_ports : &ofproto->ports;
    while ((node = sset_at_position(sset, &state->bucket, &state->offset))) {
        int error;

        VLOG_DBG("port dump loop detecting port %s", node->name);

        error = port_query_by_name(ofproto_, node->name, &state->port);
        if (!error) {
            VLOG_DBG("port dump loop reporting port struct %s",
                     state->port.name);
            *port = state->port;
            state->has_port = true;
            return 0;
        } else if (error != ENODEV) {
            return error;
        }
    }

    if (!state->ghost) {
        state->ghost = true;
        state->bucket = 0;
        state->offset = 0;
        return port_dump_next(ofproto_, state_, port);
    }

    return EOF;
}

static int
port_dump_done(const struct ofproto *ofproto_ OVS_UNUSED, void *state_)
{
    struct sim_provider_port_dump_state *state = state_;

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
    }
    free(state);
    return 0;
}

static struct sim_provider_rule *
sim_provider_rule_cast(const struct rule *rule)
{
    return NULL;
}

static struct rule *
rule_alloc(void)
{
    struct sim_provider_rule *rule = xmalloc(sizeof *rule);

    return &rule->up;
}

static void
rule_dealloc(struct rule *rule_)
{
    struct sim_provider_rule *rule = sim_provider_rule_cast(rule_);

    free(rule);
}

static enum ofperr
rule_construct(struct rule *rule_ OVS_UNUSED)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    return 0;
}

static void rule_insert(struct rule *rule, struct rule *old_rule,
                    bool forward_stats)
OVS_REQUIRES(ofproto_mutex)
{
    return;
}

static void
rule_delete(struct rule *rule_ OVS_UNUSED)
OVS_REQUIRES(ofproto_mutex)
{
    return;
}

static void
rule_destruct(struct rule *rule_ OVS_UNUSED)
{
    return;
}

static void
rule_get_stats(struct rule *rule_ OVS_UNUSED, uint64_t * packets OVS_UNUSED,
               uint64_t * bytes OVS_UNUSED, long long int *used OVS_UNUSED)
{
    return;
}

static enum ofperr
rule_execute(struct rule *rule OVS_UNUSED, const struct flow *flow OVS_UNUSED,
             struct dp_packet *packet OVS_UNUSED)
{
    return 0;
}

static void
rule_modify_actions(struct rule *rule_ OVS_UNUSED,
                    bool reset_counters OVS_UNUSED)
OVS_REQUIRES(ofproto_mutex)
{
    return;
}

static struct sim_provider_group
*
sim_provider_group_cast(const struct ofgroup *group)
{
    return group ? CONTAINER_OF(group, struct sim_provider_group, up) : NULL;
}

static struct ofgroup *
group_alloc(void)
{
    struct sim_provider_group *group = xzalloc(sizeof *group);

    return &group->up;
}

static void
group_dealloc(struct ofgroup *group_)
{
    struct sim_provider_group *group = sim_provider_group_cast(group_);

    free(group);
}

static enum ofperr
group_construct(struct ofgroup *group_ OVS_UNUSED)
{
    return 0;
}

static void
group_destruct(struct ofgroup *group_ OVS_UNUSED)
{
    return;
}

static enum ofperr
group_modify(struct ofgroup *group_ OVS_UNUSED)
{
    return 0;
}

static enum ofperr
group_get_stats(const struct ofgroup *group_ OVS_UNUSED,
                struct ofputil_group_stats *ogs OVS_UNUSED)
{
    return 0;
}

static const char *
get_datapath_version(const struct ofproto *ofproto_ OVS_UNUSED)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);

    return VERSION;
}

static bool
set_frag_handling(struct ofproto *ofproto_ OVS_UNUSED,
                  enum ofp_config_flags frag_handling OVS_UNUSED)
{
    return false;
}

static enum ofperr
packet_out(struct ofproto *ofproto_ OVS_UNUSED,
           struct dp_packet *packet OVS_UNUSED,
           const struct flow *flow OVS_UNUSED,
           const struct ofpact *ofpacts OVS_UNUSED,
           size_t ofpacts_len OVS_UNUSED)
{
    return 0;
}

static void
get_netflow_ids(const struct ofproto *ofproto_ OVS_UNUSED,
                uint8_t * engine_type OVS_UNUSED,
                uint8_t * engine_id OVS_UNUSED)
{
    return;
}

static switch_handle_t
l3_route_nhop_glean_get()
{
    return switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_GLEAN);
}

static int
ip_string_to_prefix(
        bool is_ipv6,
        char *ip_address,
        void *prefix,
        int *prefixlen)
{
    char *p;
    char *tmp_ip_addr;
    int maxlen =  is_ipv6 ? 128 : 32;

    *prefixlen = maxlen;
    tmp_ip_addr = strdup(ip_address);

    if ((p = strchr(tmp_ip_addr, '/'))) {
        *p++ = '\0';
        *prefixlen = atoi(p);
    }

    if (*prefixlen > maxlen) {
        VLOG_DBG("Bad prefixlen %d > %d", *prefixlen, maxlen);
        free(tmp_ip_addr);
        return EINVAL;
    }

    if (!is_ipv6) {
        /* ipv4 address in host order */
        in_addr_t *addr = (in_addr_t*)prefix;
        *addr = inet_network(tmp_ip_addr);
        if (*addr == -1) {
            VLOG_ERR("Invalid ip address %s", ip_address);
            free(tmp_ip_addr);
            return EINVAL;
        }
    } else {
        /* ipv6 address */
        if (inet_pton(AF_INET6, tmp_ip_addr, prefix) == 0) {
            VLOG_DBG("%d inet_pton failed with %s", is_ipv6, strerror(errno));
            free(tmp_ip_addr);
            return EINVAL;
        }
    }

    free(tmp_ip_addr);
    return 0;
}

static int
port_l3_host_add(struct ofproto *ofproto_, bool is_ipv6, char *ip_addr)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    switch_ip_addr_t ip_address;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_handle_t nhop_handle = 0;

    ip_address.type = is_ipv6 ? SWITCH_API_IP_ADDR_V6 : SWITCH_API_IP_ADDR_V4;

    /*
     * interface address is always a host IP.
     * set the prefix length to 32 or 128.
     */
    if (!is_ipv6) {
        ip_string_to_prefix(
                is_ipv6,
                ip_addr,
                &ip_address.ip.v4addr,
                &ip_address.prefix_len);
        ip_address.prefix_len = 32;
    } else {
        ip_string_to_prefix(
                is_ipv6,
                ip_addr,
                &ip_address.ip.v6addr,
                &ip_address.prefix_len);
        ip_address.prefix_len = 128;
    }

    nhop_handle = l3_route_nhop_glean_get();

    status = switch_api_l3_route_add(
                0x0,
                ofproto->vrf_handle,
                &ip_address,
                nhop_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to add route");
        return 1;
    }

    VLOG_INFO("vrf %lx v4_ip %x prefix %d nhop %lx",
               ofproto->vrf_handle,
               ip_address.ip.v4addr,
               ip_address.prefix_len,
               nhop_handle);

    return 0;
}

static int
port_l3_host_delete(struct ofproto *ofproto_, bool is_ipv6, char *ip_addr)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    switch_ip_addr_t ip_address;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_handle_t nhop_handle = 0;

    ip_address.type = is_ipv6 ? SWITCH_API_IP_ADDR_V6 : SWITCH_API_IP_ADDR_V4;

    if (!is_ipv6) {
        ip_string_to_prefix(
                is_ipv6,
                ip_addr,
                &ip_address.ip.v4addr,
                &ip_address.prefix_len);
        ip_address.prefix_len = 32;
    } else {
        ip_string_to_prefix(
                is_ipv6,
                ip_addr,
                &ip_address.ip.v6addr,
                &ip_address.prefix_len);
        ip_address.prefix_len = 128;
    }

    nhop_handle = l3_route_nhop_glean_get();

    status = switch_api_l3_route_delete(
                0x0,
                ofproto->vrf_handle,
                &ip_address,
                nhop_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to delete route");
        return EINVAL;
    }

    VLOG_INFO("vrf %lx v4_ip %x prefix %d nhop %lx",
               ofproto->vrf_handle,
               ip_address.ip.v4addr,
               ip_address.prefix_len,
               nhop_handle);
    return 0;
}

static int
port_ip_reconfigure(struct ofproto *ofproto, struct ofbundle *bundle,
                    const struct ofproto_bundle_settings *s)
{
    bool is_ipv6 = false;

    VLOG_DBG("In port_ip_reconfigure with ip_change val=0x%x", s->ip_change);
    /* If primary ipv4 got added/deleted/modified */
    if (s->ip_change & PORT_PRIMARY_IPv4_CHANGED) {
        if (s->ip4_address) {
            if (bundle->ip4_address) {
                if (strcmp(bundle->ip4_address, s->ip4_address) != 0) {
                    /* If current and earlier are different, delete old */
                    port_l3_host_delete(ofproto, is_ipv6,
                                        bundle->ip4_address);
                    free(bundle->ip4_address);

                    /* Add new */
                    bundle->ip4_address = xstrdup(s->ip4_address);
                    port_l3_host_add(ofproto, is_ipv6,
                                     bundle->ip4_address);
                }
                /* else no change */
            } else {
                /* Earlier primary was not there, just add new */
                bundle->ip4_address = xstrdup(s->ip4_address);
                port_l3_host_add(ofproto, is_ipv6, bundle->ip4_address);
            }
        } else {
            /* Primary got removed, earlier if it was there then remove it */
            if (bundle->ip4_address != NULL) {
                port_l3_host_delete(ofproto, is_ipv6, bundle->ip4_address);
                free(bundle->ip4_address);
                bundle->ip4_address = NULL;
            }
        }
    }

    /* If primary ipv6 got added/deleted/modified */
    if (s->ip_change & PORT_PRIMARY_IPv6_CHANGED) {
        is_ipv6 = true;
        if (s->ip6_address) {
            if (bundle->ip6_address) {
                if (strcmp(bundle->ip6_address, s->ip6_address) !=0) {
                    /* If current and earlier are different, delete old */
                    port_l3_host_delete(ofproto, is_ipv6, bundle->ip6_address);
                    free(bundle->ip6_address);

                    /* Add new */
                    bundle->ip6_address = xstrdup(s->ip6_address);
                    port_l3_host_add(ofproto, is_ipv6, bundle->ip6_address);

                }
                /* else no change */
            } else {

                /* Earlier primary was not there, just add new */
                bundle->ip6_address = xstrdup(s->ip6_address);
                port_l3_host_add(ofproto, is_ipv6, bundle->ip6_address);
            }
        } else {
            /* Primary got removed, earlier if it was there then remove it */
            if (bundle->ip6_address != NULL) {
                port_l3_host_delete(ofproto, is_ipv6, bundle->ip6_address);
                free(bundle->ip6_address);
                bundle->ip6_address = NULL;
            }
        }
    }

    /* TODO: support for secondary ip address */

    return 0;
}

static int
add_l3_host_entry(const struct ofproto *ofproto_, void *aux,
                  bool is_ipv6_addr, char *ip_addr,
                  char *next_hop_mac_addr, int *l3_egress_id)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ofbundle *bundle;
    switch_ip_addr_t ip_address;
    int rc = 0;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    struct ether_addr *mac_addr = NULL;
    switch_api_neighbor_t api_neighbor;
    switch_handle_t nhop_handle = 0;
    switch_handle_t neigh_handle = 0;
    switch_nhop_key_t nhop_key;

    VLOG_INFO("add_l3_host_entry: ip address %s", ip_addr);

    bundle = bundle_lookup(ofproto, aux);
    if (bundle == NULL) {
        VLOG_ERR("Failed to get port bundle/l3_intf not configured");
        return EINVAL;
    }
    VLOG_INFO("add_l3_host_entry: bundle %s", bundle->name);

    mac_addr = ether_aton(next_hop_mac_addr);

    if (!mac_addr || !next_hop_mac_addr) {
        VLOG_ERR("add_l3_host_entry failed: invalid mac address");
        return EINVAL;
    }

    memset(&nhop_key, 0, sizeof(nhop_key));
    nhop_key.intf_handle = bundle->if_handle;
    nhop_handle = switch_api_nhop_create(
                                       0x0,
                                       &nhop_key);

    ip_address.type = is_ipv6_addr ? SWITCH_API_IP_ADDR_V6 : SWITCH_API_IP_ADDR_V4;

    if (!is_ipv6_addr) {
        ip_string_to_prefix(
                is_ipv6_addr,
                ip_addr,
                &ip_address.ip.v4addr,
                &ip_address.prefix_len);
    } else {
        ip_string_to_prefix(
                is_ipv6_addr,
                ip_addr,
                &ip_address.ip.v6addr,
                &ip_address.prefix_len);
    }

    memset(&api_neighbor, 0x0, sizeof(switch_api_neighbor_t));
    api_neighbor.neigh_type = SWITCH_API_NEIGHBOR_NONE;
    api_neighbor.rw_type = SWITCH_API_NEIGHBOR_RW_TYPE_L3;
    api_neighbor.vrf_handle = ofproto->vrf_handle;
    api_neighbor.interface = bundle->if_handle;
    api_neighbor.nhop_handle = nhop_handle;
    memcpy(&api_neighbor.ip_addr, &ip_addr, sizeof(switch_ip_addr_t));
    memcpy(&api_neighbor.mac_addr.mac_addr, mac_addr, ETH_ALEN);

    neigh_handle = switch_api_neighbor_entry_add(0x0, &api_neighbor);

    VLOG_DBG("is v6 addr: %d", (int)is_ipv6_addr);
    VLOG_DBG("ip addr: %s", ip_addr);
    VLOG_DBG("mac addr: %s", next_hop_mac_addr);
    VLOG_DBG("nhop handle %lx", nhop_handle);
    VLOG_DBG("neigh handle %lx", neigh_handle);

    *l3_egress_id = handle_to_id(nhop_handle);

    status = switch_api_l3_route_add(
                             0x0,
                             ofproto->vrf_handle,
                             &ip_address,
                             nhop_handle);

    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("add_l3_host_entry failed");
    } else {
        VLOG_DBG("add_l3_host_entry success");
    }

    return 0;
}

static int
delete_l3_host_entry(const struct ofproto *ofproto_, void *aux,
                     bool is_ipv6_addr, char *ip_addr, int *l3_egress_id)

{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ofbundle *bundle;
    switch_ip_addr_t ip_address;
    int rc = 0;
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    bundle = bundle_lookup(ofproto, aux);
    if (bundle == NULL) {
        VLOG_ERR("Failed to get port bundle/l3_intf not configured");
        return EINVAL;
    }

    ip_address.type = is_ipv6_addr ? SWITCH_API_IP_ADDR_V6 : SWITCH_API_IP_ADDR_V4;

    if (!is_ipv6_addr) {
        ip_string_to_prefix(
                is_ipv6_addr,
                ip_addr,
                &ip_address.ip.v4addr,
                &ip_address.prefix_len);
    } else {
        ip_string_to_prefix(
                is_ipv6_addr,
                ip_addr,
                &ip_address.ip.v6addr,
                &ip_address.prefix_len);
    }

    VLOG_INFO("delete_l3_host_entry:ip addr: %s", ip_addr);
    VLOG_DBG("is v6 addr: %d", (int)is_ipv6_addr);
    VLOG_DBG("l3 egress id %d", *l3_egress_id);
    switch_handle_t nhop_handle = id_to_handle(SWITCH_HANDLE_TYPE_NHOP, *l3_egress_id);

    status = switch_api_l3_route_delete(
                             0x0,
                             ofproto->vrf_handle,
                             &ip_address,
                             nhop_handle);

    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("route delete failed - %d", status);
        return status;
    }

    switch_handle_t neighbor_handle = switch_api_neighbor_handle_get(nhop_handle);
    if (neighbor_handle != SWITCH_API_INVALID_HANDLE) {
        status = switch_api_neighbor_entry_remove(0x0, neighbor_handle);
        if (status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("neighbor delete failed - %d", status);
        }
    }

    status = switch_api_nhop_delete(0x0, nhop_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("nhop delete 0x%x failed - %d", nhop_handle, status);
    }

    return 0;
}

/* Add nexthop into the route entry */
static void
l3_nexthop_hash_insert(
        struct ops_route *ops_routep,
        struct ofproto_route_nexthop *of_nh)
{
    char *hashstr;
    struct ops_nexthop *nh;

    if (!ops_routep || !of_nh) {
        return;
    }

    nh = xzalloc(sizeof(*nh));

    if (of_nh->id) {
        nh->id = xstrdup(of_nh->id);
    }

    if (of_nh->state == OFPROTO_NH_RESOLVED) {
        nh->nhop_handle = id_to_handle(
                             SWITCH_HANDLE_TYPE_NHOP,
                             of_nh->l3_egress_id);
    } else {
        nh->nhop_handle = l3_route_nhop_glean_get();
    }

    hashstr = of_nh->id;
    hmap_insert(&ops_routep->nexthops, &nh->node, hash_string(hashstr, 0));
    ops_routep->n_nexthops++;

    VLOG_DBG("Add NH %s, egress_id %d, for route %s",
              nh->id, nh->nhop_handle, ops_routep->prefix);
}

/* Delete nexthop into route entry */
static void
l3_nexthop_hash_delete(
        struct ops_route *ops_routep,
        struct ops_nexthop *nh)
{
    if (!ops_routep || !nh) {
        return;
    }

    VLOG_DBG("Delete NH %s in route %s", nh->id, ops_routep->prefix);

    hmap_remove(&ops_routep->nexthops, &nh->node);
    if (nh->id) {
        free(nh->id);
    }
    free(nh);
    ops_routep->n_nexthops--;
}

/* Find nexthop entry in the route's nexthops hash */
static struct ops_nexthop*
l3_nexthop_hash_lookup(
        struct ops_route *ops_routep,
        struct ofproto_route_nexthop *of_nh)
{
    char *hashstr;
    struct ops_nexthop *nh;

    hashstr = of_nh->id;
    HMAP_FOR_EACH_WITH_HASH(nh, node, hash_string(hashstr, 0),
                            &ops_routep->nexthops) {
        if ((strcmp(nh->id, of_nh->id) == 0)){
            return nh;
        }
    }
    return NULL;
}

/* Create route hash */
static void
l3_route_compute_hash(
        switch_handle_t vrf_handle,
        char *prefix,
        char *hashstr,
        int hashlen)
{
    snprintf(hashstr, hashlen, "%lx:%s", vrf_handle, prefix);
}

static struct ops_route *
l3_route_hash_lookup(
        switch_handle_t vrf_handle,
        struct ofproto_route *of_routep)
{
    struct ops_route *ops_routep = NULL;
    char hashstr[OPS_ROUTE_HASH_MAXSIZE];

    l3_route_compute_hash(vrf_handle, of_routep->prefix, hashstr, sizeof(hashstr));
    HMAP_FOR_EACH_WITH_HASH(ops_routep, node, hash_string(hashstr, 0),
                            &l3_route_table) {
        if ((strcmp(ops_routep->prefix, of_routep->prefix) == 0) &&
            (ops_routep->vrf_handle == vrf_handle)) {
            return ops_routep;
        }
    }
    return NULL;
}

/* Add new route and NHs */
static struct ops_route*
l3_route_hash_insert(
        switch_handle_t vrf_handle,
        struct ofproto_route *of_routep)
{
    int i;
    struct ops_route *ops_routep = NULL;
    struct ofproto_route_nexthop *of_nh;
    char hashstr[OPS_ROUTE_HASH_MAXSIZE];

    if (!of_routep) {
        return NULL;
    }

    ops_routep = xzalloc(sizeof(struct ops_route));
    ops_routep->vrf_handle = vrf_handle;
    ops_routep->prefix = xstrdup(of_routep->prefix);
    ops_routep->is_ipv6_addr = (of_routep->family == OFPROTO_ROUTE_IPV6) ? true : false;
    ops_routep->n_nexthops = 0;

    hmap_init(&ops_routep->nexthops);

    for (i = 0; i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        l3_nexthop_hash_insert(ops_routep, of_nh);
    }

    l3_route_compute_hash(vrf_handle, of_routep->prefix, hashstr, sizeof(hashstr));
    hmap_insert(&l3_route_table, &ops_routep->node, hash_string(hashstr, 0));
    VLOG_DBG("route hash inserted %lx: %s", vrf_handle, ops_routep->prefix);
    return ops_routep;
}

static void
l3_route_hash_update(
        switch_handle_t vrf_handle,
        struct ofproto_route *of_routep,
        struct ops_route *ops_routep,
        bool is_delete_nh)
{
    struct ops_nexthop* nh;
    struct ofproto_route_nexthop *of_nh;
    switch_handle_t nhop_handle = 0;
    int i;

    for (i = 0; i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        nh = l3_nexthop_hash_lookup(ops_routep, of_nh);
        if (is_delete_nh) {
            l3_nexthop_hash_delete(ops_routep, nh);
        } else {
            /* add or update */
            if (!nh) {
                l3_nexthop_hash_insert(ops_routep, of_nh);
            } else {
                if (of_nh->state == OFPROTO_NH_RESOLVED) {
                    nh->nhop_handle = id_to_handle(
                                       SWITCH_HANDLE_TYPE_NHOP,
                                       of_nh->l3_egress_id);
                } else {
                    nh->nhop_handle = l3_route_nhop_glean_get();
                }

            }
        }
    }
    VLOG_DBG("route hash updated %lx: %s", vrf_handle, ops_routep->prefix);
}

/* Delete route in system*/
static void
l3_route_hash_delete(
        struct ops_route *ops_routep)
{
    struct ops_nexthop *nh, *next;

    if (!ops_routep) {
        return;
    }

    hmap_remove(&l3_route_table, &ops_routep->node);

    HMAP_FOR_EACH_SAFE(nh, next, node, &ops_routep->nexthops) {
        l3_nexthop_hash_delete(ops_routep, nh);
    }

    if (ops_routep->prefix) {
        free(ops_routep->prefix);
    }

    VLOG_DBG("route hash deleted %lx: %s",
               ops_routep->vrf_handle,
               ops_routep->prefix);

    free(ops_routep);
}

switch_handle_t
l3_nexthop_ofroute_get(struct ofproto_route_nexthop *nh)
{
    switch_handle_t nhop_handle = 0;

    if (nh->state == OFPROTO_NH_RESOLVED) {
        nhop_handle = id_to_handle(
                           SWITCH_HANDLE_TYPE_NHOP,
                           nh->l3_egress_id);
    } else {
        nhop_handle = l3_route_nhop_glean_get();
    }

    return nhop_handle;
}

static int
l3_dump_route_entry(const struct ofproto *ofproto_,
                   struct ofproto_route *of_routep,
                   switch_ip_addr_t *ip_address)
{
    struct ofproto_route_nexthop *nh;
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    int index = 0;

    VLOG_INFO("vrf %lx", ofproto->vrf_handle);
    VLOG_INFO("ip address %s", of_routep->prefix);
    VLOG_INFO("n_nexthops %d", of_routep->n_nexthops);

    for (index = 0; index < of_routep->n_nexthops; index++) {
        nh = &of_routep->nexthops[index];
        VLOG_INFO("nhop %d", index + 1);
        VLOG_INFO("id %s", nh->id);
        VLOG_INFO("type %s", nh->type == OFPROTO_NH_PORT ? "port" : "ip");
        VLOG_INFO("state %s", nh->state == OFPROTO_NH_RESOLVED ? "resolved" : "unresolved");
        VLOG_INFO("l3_egress_id %d", nh->l3_egress_id);
    }
    return 0;
}

static int
l3_ecmp_create(
        struct ops_route *ops_routep)
{
    switch_handle_t ecmp_handle = 0;
    switch_handle_t nhop_handle[MAX_NEXTHOPS_PER_ROUTE];
    uint16_t nh_count = 0;
    struct ops_nexthop *ops_nh = NULL;
    int i = 0;

    HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
        nhop_handle[nh_count++] = ops_nh->nhop_handle;
        if (nh_count == MAX_NEXTHOPS_PER_ROUTE) {
            break;
        }
    }

    VLOG_INFO("nhop_count for ecmp %d", nh_count);
    for (i = 0; i < nh_count; i++) {
        VLOG_INFO("nhop %d: %lx", i, nhop_handle[i]);
    }

    if (nh_count) {
        ecmp_handle = switch_api_ecmp_create_with_members(
                                 0x0,
                                 nh_count,
                                 nhop_handle);
        if (ecmp_handle == SWITCH_API_INVALID_HANDLE) {
            return EINVAL;
        }

        ops_routep->handle = ecmp_handle;
        ops_routep->ecmp_enabled = true;
        return 0;
    }

    return EINVAL;
}

static int
l3_ecmp_delete(
        struct ops_route *ops_routep)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_handle_t nhop_handle[MAX_NEXTHOPS_PER_ROUTE];
    switch_handle_t ecmp_handle = 0;
    uint16_t nh_count = 0;
    struct ops_nexthop *ops_nh = NULL;

    if (!ops_routep->ecmp_enabled) {
        return 0;
    }

    HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
        nhop_handle[nh_count++] = ops_nh->nhop_handle;
    }

    ecmp_handle = ops_routep->handle;

    if (nh_count != 0) {
        status = switch_api_ecmp_member_delete(
                             0x0,
                             ecmp_handle,
                             nh_count,
                             nhop_handle);
        if (status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("failed to delete ecmp members");
        }
    }

    status = switch_api_ecmp_delete(0x0, ecmp_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to delete ecmp");
        return EINVAL;
    }

    VLOG_DBG("ecmp handle deleted %lx", ecmp_handle);

    ops_routep->handle = 0;
    ops_routep->ecmp_enabled = false;
    return 0;
}

static int
l3_route_entry_new(
        switch_handle_t vrf_handle,
        switch_ip_addr_t *ip_address,
        struct ofproto_route *of_routep)
{
    struct ops_route *ops_routep = NULL;
    struct ops_nexthop *ops_nh = NULL;
    switch_handle_t handle = 0;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    int rc = 0;

    ops_routep = l3_route_hash_insert(vrf_handle, of_routep);

    if (ops_routep->n_nexthops > 1) {
        rc = l3_ecmp_create(ops_routep);
        if (rc != 0) {
            VLOG_ERR("failed to create ecmp members");
            return rc;
        }
        handle = ops_routep->handle;
    } else {
        HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
            handle = ops_nh->nhop_handle;
            break;
        }
    }

    status = switch_api_l3_route_add(
                             0x0,
                             vrf_handle,
                             ip_address,
                             handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to add new route %d", status);
        return EINVAL;
    }

    VLOG_INFO("route added with handle %lx", handle);
    return 0;
}

static int
l3_ecmp_members_update(
        struct ofproto_route *of_routep,
        struct ops_route *ops_routep)
{
    struct ofproto_route_nexthop *of_nh = NULL;
    struct ops_nexthop *nh = NULL;
    switch_handle_t add_nh[MAX_NEXTHOPS_PER_ROUTE];
    switch_handle_t rem_nh[MAX_NEXTHOPS_PER_ROUTE];
    int add_nh_count = 0;
    int rem_nh_count = 0;
    switch_handle_t of_nhop_handle = 0;
    switch_handle_t nhop_handle = 0;
    int i = 0;
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    ovs_assert(ops_routep->ecmp_enabled == true);

    for (i = 0; i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        nh = l3_nexthop_hash_lookup(ops_routep, of_nh);
        of_nhop_handle = l3_nexthop_ofroute_get(of_nh);
        if (!nh) {
            if (add_nh_count < MAX_NEXTHOPS_PER_ROUTE) {
                add_nh[add_nh_count++] = of_nhop_handle;
            }
        } else {
            nhop_handle = nh->nhop_handle;
            if (nhop_handle != of_nhop_handle) {
                if (rem_nh_count < MAX_NEXTHOPS_PER_ROUTE &&
                    add_nh_count < MAX_NEXTHOPS_PER_ROUTE) {
                    rem_nh[rem_nh_count++] = nhop_handle;
                    add_nh[add_nh_count++] = of_nhop_handle;
                }
            }
        }
    }

    if (add_nh_count) {
        for (i = 0; i < add_nh_count; i++) {
            VLOG_INFO("nhop %d: %lx", i, add_nh[i]);
        }

        status = switch_api_ecmp_member_add(
                             0x0,
                             ops_routep->handle,
                             add_nh_count,
                             add_nh);
        if (status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("failed to add ecmp members");
        }
    }

    if (rem_nh_count) {
        for (i = 0; i < rem_nh_count; i++) {
            VLOG_INFO("nhop %d: %lx", i, rem_nh[i]);
        }
        status = switch_api_ecmp_member_delete(
                             0x0,
                             ops_routep->handle,
                             rem_nh_count,
                             rem_nh);
        if (status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("failed to remove ecmp members");
        }
    }

    VLOG_INFO("route updated with ecmp handle %lx", ops_routep->handle);
}

static int
l3_route_entry_update(
        switch_handle_t vrf_handle,
        switch_ip_addr_t *ip_address,
        struct ofproto_route *of_routep,
        struct ops_route *ops_routep)
{
    switch_handle_t handle = 0;
    struct ofproto_route_nexthop *of_nh = NULL;
    struct ops_nexthop *ops_nh = NULL;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    int rc = 0;
    int new_nexthops = 0;
    int total_nexthops = 0;
    int i = 0;

    ovs_assert(of_routep && ops_routep);

    for (i = 0; i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        ops_nh = l3_nexthop_hash_lookup(ops_routep, of_nh);
        if (!ops_nh) {
            new_nexthops++;
        }
    }

    total_nexthops = ops_routep->n_nexthops + new_nexthops;

    if (total_nexthops <= 1) {
        /*
         * non-ecmp update
         */
        l3_route_hash_update(vrf_handle, of_routep, ops_routep, false);
        HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
            handle = ops_nh->nhop_handle;
        }
        status = switch_api_l3_route_add(
                                 0x0,
                                 vrf_handle,
                                 ip_address,
                                 handle);
        if (status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("failed to add update route");
            return EINVAL;
        }
    } else if (total_nexthops > 1 && ops_routep->n_nexthops <= 1) {
        /* non-ecmp route to ecmp route
         * 1. update the hash to new set of nexthops
         * 2. create ecmp object and members with new nexthops
         * 3. update route with ecmp handle
         */
        l3_route_hash_update(vrf_handle, of_routep, ops_routep, false);
        rc = l3_ecmp_create(ops_routep);
        if (rc == EINVAL) {
            VLOG_ERR("failed to create ecmp");
            return rc;
        }
        handle = ops_routep->handle;
        status = switch_api_l3_route_add(
                                 0x0,
                                 vrf_handle,
                                 ip_address,
                                 handle);
        if (status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("failed to update route");
            return EINVAL;
        }
    } else if (total_nexthops > 1 && ops_routep->n_nexthops > 1) {
        /* ecmp route to ecmp route */
        rc = l3_ecmp_members_update(of_routep, ops_routep);
        if (rc == EINVAL) {
            VLOG_ERR("P4: route update failed");
            return rc;
        }
        l3_route_hash_update(vrf_handle, of_routep, ops_routep, false);
        return 0;
    }

    VLOG_INFO("route updated with handle %lx", handle);
    return 0;
}

static int
l3_route_entry_add(const struct ofproto *ofproto_,
                   struct ofproto_route *of_routep,
                   switch_ip_addr_t *ip_address)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ops_route *ops_routep = NULL;
    switch_handle_t vrf_handle = 0;
    switch_handle_t handle = 0;
    struct ops_nexthop *ops_nh = NULL;
    int rc = 0;

    l3_dump_route_entry(ofproto_, of_routep, ip_address);

    vrf_handle = ofproto->vrf_handle;

    ops_routep = l3_route_hash_lookup(vrf_handle, of_routep);
    if (!ops_routep) {
        rc = l3_route_entry_new(
                             vrf_handle,
                             ip_address,
                             of_routep);
    } else {
        rc = l3_route_entry_update(
                             vrf_handle,
                             ip_address,
                             of_routep,
                             ops_routep);
    }

    if (rc == EINVAL) {
        VLOG_ERR("l3_route_entry_add failed");
        return rc;
    }

    return rc;
}

static int
l3_route_entry_delete(
        const struct ofproto *ofproto_,
        struct ofproto_route *of_routep,
        switch_ip_addr_t *ip_address)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ops_route *ops_routep = NULL;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    int error = 0;

    l3_dump_route_entry(ofproto_, of_routep, ip_address);

    ops_routep = l3_route_hash_lookup(ofproto->vrf_handle, of_routep);
    if (!ops_routep) {
        VLOG_ERR("failed to get route");
        return EINVAL;
    }

    l3_ecmp_delete(ops_routep);

    status = switch_api_l3_route_delete(
                             0x0,
                             ops_routep->vrf_handle,
                             ip_address,
                             0x0);

    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("failed to delete route entry");
        error = EINVAL;
    }

    l3_route_hash_delete(ops_routep);

    return error;
}

static int
l3_nhop_entry_delete(
        const struct ofproto *ofproto_,
        struct ofproto_route *of_routep,
        switch_ip_addr_t *ip_address)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ops_route *ops_routep = NULL;
    struct ops_nexthop *ops_nh = NULL;
    struct ops_nexthop *ops_nh_tmp = NULL;
    struct ofproto_route_nexthop *of_nh = NULL;
    int new_n_nexthops = 0;
    switch_handle_t handle = 0;
    switch_handle_t vrf_handle = 0;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_handle_t rem_nh[MAX_NEXTHOPS_PER_ROUTE];
    uint16_t rem_nh_count = 0;
    bool nhop_found = false;
    int rc = 0;
    int i = 0;

    l3_dump_route_entry(ofproto_, of_routep, ip_address);

    vrf_handle = ofproto->vrf_handle;

    ops_routep = l3_route_hash_lookup(vrf_handle, of_routep);
    if (!ops_routep) {
        VLOG_ERR("failed to get route");
        return EINVAL;
    }

    for (i = 0; i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        ops_nh = l3_nexthop_hash_lookup(ops_routep, of_nh);
        if (ops_nh) {
            rem_nh_count++;
        }
    }

    if (!rem_nh_count) {
        VLOG_ERR("no nhops to be deleted");
        return EINVAL;
    }

    new_n_nexthops = ops_routep->n_nexthops - rem_nh_count;
    ovs_assert(new_n_nexthops >= 0);

    VLOG_INFO("total nh %d new nh %d rem nh %d",
               ops_routep->n_nexthops,
               new_n_nexthops,
               rem_nh_count);
    /*
     * There can never be non-ecmp to non-ecmp or
     * non-ecmp to ecmp
     */

    /* ecmp to non-ecmp */
    if (new_n_nexthops <= 1 && ops_routep->n_nexthops > 1) {

        /*
         * find the nexthop from ops_routep which is not
         * in of_routep.
         */
        HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
            nhop_found = false;
            for (i = 0; i < of_routep->n_nexthops; i++) {
                of_nh = &of_routep->nexthops[i];
                ops_nh_tmp = l3_nexthop_hash_lookup(ops_routep, of_nh);

                /*
                 * this should never happen. all of_routep nexthops
                 * must be in ops_routep hashmap.
                 */
                if (!ops_nh_tmp) {
                    continue;
                }

                if (ops_nh_tmp->nhop_handle == ops_nh->nhop_handle) {
                    nhop_found = true;
                    break;
                }
            }

            if (!nhop_found) {
                handle = ops_nh->nhop_handle;
                break;
            }
        }

        if (handle) {
            status = switch_api_l3_route_add(
                                 0x0,
                                 vrf_handle,
                                 ip_address,
                                 handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                VLOG_ERR("delete nh: failed to update route");
            }
        }

        rc = l3_ecmp_delete(ops_routep);
        if (rc == EINVAL) {
            VLOG_ERR("nhop entry delete failed");
            return rc;
        }

        l3_route_hash_update(vrf_handle, of_routep, ops_routep, true);
    /* ecmp to ecmp */
    } else {
        rem_nh_count = 0;
        for (i = 0; i < of_routep->n_nexthops; i++) {
            of_nh = &of_routep->nexthops[i];
            ops_nh = l3_nexthop_hash_lookup(ops_routep, of_nh);
            if (ops_nh) {
                if (rem_nh_count < MAX_NEXTHOPS_PER_ROUTE) {
                    rem_nh[rem_nh_count++] = l3_nexthop_ofroute_get(&of_routep->nexthops[i]);
                }
            }
        }

        VLOG_INFO("ecmp handle %lx rem_nh %x", ops_routep->handle, rem_nh_count);

        for (i = 0; i < rem_nh_count; i++) {
            VLOG_INFO("rem nh %d: %lx", i, rem_nh[i]);
        }

        if (rem_nh_count) {
            status = switch_api_ecmp_member_delete(
                                 0x0,
                                 ops_routep->handle,
                                 rem_nh_count,
                                 rem_nh);
            if (status != SWITCH_STATUS_SUCCESS) {
                VLOG_ERR("failed to delete ecmp members %d", status);
            }
        }

        l3_route_hash_update(vrf_handle, of_routep, ops_routep, true);
    }

    VLOG_INFO("route updated with handle %lx", ops_routep->handle);
    return 0;
}

static int
l3_route_action(const struct ofproto *ofproto,
                enum ofproto_route_action action,
                struct ofproto_route *of_routep)
{
    struct ofproto_route_nexthop *of_nh = NULL;
    switch_ip_addr_t ip_address;
    bool is_ipv6_addr = false;
    int rc = 0;
    int i = 0;

    switch (of_routep->family) {
        case OFPROTO_ROUTE_IPV4:
            is_ipv6_addr = false;
            ip_address.type = SWITCH_API_IP_ADDR_V4;
            ip_string_to_prefix(
                    is_ipv6_addr,
                    of_routep->prefix,
                    &ip_address.ip.v4addr,
                    &ip_address.prefix_len);
            break;
        case OFPROTO_ROUTE_IPV6:
            is_ipv6_addr = true;
            ip_address.type = SWITCH_API_IP_ADDR_V6;
            ip_string_to_prefix(
                    is_ipv6_addr,
                    of_routep->prefix,
                    &ip_address.ip.v6addr,
                    &ip_address.prefix_len);
            break;
        default:
            return EINVAL;
    }

    VLOG_INFO("l3_route_action: is v6 addr: %d", (int)is_ipv6_addr);
    VLOG_INFO("l3_route_action: ip addr: %s", of_routep->prefix);

    switch (action) {
        case OFPROTO_ROUTE_ADD:
            VLOG_INFO("l3_route_action: received route add");
            rc = l3_route_entry_add(ofproto, of_routep, &ip_address);
            break;
        case OFPROTO_ROUTE_DELETE:
            VLOG_INFO("l3_route_action: received route delete");
            rc = l3_route_entry_delete(ofproto, of_routep, &ip_address);
            break;
        case OFPROTO_ROUTE_DELETE_NH:
            VLOG_INFO("l3_route_action: received delete nhop");
            rc = l3_nhop_entry_delete(ofproto, of_routep, &ip_address);
            break;
        default:
            return EINVAL;
    }

    if (rc != 0) {
        for (i = 0; i < of_routep->n_nexthops; i++) {
            of_nh = &of_routep->nexthops[i];
            of_nh->rc = rc;
        }
    }

    return rc;
}

const struct ofproto_class ofproto_sim_provider_class = {
    init,
    enumerate_types,
    enumerate_names,
    del,
    port_open_type,
    NULL,                       /* may implement type_run */
    NULL,                       /* may implement type_wait */
    alloc,
    construct,
    destruct,
    dealloc,
    run,
    wait,
    NULL,                       /* get_memory_usage */
    NULL,                       /* may implement type_get_memory_usage */
    NULL,                       /* may implement flush */
    query_tables,

    set_table_version,

    port_alloc,
    port_construct,
    port_destruct,
    port_dealloc,
    NULL,                       /* may implement port_modified */
    port_reconfigured,
    port_query_by_name,
    port_add,
    port_del,
    port_get_stats,
    port_dump_start,
    port_dump_next,
    port_dump_done,
    NULL,                       /* may implement port_poll */
    NULL,                       /* may implement port_poll_wait */
    NULL,                       /* may implement port_is_lacp_current */
    NULL,                       /* may implement port_get_lacp_stats */
    NULL,                       /* rule_choose_table */
    rule_alloc,
    rule_construct,
    rule_insert,
    rule_delete,
    rule_destruct,
    rule_dealloc,
    rule_get_stats,
    rule_execute,

    set_frag_handling,
    packet_out,
    NULL,                       /* may implement set_netflow */
    get_netflow_ids,
    NULL,                       /* may implement set_sflow */
    NULL,                       /* may implement set_ipfix */
    NULL,                       /* may implement set_cfm */
    cfm_status_changed,
    NULL,                       /* may implement get_cfm_status */

    NULL,                       /* may implement set_lldp */
    NULL,                       /* may implement get_lldp_status */
    NULL,                       /* may implement set_aa */
    NULL,                       /* may implement aa_mapping_set */
    NULL,                       /* may implement aa_mapping_unset */
    NULL,                       /* may implement aa_vlan_get_queued */
    NULL,                       /* may implement aa_vlan_get_queue_size */

    NULL,                       /* may implement set_bfd */
    bfd_status_changed,
    NULL,                       /* may implement get_bfd_status */
    NULL,                       /* may implement set_stp */
    NULL,                       /* may implement get_stp_status */
    NULL,                       /* may implement set_stp_port */
    NULL,                       /* may implement get_stp_port_status */
    NULL,                       /* may implement get_stp_port_stats */
    NULL,                       /* may implement set_rstp */
    NULL,                       /* may implement get_rstp_status */
    NULL,                       /* may implement set_rstp_port */
    NULL,                       /* may implement get_rstp_port_status */
    NULL,                       /* may implement set_queues */
    bundle_set,
    bundle_remove,
    bundle_get,
    set_vlan,
    NULL,                       /* may implement mirror_set__ */
    mirror_get_stats__,
    NULL,                       /* may implement set_flood_vlans */
    is_mirror_output_bundle,
    forward_bpdu_changed,
    NULL,                       /* may implement set_mac_table_config */
    NULL,                       /* may implement set_mcast_snooping */
    NULL,                       /* may implement set_mcast_snooping_port */
    NULL,                       /* set_realdev, is unused */
    NULL,                       /* meter_get_features */
    NULL,                       /* meter_set */
    NULL,                       /* meter_get */
    NULL,                       /* meter_del */
    group_alloc,                /* group_alloc */
    group_construct,            /* group_construct */
    group_destruct,             /* group_destruct */
    group_dealloc,              /* group_dealloc */
    group_modify,               /* group_modify */
    group_get_stats,            /* group_get_stats */
    get_datapath_version,       /* get_datapath_version */
    add_l3_host_entry,          /* Add l3 host entry */
    delete_l3_host_entry,       /* Delete l3 host entry */
    NULL,                       /* Get l3 host entry hit bits */
    l3_route_action,            /* l3 route action - install, update, delete */
    NULL,                       /* enable/disable ECMP globally */
    NULL,                       /* enable/disable ECMP hash configs */
};
