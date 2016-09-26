#include <errno.h>

#include "unixctl.h"
#include "util.h"
#include "linux/if_ether.h"
#include "openvswitch/vlog.h"
#include "switchapi/switch_interface.h"
#include "switchapi/switch_l2.h"
#include "switchapi/switch_vrf.h"
#include "switchapi/switch_capability.h"
#include <ovs/dynamic-string.h>
#include "netdev-p4-vport.h"
#include "netdev-provider.h"
#include "netdev-p4-sim.h"
#include "ofproto-p4-sim-provider.h"
#include "switchapi/switch_tunnel.h"
#include "ops-tunnel.h"
#include "netinet/ether.h"
//#include "switch_capability_int.h"

VLOG_DEFINE_THIS_MODULE(P4_vport);

/**** Logical Network for terminal diag ****/
switch_logical_network_t           p4_ln_info;
switch_handle_t                    p4_ln_handle;
/*******************************************/

static  uint16_t tnl_udp_port = UDP_PORT_MIN;

/* All existing ofproto provider instances, indexed by ->up.name. */
//static struct hmap all_logical_net_nodes =
//                        HMAP_INITIALIZER(&all_logical_net_nodes);

static uint32_t get_prefix_len(const char * route_prefix);
static void ip_to_prefix(uint32_t ip, uint32_t prefix_len, char *ip_prefix);

struct hmap tunnel_hmap = HMAP_INITIALIZER(&tunnel_hmap);

/* caller has to validate *dev
 * ip_addr is hostbyte order
 */
tunnel_node *
tnl_insert(struct netdev *dev, uint32_t ip_addr)
{
    tunnel_node *node = NULL;
    node = xmalloc(sizeof *node); /* Check if xmalloc is successful */
    hmap_insert(&tunnel_hmap, &node->hmap_t_node, hash_int(ip_addr, 0));
    node->remote_ip = ip_addr;
    node->netdev = dev;
    VLOG_INFO("Insert hashmap tunnel dest IP 0x%x", ip_addr);
    return node;
}

tunnel_node *
tnl_lookup_ip(uint32_t ip)
{
    tunnel_node *node;
    uint32_t hash = hash_int(ip, 0);
    HMAP_FOR_EACH_WITH_HASH(node, hmap_t_node, hash, &tunnel_hmap) {
        if (node->remote_ip == ip) {
            return node;
        }
    }
    return NULL;
}

/* caller has to validate *dev */
tunnel_node *
tnl_lookup_netdev(struct netdev *netdev)
{
	uint32_t ip = 0;
    const struct netdev_tunnel_config *tnl_cfg = netdev_get_tunnel_config(netdev);
    if (tnl_cfg) {
        ip = ntohl(in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_dst));
        if (!ip) {
            /* TODO with ipv6 */
            return NULL;
        }
    }
    return tnl_lookup_ip(ip);
}

/* caller has to validate *netdev */
void
tnl_remove(struct netdev *netdev)
{
    tunnel_node *node;
    node = tnl_lookup_netdev(netdev);
    if(node) {
        hmap_remove(&tunnel_hmap, &node->hmap_t_node);
        free(node);
    }
}
static int
get_src_udp(void)
{
    uint16_t next = tnl_udp_port++;
    if(tnl_udp_port == UDP_PORT_MAX)
       tnl_udp_port = UDP_PORT_MIN;
    return (int)next;
}

static inline int
get_vni(struct netdev *netdev)
{
    const struct netdev_tunnel_config *tnl_cfg;
    tnl_cfg = netdev_get_tunnel_config(netdev);
    if(tnl_cfg && (tnl_cfg->in_key_present) && (!tnl_cfg->in_key_flow)) {
        return ntohll(tnl_cfg->in_key);
    }
    return -1;
}

/*
static switch_handle_t
get_logical_network(int vni)
{
    struct hmap_node *lnw;
    HMAP_FOR_EACH(lnw, hmap_node, &all_logical_net_nodes) {
        if (lnw  == vni )


}
*/
static void
print_tunnel_info(switch_tunnel_info_t *tunnel_info)
{
    VLOG_INFO("ENCP_MODE = %d", tunnel_info->encap_mode);
    VLOG_INFO("SRC IP = %lx", tunnel_info->u.ip_encap.src_ip.ip.v4addr);
    VLOG_INFO("DST IP = %lx", tunnel_info->u.ip_encap.dst_ip.ip.v4addr);
    VLOG_INFO("VRF Handle = %lx", tunnel_info->u.ip_encap.vrf_handle);
    VLOG_INFO("TTL = %d", tunnel_info->u.ip_encap.ttl);
    VLOG_INFO("proto = %d", tunnel_info->u.ip_encap.proto);
    VLOG_INFO("SRC Port = %d", tunnel_info->u.ip_encap.u.udp.src_port);
    VLOG_INFO("DST Port = %d", tunnel_info->u.ip_encap.u.udp.dst_port);
    VLOG_INFO("ENCAP type = %d", tunnel_info->encap_info.encap_type);
    VLOG_INFO("VNI = %d", tunnel_info->encap_info.u.vxlan_info.vnid);
    VLOG_INFO("Out Inf = %lx", tunnel_info->out_if);
    VLOG_INFO("Core Intf = %d", tunnel_info->flags.core_intf);
    VLOG_INFO("Flood Enabled = %d", tunnel_info->flags.flood_enabled);
}

switch_handle_t
p4_ops_vport_create_tunnel(struct ofbundle *bundle, struct netdev *netdev)
{
    int                         unit, rc = 0;
    const struct netdev_tunnel_config *tnl_cfg;
    switch_tunnel_info_t        tunnel_info;
    switch_udp_t                udp;
    switch_ip_addr_t            dst_ip, src_ip;
    ovs_be32                    ipv4;
    switch_api_interface_info_t i_info;
    switch_api_interface_info_t *access_intf_info;
    struct sim_provider_node    *ofproto = bundle->ofproto;
    const char                  *devname = NULL;
    struct sim_provider_ofport *port = NULL;

    VLOG_INFO("bundle name = %s, if_handle = %d", bundle->name, bundle->if_handle);
    tnl_cfg = netdev_get_tunnel_config(netdev);

    ovs_assert(!P4_HANDLE_IS_VALID(bundle->if_handle));
    memset(&i_info, 0, sizeof(switch_api_interface_info_t));

    memset(&tunnel_info, 0, sizeof(switch_tunnel_info_t));
    tunnel_info.encap_mode = SWITCH_API_TUNNEL_ENCAP_MODE_IP;

    ipv4 =  in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_src);
    if(!ipv4) {
        /* TODO: support IPV6 */
        char ipv6[INET6_ADDRSTRLEN];
        ipv6_string_mapped(ipv6, &tnl_cfg->ipv6_src);
        VLOG_INFO("Invalid source IP %s\n",ipv6);
        return EINVAL;
    }
    /* Update source IP of the tunnel */
    tunnel_info.u.ip_encap.src_ip.type = SWITCH_API_IP_ADDR_V4;
    tunnel_info.u.ip_encap.src_ip.ip.v4addr = ntohl(ipv4);
    tunnel_info.u.ip_encap.src_ip.prefix_len = 32;

    ipv4 =  in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_dst);
    if(!ipv4) {
        /* TODO: support IPV6 */
        VLOG_INFO("Invalid remote IP\n");
        return EINVAL;
    }
    /* Update destination IP of the tunnel */
    tunnel_info.u.ip_encap.dst_ip.type = SWITCH_API_IP_ADDR_V4;
    tunnel_info.u.ip_encap.dst_ip.ip.v4addr = ntohl(ipv4);
    tunnel_info.u.ip_encap.dst_ip.prefix_len = 32;

    /* if no VRF present then including tunnel as a part of default VRF */
    if(ofproto->vrf_handle == 0 && switch_api_default_vrf_internal() != 0) {
        tunnel_info.u.ip_encap.vrf_handle = switch_api_default_vrf_internal();
    }
    else {
        tunnel_info.u.ip_encap.vrf_handle = ofproto->vrf_handle;
    }
    tunnel_info.u.ip_encap.ttl = tnl_cfg->ttl;

    tunnel_info.u.ip_encap.proto == 17; // VxLAN protocol
    tunnel_info.u.ip_encap.u.udp.src_port = get_src_udp();
    tunnel_info.u.ip_encap.u.udp.dst_port = ntohs(tnl_cfg->dst_port);

    tunnel_info.encap_info.encap_type = SWITCH_API_ENCAP_TYPE_VXLAN;
    tunnel_info.encap_info.u.vxlan_info.vnid = get_vni(netdev);

    tunnel_info.out_if = get_intf_handle_from_ip(&(tunnel_info.u.ip_encap.src_ip));
    tunnel_info.flags.core_intf = true;
    tunnel_info.flags.flood_enabled = true;

    // print_tunnel_info(&tunnel_info);
    bundle->if_handle = switch_api_tunnel_interface_create(DEFAULT_P4_DEVICE,
                            SWITCH_API_DIRECTION_BOTH, &tunnel_info);
    if (P4_HANDLE_IS_VALID(bundle->if_handle)) {
        /* TODO: Identify if stats also need to be enabled */
        /* switch_api_vlan_stats_enable(device, handle); */
        VLOG_INFO("Created VxLAN Tunnel interface, handle = %lx", bundle->if_handle);
        return bundle->if_handle;
    }
    return SWITCH_API_INVALID_HANDLE;
}

int
ops_vport_tunnel_add_neighbor(struct ofbundle *bundle, switch_handle_t tunnel_handle,
                              struct ops_neighbor *nbor)
{
    struct sim_provider_node    *ofproto = bundle->ofproto;
    switch_handle_t             access_handle = 0;
    switch_handle_t             vlan_handle = 0;
    switch_handle_t             neigh1_handle = 0;
    switch_handle_t             neigh2_handle = 0;
    switch_api_neighbor_t       neighbor1;
    switch_api_neighbor_t       neighbor2;
    switch_interface_type_t     type = 0;
    switch_vlan_t               vlan_id;
    switch_handle_t             nhop_handle = 0;
    struct ether_addr *         mac_addr = NULL;
    switch_nhop_key_t           nexthop_key;
    switch_status_t             status;

    //logical_net = get_logical_network(tunnel_info.encap_info.u.vxlan_info.vnid);
    /* TODO Remove hardcoded interface 1 as a Access port */
    access_handle = get_intf_handle_from_name("1");
    switch_api_interface_get_type(access_handle, &type);
    VLOG_INFO("interface type = %d", type);
    switch_api_interface_get_vlan_handle(access_handle, &vlan_handle);
    switch_api_vlan_handle_to_id_get(vlan_handle, &vlan_id);

    VLOG_INFO("VLAN id = %d", vlan_id);
    /* TODO Identify the prefix length for IP address */
    if (!P4_HANDLE_IS_VALID(access_handle)) {
        VLOG_INFO("Unable to ge the access interface handle for interface 1");
        return 0;
    }
    VLOG_INFO("Access Handle is = %lx", access_handle);
    status = switch_api_logical_network_member_add(DEFAULT_P4_DEVICE, p4_ln_handle, access_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_INFO("Unable to add access interface member to logical network");
        return 0;
    }
    VLOG_INFO("Tunnel Handle is = %lx", tunnel_handle);
    status = switch_api_logical_network_member_add(DEFAULT_P4_DEVICE, p4_ln_handle, tunnel_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_INFO("Unable to add tunnel interface member to logical network");
        return 0;
    }

    VLOG_INFO("added both the interfaces to logical network");

    memset(&nexthop_key, 0x0, sizeof(switch_nhop_key_t));
    nexthop_key.intf_handle = tunnel_handle;
    nexthop_key.ip_addr_valid = false;
    nhop_handle = switch_api_nhop_create(DEFAULT_P4_DEVICE, &nexthop_key);
    VLOG_INFO("nexthop handle %lx", nbor->nhop_handle);

    memset(&neighbor1, 0x0, sizeof(switch_api_neighbor_t));
    neighbor1.neigh_type = SWITCH_API_NEIGHBOR_IPV4_TUNNEL;
    neighbor1.rw_type = SWITCH_API_NEIGHBOR_RW_TYPE_L2;
    neighbor1.vrf_handle = ofproto->vrf_handle;
    neighbor1.interface = tunnel_handle;
    neighbor1.nhop_handle = nhop_handle;
    neighbor1.ip_addr.type = SWITCH_API_IP_ADDR_V4;
    neighbor1.ip_addr.ip.v4addr = nbor->ip;
    neighbor1.ip_addr.prefix_len = 32;

    //memcpy(&neighbor1.ip_addr, &tunnel_info.u.ip_encap.src_ip, sizeof(switch_ip_addr_t));
    VLOG_INFO("Adding neighbor IP: %lx, MAC:%s", nbor->ip, nbor->mac);
    mac_addr = ether_aton(CONST_CAST(char *, nbor->mac));
    VLOG_INFO("mac_addr = %lx, &mac_addr->ether_addr_octet %lx", mac_addr, &mac_addr->ether_addr_octet);
    memcpy(&(neighbor1.mac_addr.mac_addr), mac_addr, ETH_ALEN);
    neigh1_handle = switch_api_neighbor_entry_add(DEFAULT_P4_DEVICE, &neighbor1);
    VLOG_INFO("neigh 1 handle %lx", neigh1_handle);

    memset(&neighbor2, 0x0, sizeof(switch_api_neighbor_t));
    neighbor2.neigh_type = SWITCH_API_NEIGHBOR_NONE;
    neighbor2.rw_type = SWITCH_API_NEIGHBOR_RW_TYPE_L2;
    neighbor2.vrf_handle = ofproto->vrf_handle;
    neighbor2.interface = tunnel_handle;
    neighbor2.nhop_handle = 0x0;
    neighbor2.ip_addr.type = SWITCH_API_IP_ADDR_V4;
    neighbor2.ip_addr.ip.v4addr = nbor->ip;
    neighbor2.ip_addr.prefix_len = 32;
    //memcpy(&neighbor2.ip_addr, &tunnel_info.u.ip_encap.src_ip, sizeof(switch_ip_addr_t));
    mac_addr = ether_aton(CONST_CAST(char *, nbor->mac));
    memcpy(&neighbor2.mac_addr.mac_addr, mac_addr, ETH_ALEN);
    neigh2_handle = switch_api_neighbor_entry_add(DEFAULT_P4_DEVICE, &neighbor2);
    VLOG_INFO("neigh 2 handle %lx", neigh2_handle);

    /*
    switch_api_mac_entry_t mac_entry1;
    memset(&mac_entry1, 0x0, sizeof(switch_api_mac_entry_t));
    memcpy(&mac_entry1.mac.mac_addr, ether_aton("00:00:00:00:aa:01"), ETH_ALEN);
    mac_entry1.vlan_handle = p4_ln_handle;
    mac_entry1.handle = access_handle;
    mac_entry1.entry_type = SWITCH_MAC_ENTRY_STATIC;
    switch_api_mac_table_entry_add(DEFAULT_P4_DEVICE, &mac_entry1);
    VLOG_INFO("added mac 1");

    switch_api_mac_entry_t mac_entry2;
    memset(&mac_entry2, 0x0, sizeof(switch_api_mac_entry_t));
    memcpy(&mac_entry2.mac.mac_addr, ether_aton("00:22:22:22:22:22"), ETH_ALEN);
    mac_entry2.vlan_handle = p4_ln_handle;
    mac_entry2.handle = nhop_handle;
    mac_entry2.entry_type = SWITCH_MAC_ENTRY_STATIC;
    switch_api_mac_table_entry_add(DEFAULT_P4_DEVICE, &mac_entry2);
    VLOG_INFO("added mac 2");
    */
    return 0;
}

static int
ops_vport_lsw_create(int hw_unit, uint32_t vni)
{
    int rc;
    switch_logical_network_t          *ln_info = NULL;
    switch_vrf_info_t                 *vrf_info = NULL;
    struct hmap_node                  *ln_node = NULL;

    ln_info = &p4_ln_info;
    memset(ln_info, 0, sizeof(switch_logical_network_t));

    VLOG_DBG("Creating Logical Network for HW Unit %d and VNI: 0x%x", hw_unit, vni);
    ln_info->type = SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_BASIC;
    ln_info->encap_info.u.tunnel_vni = vni;

    /* TODO: Figure out the exact age interval value to be set */
    ln_info->age_interval = 1800;

    if(switch_api_default_vrf_internal() != 0) {
        ln_info->vrf_handle = switch_api_default_vrf_internal();
    }

    p4_ln_handle = switch_api_logical_network_create(hw_unit, ln_info);
    if (p4_ln_handle != SWITCH_API_INVALID_HANDLE) {
        /* TODO: Identify if stats also need to be enabled */
        /* switch_api_vlan_stats_enable(device, handle); */
        //ln_node = malloc(sizeof(struct hmap_node));
        //hmap_insert(&all_logical_net_nodes, ln_node, hmap_int(vni,0));
        return p4_ln_handle;
    }

    return 0;
}

static void
diag_vport_lsw_create(struct unixctl_conn *conn, int argc,
        const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    int rc;
    int hw_unit = atoi(argv[1]);
    uint32_t vni = atoi(argv[2]);
    VLOG_INFO("%s unit %d vni %d",__func__, hw_unit, vni);
    rc  = ops_vport_lsw_create(hw_unit, vni);
    if (!rc) {
        VLOG_ERR("%s failed rc: %d", __func__, rc);
        ds_put_format(&ds, "fail switch_api_logical_network_create");
    } else {
        VLOG_INFO("Logical Network for HW Unit %d and VNI: 0x%x is %lx", hw_unit, vni, rc);
        ds_put_format(&ds, "Successful create lsw,"
                           " vnid %d logical network handle = %u\n",
                            p4_ln_info.encap_info.u.tunnel_vni, rc);
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

int
p4_vport_init(int hw_unit)
{
    int rc = 0;

    unixctl_command_register("lsw", "hw_unit vni", 2, 2,
                   diag_vport_lsw_create, NULL);

    return 0;
}




void
p4_vport_update_host_chg(int event, char *ip_addr, int l3_egress_id)
{
    uint32_t ip;
    tunnel_node * node;

    if(!ip_addr) {
        VLOG_ERR("%s Null pointer\n", __func__);
        return;
    }
    VLOG_DBG("%s entered, ip %s", __func__, ip_addr);

    /* TODO IPV6 */
    if(!inet_pton(AF_INET, ip_addr, &ip))
        return;

    node = tnl_lookup_ip(ntohl(ip));
    if(node) {
       /*
        * TODO
        * Host is my neighbor, update my tunnel's neighbor
        */
    }
}

/*
 * When ASIC receives Route Action (Add, Delete),
 * This function will traverse the netdev hashmap, pick out
 * the tunnel device and compare its destination ip with
 * the route prefix. If there is a match, it will
 * creat/bind/unbind tunnels depending on the
 * tunnel state and route action
 */

void
p4_vport_update_route_chg(int event, char* route_prefix)
{
    tunnel_node * tnl, *next;
    int plen;
    char ip_prefix[INET_ADDRSTRLEN];
    uint32_t ipv4;

    if(!route_prefix) {
        VLOG_DBG("%s Null pointer \n", __func__);
        return;
    }
    VLOG_INFO("%s entered, route prefix %s", __func__,route_prefix);
    plen = get_prefix_len(route_prefix);
    HMAP_FOR_EACH_SAFE(tnl, next, hmap_t_node, &tunnel_hmap) {
            ipv4 =  htonl(tnl->remote_ip);
            ip_to_prefix(ipv4, plen, ip_prefix);
            VLOG_INFO("My prefix %s vs route_prefix %s", ip_prefix,route_prefix);
            if(strcmp(ip_prefix, route_prefix)== 0){
                VLOG_INFO("Route changed on my tunnel");
                /*
                 * TODO
                 * This route is my route.
                 * Update this tunnel's nexthop if applicable
                 */
            }
    }
}

static uint32_t
get_prefix_len(const char * route_prefix)
{
    char *p = strchr(route_prefix, '/');
    if(p) {
        return atoi(++p);
    }
    return 0;
}

/*
 * Input: net byte order ipv4
 * Out put: route_prefix string
 * X.X.X.X/Y
 */
static void
ip_to_prefix(uint32_t ip, uint32_t prefix_len, char *ip_prefix)
{
    uint32_t prefix, len;
    if(ip_prefix) {
        prefix = ip & be32_prefix_mask(prefix_len);
        inet_ntop(AF_INET, &prefix, ip_prefix, INET_ADDRSTRLEN);
        len = strlen(ip_prefix);
        snprintf(&ip_prefix[len],INET_ADDRSTRLEN - len, "/%d", prefix_len);
    }
}
