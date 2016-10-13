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
#include "netdev-provider.h"
#include "netdev-p4-sim.h"
#include "ofproto-p4-sim-provider.h"
#include "switchapi/switch_tunnel.h"
#include "p4-tunnel.h"
#include "bridge.h"
#include "types.h"
#include "netinet/ether.h"
//#include "switch_capability_int.h"

VLOG_DEFINE_THIS_MODULE(P4_vport);

/**** Logical Network for terminal diag ****/
switch_handle_t                    p4_ln_handle;
/*******************************************/

int
_shr_popcount(unsigned int n)
{
    n = (n & 0x55555555) + ((n >> 1) & 0x55555555);
    n = (n & 0x33333333) + ((n >> 2) & 0x33333333);
    n = (n + (n >> 4)) & 0x0f0f0f0f;
    n = n + (n >> 8);

    return (n + (n >> 16)) & 0xff;
}

static  uint16_t tnl_udp_port = UDP_PORT_MIN;


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
    VLOG_DBG("Insert hashmap tunnel dest IP 0x%x", ip_addr);
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
    VLOG_DBG("ENCP_MODE = %d", tunnel_info->encap_mode);
    VLOG_DBG("SRC IP = %lx", tunnel_info->u.ip_encap.src_ip.ip.v4addr);
    VLOG_DBG("DST IP = %lx", tunnel_info->u.ip_encap.dst_ip.ip.v4addr);
    VLOG_DBG("VRF Handle = %lx", tunnel_info->u.ip_encap.vrf_handle);
    VLOG_DBG("TTL = %d", tunnel_info->u.ip_encap.ttl);
    VLOG_DBG("proto = %d", tunnel_info->u.ip_encap.proto);
    VLOG_DBG("SRC Port = %d", tunnel_info->u.ip_encap.u.udp.src_port);
    VLOG_DBG("DST Port = %d", tunnel_info->u.ip_encap.u.udp.dst_port);
    VLOG_DBG("ENCAP type = %d", tunnel_info->encap_info.encap_type);
    VLOG_DBG("VNI = %d", tunnel_info->encap_info.u.vxlan_info.vnid);
    VLOG_DBG("Out Inf = %lx", tunnel_info->out_if);
    VLOG_DBG("Core Intf = %d", tunnel_info->flags.core_intf);
    VLOG_DBG("Flood Enabled = %d", tunnel_info->flags.flood_enabled);
}

switch_handle_t
p4_vport_create_tunnel(struct ofbundle *bundle, struct netdev *netdev)
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

    VLOG_DBG("bundle name = %s, if_handle = %d", bundle->name, bundle->if_handle);
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
        VLOG_ERR("Invalid source IP %s\n",ipv6);
        return EINVAL;
    }
    /* Update source IP of the tunnel */
    tunnel_info.u.ip_encap.src_ip.type = SWITCH_API_IP_ADDR_V4;
    tunnel_info.u.ip_encap.src_ip.ip.v4addr = ntohl(ipv4);
    tunnel_info.u.ip_encap.src_ip.prefix_len = 32;

    ipv4 =  in6_addr_get_mapped_ipv4(&tnl_cfg->ipv6_dst);
    if(!ipv4) {
        /* TODO: support IPV6 */
        VLOG_ERR("Invalid remote IP\n");
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

    tunnel_info.u.ip_encap.proto = 17; // VxLAN protocol
    tunnel_info.u.ip_encap.u.udp.src_port = get_src_udp();
    tunnel_info.u.ip_encap.u.udp.dst_port = ntohs(tnl_cfg->dst_port);

    tunnel_info.encap_info.encap_type = SWITCH_API_ENCAP_TYPE_VXLAN;
    VLOG_DBG("setting VNI = 0x%x, %d", get_vni(netdev), get_vni(netdev));
    tunnel_info.encap_info.u.vxlan_info.vnid = get_vni(netdev);

    tunnel_info.out_if = p4_get_intf_handle_from_ip(&(tunnel_info.u.ip_encap.src_ip));
    tunnel_info.flags.core_intf = true;
    tunnel_info.flags.flood_enabled = true;

    // print_tunnel_info(&tunnel_info);
    bundle->if_handle = switch_api_tunnel_interface_create(DEFAULT_P4_DEVICE,
                            SWITCH_API_DIRECTION_BOTH, &tunnel_info);
    if (P4_HANDLE_IS_VALID(bundle->if_handle)) {
        /* TODO: Identify if stats also need to be enabled */
        /* switch_api_vlan_stats_enable(device, handle); */
        VLOG_INFO("Created VxLAN Tunnel interface, handle = %lx", bundle->if_handle);
        netdev_set_tunnel_iface_handle(netdev, bundle->if_handle);
        return bundle->if_handle;
    }

    return SWITCH_API_INVALID_HANDLE;
}

int
p4_vport_tunnel_add_neighbor(struct ofbundle *bundle, struct netdev *netdev,
                              struct ops_neighbor *nbor)
{
    struct sim_provider_node    *ofproto = bundle->ofproto;
    switch_handle_t             tunnel_handle = netdev_get_tunnel_iface_handle(netdev);
    switch_handle_t             neigh1_handle = 0;
    switch_handle_t             neigh2_handle = 0;
    switch_api_neighbor_t       neighbor1;
    switch_api_neighbor_t       neighbor2;
    switch_handle_t             nhop_handle = 0;
    struct ether_addr *         mac_addr = NULL;
    switch_nhop_key_t           nexthop_key;
    switch_status_t             status;

    //logical_net = get_logical_network(tunnel_info.encap_info.u.vxlan_info.vnid);
    status = switch_api_logical_network_member_add(DEFAULT_P4_DEVICE, p4_ln_handle, tunnel_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("Unable to add tunnel interface member to logical network");
        return 0;
    }

    netdev_set_logical_nw_handle(netdev, p4_ln_handle);

    memset(&nexthop_key, 0x0, sizeof(switch_nhop_key_t));
    nexthop_key.intf_handle = tunnel_handle;
    nexthop_key.ip_addr_valid = false;
    nhop_handle = switch_api_nhop_create(DEFAULT_P4_DEVICE, &nexthop_key);
    VLOG_DBG("nexthop handle %lx", nbor->nhop_handle);

    netdev_set_nexthop_handle(netdev, nhop_handle);
    memset(&neighbor1, 0x0, sizeof(switch_api_neighbor_t));
    neighbor1.neigh_type = SWITCH_API_NEIGHBOR_IPV4_TUNNEL;
    neighbor1.rw_type = SWITCH_API_NEIGHBOR_RW_TYPE_L2;
    neighbor1.vrf_handle = ofproto->vrf_handle;
    neighbor1.interface = tunnel_handle;
    neighbor1.nhop_handle = nhop_handle;
    neighbor1.ip_addr.type = SWITCH_API_IP_ADDR_V4;
    neighbor1.ip_addr.ip.v4addr = nbor->ip;
    neighbor1.ip_addr.prefix_len = 32;

    VLOG_DBG("Adding neighbor IP: %lx, MAC:%s", nbor->ip, nbor->mac);
    mac_addr = ether_aton(CONST_CAST(char *, nbor->mac));
    memcpy(&(neighbor1.mac_addr.mac_addr), mac_addr, ETH_ALEN);
    neigh1_handle = switch_api_neighbor_entry_add(DEFAULT_P4_DEVICE, &neighbor1);
    VLOG_DBG("neigh 1 handle %lx", neigh1_handle);

    memset(&neighbor2, 0x0, sizeof(switch_api_neighbor_t));
    neighbor2.neigh_type = SWITCH_API_NEIGHBOR_NONE;
    neighbor2.rw_type = SWITCH_API_NEIGHBOR_RW_TYPE_L2;
    neighbor2.vrf_handle = ofproto->vrf_handle;
    neighbor2.interface = tunnel_handle;
    neighbor2.nhop_handle = 0x0;
    neighbor2.ip_addr.type = SWITCH_API_IP_ADDR_V4;
    neighbor2.ip_addr.ip.v4addr = nbor->ip;
    neighbor2.ip_addr.prefix_len = 32;
    mac_addr = ether_aton(CONST_CAST(char *, nbor->mac));
    memcpy(&neighbor2.mac_addr.mac_addr, mac_addr, ETH_ALEN);
    neigh2_handle = switch_api_neighbor_entry_add(DEFAULT_P4_DEVICE, &neighbor2);
    VLOG_DBG("neigh 2 handle %lx", neigh2_handle);

    return 0;
}


int
p4_vport_lsw_create(int hw_unit, uint32_t vni)
{
    int rc;
    switch_logical_network_t          *ln_info = NULL;
    switch_vrf_info_t                 *vrf_info = NULL;
    struct hmap_node                  *ln_node = NULL;
    switch_logical_network_t           p4_ln_info;

    ln_info = &p4_ln_info;
    memset(ln_info, 0, sizeof(switch_logical_network_t));

    VLOG_INFO("Creating Logical Network for HW Unit %d and VNI: 0x%x", hw_unit, vni);
    ln_info->type = SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_BASIC;
    ln_info->encap_info.u.tunnel_vni = vni;

    /* Default value for the age interval */
    ln_info->age_interval = 1800;

    if(switch_api_default_vrf_internal() != 0) {
        ln_info->vrf_handle = switch_api_default_vrf_internal();
    }

    p4_ln_handle = switch_api_logical_network_create(hw_unit, ln_info);
    if (p4_ln_handle != SWITCH_API_INVALID_HANDLE) {
        //ln_node = malloc(sizeof(struct hmap_node));
        //hmap_insert(&all_logical_net_nodes, ln_node, hmap_int(vni,0));
        return p4_ln_handle;
    }

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
    VLOG_DBG("%s entered, route prefix %s", __func__,route_prefix);
    plen = get_prefix_len(route_prefix);
    HMAP_FOR_EACH_SAFE(tnl, next, hmap_t_node, &tunnel_hmap) {
            ipv4 =  htonl(tnl->remote_ip);
            ip_to_prefix(ipv4, plen, ip_prefix);
            VLOG_INFO("prefix %s vs route_prefix %s", ip_prefix,route_prefix);
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

int
p4_vport_bind_access_port(int hw_unit, p4_pbmp_t pbm, int vni, int vlan)
{
    switch_handle_t             access_handle = 0;
    switch_handle_t             vlan_handle = 0;
    switch_interface_type_t     type = 0;
    switch_vlan_t               vlan_id = 0;
    struct netdev               *netdev = NULL;
    int                         aport = 0;
    switch_status_t             status = -1;


    if(!VALID_TUNNEL_KEY(vni)) {
        VLOG_ERR("Invalid vni %d, ", vni);
        return EINVAL;
    }
    P4_PBMP_ITER (pbm, aport) {
        access_handle = p4_get_intf_handle_and_remove_vlan(aport);
        if (!P4_HANDLE_IS_VALID(access_handle)) {
            VLOG_DBG("Unable to get the access interface handle for interface %d", aport);
            continue;
        }

        status = switch_api_logical_network_member_add(hw_unit, p4_ln_handle, access_handle);
        if (status != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("Unable to add access interface %d member to logical network", aport);
            return 0;
        }
    }
    return 0;
}

int
p4_vport_unbind_access_port(int hw_unit, p4_pbmp_t pbm, int vni)
{
    /* This function will be added with Tunnel deletion part */
    return 0;
}


int
p4_vport_bind_all_ports_on_vlan(int vni, int vlan)
{
    p4_pbmp_t pbm;
    int ret;
    int unit;
    VLOG_DBG("%s bind all access ports for vni %d and vlan %d", __func__, vni, vlan);
    // bind all access ports on this vlan
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        P4_PBMP_CLEAR(pbm);
        ret = ops_vlan_get_cfg_access_ports_for_vlan(unit, vlan, &pbm);
        if (ret < 0) {
            VLOG_ERR("Failed to get access port bitmap for [VLAN:VNI] [%d:%d]",
                     vlan, vni);
            return ret;
        }
        ret = p4_vport_bind_access_port(unit, pbm, vni, vlan);
        if (ret < 0)
            return ret;

    }
    return 0;
}


int
p4_vport_unbind_all_ports_on_vlan(int vni, int vlan)
{
    /* This function will be added with Tunnel deletion part */
    return 0;
}


int p4_vport_bind_port_on_vlan(int vni, int vlan, struct port *port)
{
    struct iface *iface;
    int hw_unit = 0, hw_id;
    p4_pbmp_t pbmp;
    int rc;

    if (!port) {
        VLOG_ERR("Invalid port");
        return -1;
    }

    P4_PBMP_CLEAR(pbmp);
    LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
        VLOG_DBG("Bind interface %d on VLAN %d, tunnel %d",
                  iface->ofp_port, vlan, vni);
        netdev_sim_get_port_number(iface->netdev, &hw_id);
        P4_PBMP_PORT_ADD(pbmp, hw_id);
    }
    rc = p4_vport_bind_access_port(hw_unit, pbmp, vni, vlan);
    if (rc < 0) {
        VLOG_ERR("Failed to bind port %s on [VLAN: VNI] [%d: %d]",
                 port->name, vlan, vni);
    } else {
        VLOG_INFO("Successfully bound port %s on [VLAN: VNI] [%d: %d]",
                 port->name, vlan, vni);
    }
    return rc;
    return 0;
}


int p4_vport_unbind_port_on_vlan(int vni, int vlan, struct port *port)
{
    /* This function will be added with Tunnel deletion part */
    return 0;
}
