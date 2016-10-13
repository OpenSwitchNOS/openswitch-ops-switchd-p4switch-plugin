#ifndef __P4_VPORT_H__
#define __P4_VPORT_H__ 1

int   ops_vport_bind_all_ports_on_vlan(int vni, int vlan);
int   ops_vport_unbind_all_ports_on_vlan(int vni, int vlan);
int   ops_vport_bind_port_on_vlan(int vni, int vlan, struct port *port);
int   ops_vport_unbind_port_on_vlan(int vni, int vlan, struct port *port);

#endif /* __P4_VPORT_H__ */
