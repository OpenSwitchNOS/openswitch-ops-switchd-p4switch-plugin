# High level design of ops-switchd-p4switch-plugin (OpenSwitch P4 simulation)


## Contents

- [Description](#description)
- [Responsibilities](#responsibilities)
- [Design choices](#design-choices)
- [Relationship between OpenSwitch and P4 data-plane simulator](#relationship-between-openswitch-and-p4-dataplane-simulator)
- [Internal structure](#internal-structure)
- [netdev simulation provider](#netdev-simulation-provider)
- [ofproto simulation provider](#ofproto-simulation-provider)
- [ofproto simulation provider plugin](#ofproto-simulation-provider-plugin)
- [SwtichApi](#swtichapi)
- [PD_Api](#pd_api)
- [ACL](#acl)
    - [Plugin Interfaces](#plugin-interfaces)
        - [Apply](#apply)
        - [Remove](#remove)
        - [Replace](#replace)
        - [List Update](#list-update)
        - [Get Statistics](#get-statistics)
        - [Clear Statististics](#clear-statistics)
        - [Clear All Statististics](#clear-all-statistics)
        - [Log Packet Callback](#log-packet-callback)
- [References](#references)

## Description

The OpenSwitch P4 simulation enables component and feature test in a pure software simulation environment without a need for any physical network setup.

This plugin provides a P4 defined data processing pipeline and APIs to control/configure that pipeline.
As the pipeline is written in P4, the pipeline itself can be modified to add more dataplane features.
This provides a powerful innovation and development platform for implementing new ideas and features in the
data-plane of a networking device.

Target users include developers, testers and continuous integration systems. The simulation is especially useful, when dealing with protocol daemons, configuration interfaces, system components and other key portions of the code. The simulation is of little benefit for testing components, such as an actual data plane or platform devices (fans, LEDs and sensors). Hence, it does not simulate any of these aspects of the product.

OpenSwitch controls and programs the forwarding plane device ("ASIC") by using an ofproto provider class to manage L2 and L3 features, as well as a netdev class to manage physical interfaces. The class functions are invoked by the bridge software, and they abstract the forwarding device implementation.

In the case of simulation, the forwarding device is a P4 simulator executing a P4 programn, which acts as a forwarding "P4-ASIC". The simulation provider programs the target P4 switch by using a set of APIs called switchapi.

The simulation environment consists of a Docker namespace framework running Mininet. Yocto build systems create a Docker image target that extends a Mininet-like environment. Mininet allows the instantiation of switches and hosts. It also supports the connection setup between any host/switch port to any host/switch port. The Docker/Mininet environment is very scalable, and it allows the simultaneous testing of complex topologies in a virtual environment.

## Responsibilities

The simulation provider implements control path class functions to manage the simulated "P4-ASIC". It also programs IP tables to provide L3 interface support by the Linux kernel.

## Design choices

The design selected a P4 simulator with switch.p4 as a forwarding plane as it provides following benefits -
- It is a open-source software available from P4Lang
- Switch.p4 is a feature-rich P4 defined pipeline
- P4 allows to add/modify data-plane features as openSwitch features evolve
- It provides a reference implementation for future P4 programmable devices

The Docker/Mininet framework was selected because the virtual machine based simulation proved too difficult to deploy and manage. Docker provides a lightweight scalable virtualization, which is critical to regression testing and continuous
integration. Mininet provides a simple and powerful framework to develop networking tests using Python scripts which execute either in simulation or on real hardware.

## Relationship between OpenSwitch and P4 dataplane simulator

```ditaa
+---------------------------------------------------------------------------+
|                       OpenSwitch namespace (swns)                         |
|                                                                           |
|+-------------------------------------------------------------------------+|
||                                                                         ||
||                         OVSDB-Server                                    ||
||                                                                         ||
|+-------------------------------------------------------------------------+|
|     ^                       ^                      ^             ^        |
|     |                       |                      |             |        |
|     V                       V                      V             V        |
|+------------+  +-----------------------------+  +---------+  +-----------+|
||Mgmt Daemons|  | ops-switchd-p4switch-plugin |  | System  |  |   L2/L3   ||
||CLI, Rest,  |  |                             |  | Daemons |  |  Daemons  ||
||WebUI       |  |                             |  |         |  |           ||
|+------------+  +-----------------------------+  +---------+  +-----------+|
|                |                             |                            |
|                |                             |              Interfaces    |
|                | Simulation ofproto/netdev   |                1 - N       |
|                |  Providers (This Module)    |              | | | | |     |
|                |                             +-----><-----+-----------+   |
|                +-----------------------------+                        |   |
|                |         SwitchApi           |              Interface |   |
|                +-----------------------------+              Mux-Demux |   |
|                |           PD_Api            |                        |   |
|                +-----------------------------+-----><-----+-----------+   |
|                               ^                                 ^         |
|                               |                                 |         |
+---------------------------------------------------------------------------+
                                |                                 |
                    Control IPC |                                 | HostIf (veth)
+---------------------------------------------------------------------------+
| Emulation NameSpace (emulns)  |                                 |         |
|                               V                                 V         |
|   +------------+    +------------------------------------------------+    |
|   | Compiled   |    |                                                |    |
|   | P4 program |<-->|          P4 Simulator                          |    |
|   |            |    |                                                |    |
|   +------------+    +------------------------------------------------+    |
|                                                          | | | | |        |
+---------------------------------------------------------------------------+
                                                           | | | | |
                                                           | | | | |
                                                           Front Panel
                                                            Interfaces
                                                              1 - N
```

## Internal structure

### netdev simulation provider

Netdev is an interface (i.e. physical port) class that consists of data structures and interface functions. Netdev simulation class manages a set of Linux interfaces that emulate switch data path interfaces. The bridge (`bridge.c`) instantiates the class by mapping a generic set of netdev functions to netdev simulation functions. `vswitchd`, will then, manage switch interfaces by invoking these class functions. Netdev configures Linux kernel interfaces by constructing CLI commands and invoking system(cmd) to execute these commands. It also maintains local state for supporting class functions.


### ofproto simulation provider
-------------------------------

`Ofproto` is a port (i.e. logical port) class which consists of data structures and port interface functions. The simulation provider supports L2 and L3 interfaces. The simulation provider works in conjunction with protocol daemons to provide control path support for VLAN, LAG, LACP and Inter-VLAN routing. Additional protocols including VXLAN, QOS, ACLs, security well as open flow will be added in the future. All process communications between protocol daemons, UI and the simulation class is done via OVSDB. Configuration requests are triggered by switchd invoking class functions.

`bridge.c` instantiates the class by mapping a generic set of ofproto provider functions to ofproto simulation functions. `vswitchd`, will then, manage switch ports by invoking these class functions.

The simulation provider programs the "P4-ASIC" target by using appropriate switchapi functions. It also tracks state for its managed objects and handles provided by underlying switchapi to allow additions, modifications and deletions.

#### ofproto simulation provider plugin
---------------------------------------

The `ofproto` class functions are loaded dynamically via a plugin. It allows flexibility in terms of which API to package as well as avoids licensing issues caused by shipping proprietary APIs. The class functions load before `ofproto` invokes any of the class functions. The plugin key function is `ofproto_register()` that maps `ofproto_sim_provider_class`.

### SwtichApi
-------------

The SwitchApi is a collection of APIs that abstract P4 table details, entry management to provide a higher level programming interface. E.g. A given action, such as adding port to a VLAN, may require update to multiple P4 tables. Also if changes are made to P4 program, it will change the set of table updates required for the same operation. The switchapi provides a stable interface by hiding internal P4 program details and also insulates the upper level programs from any changes in P4 program.

### PD_Api
----------

The PD (Program Dependent) API are set of library functions that are generated by the P4 compiler. These functions are generated to configure and update various P4 tables defined in the P4 program for the pipeline.
SwitchApi uses these functions to access P4 objects in the underlaying P4 target.
## ACL
An Access Control List (ACL) is a sequential list of statements, Access
Control Entries (ACEs), comprised of match attributes and actions.  A packet is
matched sequentially against the entries in the ACL. When a match is made the
action of that entry is taken (permit or deny, log, count) and no more
comparisons are made.

Initially, P4 platform will support the following:
- IPv4/IPv6 ACLs applied on ingress/egress direction to L2 and L3 ports.
- IPv4/IPv6 ACLs applied on ingress/egress direction to L2 and L3 LAGs
- per ACE hit count statistics
- ACL logging

P4 platform will not support the following:
- Match on "eq" operationg for transport layer port range
- Match on "neq", "gt" and "lt" operations

### Plugin Interfaces
For supporting ACL feature switchd invokes defined API interfaces. Plugin registers for these callbacks in ops_cls_plugin_interface.

### Apply
The "ofproto_ops_cls_apply" API is called to apply an ACL on a port for the first time. We get the list of ACE entries in the ACL which are applied to the port in ASIC. The handles to ACL and ACE entry resources are stored locally in an ACL hashmap.

### Remove
The "ofproto_ops_cls_remove" API is called to remove an ACL from a port on which it was applied. In the remove callback we remove the ACL's reference to the port and decrement the port reference count. If the port reference count is zero, destroy the ACL since its not applied on any ports.

### Replace
The "ofproto_ops_cls_replace" API is called to replace an applied ACL on a port. In this callback we remove original ACLs reference to the port, decrement the reference count, and if reference count is 0, destroy the original ACL.  Finally, we apply the new ACL on the port. If the ACL does not already exist in hardware, we create the ACL and then apply it on the port.

### List Update
The "ofproto_ops_cls_list_update" API is invoked to modify the list of ACE entries of an ACL. The API passes the updated list of ACE entries. In the callback, we delete the original list and then add the new list to the ACL. 
Note: The preferred behaviour would have been to add the new list and then delete the original list to avoid any leakage. However, due to limitations in P4 sofware model which does not allow installation of duplicate TCAM entries, we use the approach to avoid complexities. P4 supports duplicate TCAM entries in real hardware, where this design can be modified.

### Get Statistics
TBD

### Clear Statistics
TBD

### Clear All Statistics
TDB

### Log Packet Callback

TDB 

## References
-------------
* [OpenSwitch](http://www.openswitch.net/)
* [Open vSwitch](http://www.openvswitch.org/)
* [Docker](http://www.docker.com/)
* [Mininet](http://www.mininet.org/)
