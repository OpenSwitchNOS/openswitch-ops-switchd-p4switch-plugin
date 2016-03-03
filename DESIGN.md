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

## References
-------------
* [OpenSwitch](http://www.openswitch.net/)
* [Open vSwitch](http://www.openvswitch.org/)
* [Docker](http://www.docker.com/)
* [Mininet](http://www.mininet.org/)
