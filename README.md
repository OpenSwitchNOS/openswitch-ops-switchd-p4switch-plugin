OPS-SWITCHD-P4SWITCH-PLUGIN
============================

What is ops-switchd-p4switch-plugin ?
--------------------------------------
ops-switchd-p4switch-plugin is part of the P4 virtual switch based test
infrastructure of OpenSwitch.

This plugin provides a packet processing pipeline defined using P4 language 
and associated APIs (called switchapi) for run-time programming to the pipeline.
The P4 program and APIs are taken from open source software at github.com/p4lang/switch.git

The OpenSwitch simulation enables component and feature test in a pure software
simulation environment without a need for a physical network.
OpenSwitch controls and programs the forwarding plane device ("ASIC")
by using an ofproto provider class to manage L2 and L3 features, as well as a
netdev class to manage physical interfaces. The class functions are invoked
by the bridge software, and they abstract the forwarding device implementation.

This plugin provides the glue logic to connect netdev and ofproto class functions to
underlying switchapi functions to program the P4 pipeline.

How to build and run P4 plugin?
-------------------------------
The P4 plugin is activated adding the following line in <workspace>/build/conf/local.conf
EXTRA_IMAGE_FEATURES = "ops-p4"  (use += if other image features are defined)
Steps -
* clone new ops-build repo
* cd <ops-build>
* make configure genericx86-64
* make header
* echo "EXTRA_IMAGE_FEATURES += \"ops-p4\"" >> build/conf/local.conf
* make clean
* make
* make export_docker_image

The above steps build a container image with P4 simulator and P4 plugin as part of it.
All the tests can be run against it as well as the container can be used in any mininet
topologies.

Injecting ports to P4 simulator
-------------------------------
Once network interfaces which model front panel ports have been created
(typically veth pairs with one end present in "emulns" namespace and the other
end either bridged to physical NIC or connected to mininet hosts), they should
be injected into P4 simulator. Execute following command from switch bash shell.
This step is not required while running tests via frameworks like VSI, Modular
Framework which internally take care of this requirement.

```
/sbin/ip netns exec emulns /sbin/ip link set <interface name> up
/sbin/ip netns exec emulns echo port add <interface name> <port number> | /sbin/ip netns exec emulns /usr/bin/bm_tools/runtime_CLI.py --json /usr/share/ovs_p4_plugin/switch_bmv2.json --thrift-port 10001
```

Note that port numbering for P4 simulator starts from zero. Currently P4 simulator
supports a total of 48 ports.

What is the structure of the repository?
----------------------------------------
* `src` - contains c source files that provide netdev and ofproto class implementations and glue logic.
* `include` - contains c header files.
* `switch` - This is a git submodule that points to 'ops' branch of github.com/p4lang/switch.git
* `switch/p4src` - This contains P4 programs that define the pipeline
* `switch/switchapi` - This contains APIs to control and configure the P4 pipeline


What is the license?
--------------------
Apache 2.0 license. For more details refer to [COPYING](http://git.openswitch.net/cgit/openswitch/ops-switchd-p4switch-plugin/tree/COPYING)


How to make changes to P4 pipeline?
-----------------------------------
To make changes to the P4 pipeline and switchapi -
* Checkout the ops-switchd-p4switch-plugin in your workspace
* Make changes to P4 pipeline and switchapi inside switch submodule directory
* Test your changes
* Create a fork of the switch.git repository
* Create a work branch
* Push your tested changes to the work branch
* Create pull request for mainters to accept you changes
* Update the submodule refpoint in the ops-switchd-p4switch-plugin repository
* Generate gerrit review request for updating the refpoint

What other documents are available?
-----------------------------------
For the high level design of ops-switchd-p4plugin-plugin, refer to [DESIGN.md](http://www.openswitch.net/documents/dev/ops-switchd-p4plugin-plugin/tree/DESIGN.md)
For the current list of contributors and maintainers, refer to [AUTHORS.md](http://git.openswitch.net/cgit/openswitch/ops-switchd-p4plugin-plugin/tree/AUTHORS)

For general information about OpenSwitch project refer to http://www.openswitch.net.


Supported Features:
-------------------
The switch.p4 is a feature-rich implementation of a packet processing pipeline.
Only a subset of those features is exposed in the openswitch environment at this time.
Following features are avaialable in open-switch enviroment.

Layer2 features:
- Layer 2 access and trunk ports
- VLANs
- L2 switching, per-VLAN flooding
- L2 LAG interfaces
- LACP
- LLDP
- MAC learning and aging within the plugin

L3 features:
- L3 interfaces
- L3 LAG interfaces
- L3 unicast static and dynamic routing (default VRF)
- ECMP support
- VLAN interface
- Sub-interfaces

TODO List:
----------
This is a list of things that belong to supported features, but not done yet.
Look for XXX or TODO comments in the code for detail information.
- LAG hash key selection
- ECMP hash key selection
- Expose learnt MACs to upport layers
- Support native-tagged modes on a trunk port, currently only native-untagged is supported
- Make-before-brake logic should be used when converting a single port to LAG
