#!/usr/bin/env python

# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
# (c) Copyright 2016 Barefoot Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import pytest
from opsvsi.docker import *
from opsvsi.opsvsitest import *
from opsvsiutils.systemutil import *

class CustomTopo(Topo):
    '''
        Topology
                                  [2]  <--->  [2]
        H1[h1-eth0] <---> [1] S1  [3]  <--->  [3] S2 <---> [h2-eth0] H2
                                  [4]  <--->  [4]
    '''

    def build(self, hsts=2, sws=2, **_opts):
        self.hsts = hsts
        self.sws = sws

        # Add list of hosts
        for h in irange(1, hsts):
            host = self.addHost( 'h%s' % h)

        # Add list of switches
        for s in irange(1, sws):
            switch = self.addSwitch( 's%s' %s)

        # Add links between nodes based on custom topo
        self.addLink('h1', 's1')
        self.addLink('h2', 's1')
        self.addLink('s1', 's2')
        self.addLink('h3', 's2')

'''

------
| h1 |  --------
------         | Link 1
             ------ Link 3          Link 1 ------  Link 2 ------
             | S1 |  --------------------- | S2 |  ------ | h3 |
             ------                        ------         ------
------         | Link 2
| h2 |  --------
------

h1 IP - 192.168.10.1
h2 IP - 192.168.10.2
h3 IP - 192,168.20.1

Vlan 10 on S1 - Link1(access), Link2(access), Link3(trunk)
Vlan 10 on S2 - Link1(access)
Vlan 20 on S2 - Link2(trunk)

S1 Vlan10 IP - 192.168.10.10
S2 Vlan10 IP - 192.168.10.11
S2 Vlan20 IP - 192.168.20.10

This testcase tests
- ping from h1 to h2 (switching)
- ping from h1 to s1 (glean on s1)
- ping from h1 to s2 (glean on s2)
- ping from h1 to h3 (vlan routing)
- ping from h3 to s1 (glean on s1)

'''

class L3ViRoutingTest(OpsVsiTest):

    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        topo = CustomTopo(hsts=3, sws=2, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(topo, switch=VsiOpenSwitch,
                       host=Host, link=OpsVsiLink,
                       controller=None, build=True)

    def configure_hostname(self, switch, hostname):
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("hostname %s" % hostname)
        switch.cmdCLI("end")

    def create_vlan(self, switch, vlan):
        info("\n###### Creating vlan ######\n")
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("vlan %d" %vlan)
        switch.cmdCLI("no shutdown")
        switch.cmdCLI("end")

    def configure_interface(self, switch, intf, mode, vlan):
        info("\n###### Configuring Interfaces ######\n")
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("interface %d" % intf)
        switch.cmdCLI("no routing")

        if mode == "access":
            switch.cmdCLI("vlan access %s" % vlan)
        elif mode == "trunk":
            switch.cmdCLI("vlan trunk allowed %d" % vlan)

        switch.cmdCLI("no shutdown")
        switch.cmdCLI("end")

    def configure_vlan_interface(self, switch, vlan, ip):
        info("\n###### Configuring Vlan Interfaces ######\n")
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("interface vlan %d" % vlan)
        switch.cmdCLI("routing")
        switch.cmdCLI("ip address %s" % ip)
        switch.cmdCLI("no shutdown")
        switch.cmdCLI("end")

    def configure_route(self, switch, route, nhop):
        info("\n###### Configuring Route ######\n")
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("ip route %s %s" % (route, nhop))
        switch.cmdCLI("end")

    def configure_check(self):

        s1 = self.net.switches[ 0 ]
        s2 = self.net.switches[ 1 ]
        h1 = self.net.hosts[ 0 ]
        h2 = self.net.hosts[ 1 ]
        h3 = self.net.hosts[ 2 ]

        info("###### configuration start ######")

        info("\n###### 30 second delay ######")
        time.sleep(10)

        # host 1 configuration
        info("\n###### configuring host 1 ######")
        h1.cmd("ip addr del 10.0.0.1/8 dev h1-eth0")
        h1.cmd("ip addr add 192.168.10.1/24 dev h1-eth0")
        h1.cmd("ip route add 192.168.0.0/16 via 192.168.10.10")

        # host 2 configuration
        info("\n###### configuring host 2 ######")
        h2.cmd("ip addr del 10.0.0.2/8 dev h2-eth0")
        h2.cmd("ip addr add 192.168.10.2/24 dev h2-eth0")
        h2.cmd("ip route add 192.168.0.0/16 via 192.168.10.10")

        # host 3 configuration
        info("\n###### configuring host 3 ######")
        h3.cmd("ip addr del 10.0.0.3/8 dev h3-eth0")
        h3.cmd("ip addr add 192.168.20.1/24 dev h3-eth0")
        h3.cmd("ip route add 192.168.0.0/16 via 192.168.20.10")

        ## switch 1 configuration
        info("\n###### configuring switch 1 ######")
        self.configure_hostname(s1, "s1")
        self.create_vlan(s1, 10)
        self.configure_interface(s1, 1, "access", 10)
        self.configure_interface(s1, 2, "access", 10)
        self.configure_interface(s1, 3, "trunk", 10)
        self.configure_vlan_interface(s1, 10, "192.168.10.10/24")
        self.configure_route(s1, "192.168.20.0/24", "192.168.10.11")

        ## switch 1 configuration
        info("\n###### configuring switch 2 ######")
        self.configure_hostname(s2, "s2")
        self.create_vlan(s2, 10)
        self.create_vlan(s2, 20)
        self.configure_interface(s2, 1, "trunk", 10)
        self.configure_interface(s2, 2, "access", 20)
        self.configure_vlan_interface(s2, 10, "192.168.10.11/24")
        self.configure_vlan_interface(s2, 20, "192.168.20.10/24")

        CLI(self.net)

        info("\n###### configuration end ######")

    def test_vi_routing(self):

        s1 = self.net.switches[ 0 ]
        s2 = self.net.switches[ 1 ]
        h1 = self.net.hosts[ 0 ]
        h2 = self.net.hosts[ 1 ]
        h3 = self.net.hosts[ 2 ]

        info('\n### Ping host1 to host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.10.2")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        info('\n### Ping host1 to switch1 ###\n')
        ret = h1.cmd("ping -c 1 192.168.10.10")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        info('\n### Ping host1 to switch2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.10.11")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        info('\n### Ping host1 to host3 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        info('\n### Ping host3 to switch1 ###\n')
        ret = h3.cmd("ping -c 1 192.168.10.10")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

class Test_switchd_container_l3_vi_routing:

  def setup_class(cls):
    Test_switchd_container_l3_vi_routing.test = L3ViRoutingTest()

  def test_switchd_container_l3_vi_routing_configure(self):
    self.test.configure_check()

  def test_switchd_container_l3_vi_routing_test(self):
    self.test.test_vi_routing()

  def teardown_class(cls):
    Test_switchd_container_l3_vi_routing.test.net.stop()

  def __del__(self):
    del self.test
