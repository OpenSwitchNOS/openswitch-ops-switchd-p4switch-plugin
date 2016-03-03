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
        self.addLink('h2', 's2')
        self.addLink('s1', 's2')
        self.addLink('s1', 's2')
        self.addLink('s1', 's2')

class EcmpStaticRouteTest(OpsVsiTest):

    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        topo = CustomTopo(hsts=2, sws=2, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(topo, switch=VsiOpenSwitch,
                       host=Host, link=OpsVsiLink,
                       controller=None, build=True)

    def config_check(self):

        s1 = self.net.switches[ 0 ]
        s2 = self.net.switches[ 1 ]
        h1 = self.net.hosts[ 0 ]
        h2 = self.net.hosts[ 1 ]

        info("###### configuration start ######")

        info("\n###### 30 second delay ######")
        time.sleep(30)

        # host 1 configuration
        info("\n###### configuring host 1 ######")
        h1.cmd("ip addr add 192.168.10.1/24 dev h1-eth0")
        h1.cmd("ip route add 192.168.0.0/16 via 192.168.10.2")

        # host 2 configuration
        info("\n###### configuring host 2 ######")
        h2.cmd("ip addr add 192.168.20.1/24 dev h2-eth0")
        h2.cmd("ip route add 192.168.0.0/16 via 192.168.20.2")

        ## switch 1 configuration
        info("\n###### configuring switch 1 ######")
        s1.cmdCLI("configure terminal")

        # interface 1 configuration
        s1.cmdCLI("interface 1")
        s1.cmdCLI("ip address 192.168.10.2/24")
        s1.cmdCLI("no shutdown")
        s1.cmdCLI("exit")

        # interface 2 configuration
        s1.cmdCLI("interface 2")
        s1.cmdCLI("ip address 192.168.30.1/24")
        s1.cmdCLI("no shutdown")
        s1.cmdCLI("exit")

        # interface 3 configuration
        s1.cmdCLI("interface 3")
        s1.cmdCLI("ip address 192.168.40.1/24")
        s1.cmdCLI("no shutdown")
        s1.cmdCLI("exit")

        # interface 4 configuration
        s1.cmdCLI("interface 4")
        s1.cmdCLI("ip address 192.168.50.1/24")
        s1.cmdCLI("no shutdown")
        s1.cmdCLI("exit")

        s1.cmdCLI("exit")

        ## switch 2 configuration
        info("\n###### configuring switch 2 ######")
        s2.cmdCLI("configure terminal")

        # interface 1 configuration
        s2.cmdCLI("interface 1")
        s2.cmdCLI("ip address 192.168.20.2/24")
        s2.cmdCLI("no shutdown")
        s2.cmdCLI("exit")

        # interface 2 configuration
        s2.cmdCLI("interface 2")
        s2.cmdCLI("ip address 192.168.30.2/24")
        s2.cmdCLI("no shutdown")
        s2.cmdCLI("exit")

        # interface 3 configuration
        s2.cmdCLI("interface 3")
        s2.cmdCLI("ip address 192.168.40.2/24")
        s2.cmdCLI("no shutdown")
        s2.cmdCLI("exit")

        # interface 4 configuration
        s2.cmdCLI("interface 4")
        s2.cmdCLI("ip address 192.168.50.2/24")
        s2.cmdCLI("no shutdown")
        s2.cmdCLI("exit")

        s2.cmdCLI("exit")

        info("\n###### configuration end ######")

    def test_ecmp_static_route(self):

        s1 = self.net.switches[ 0 ]
        s2 = self.net.switches[ 1 ]
        h1 = self.net.hosts[ 0 ]
        h2 = self.net.hosts[ 1 ]

        # ping h1 to h2
        info("\n\n### no route between h1 and h2. ping should fail")
        info('\n### Ping host1 from host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Fail: Ping Passed!\n\n')
        else:
            info('Success: Ping Failed!\n\n')

        # add a route on s1
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("ip route 192.168.20.0/24 192.168.30.2")
        s1.cmdCLI("exit")

        # add a route on s2
        s2.cmdCLI("configure terminal")
        s2.cmdCLI("ip route 192.168.10.0/24 192.168.30.1")
        s2.cmdCLI("exit")

        time.sleep(2)

        # ping h1 to h2
        info("\n### added 1 route between h1 and h2. ping should succeed")
        info('\n### Ping host1 from host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        # add one more route on s1 to make it ecmp
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("ip route 192.168.20.0/24 192.168.40.2")
        s1.cmdCLI("exit")

        # add one more route on s2 to make it ecmp
        s2.cmdCLI("configure terminal")
        s2.cmdCLI("ip route 192.168.10.0/24 192.168.40.1")
        s2.cmdCLI("exit")

        time.sleep(2)

        # ping h1 to h2
        info("\n### added 1 more route between h1 and h2. ping should succeed")
        info('\n### Ping host1 from host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')


        # add one more route on s1
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("ip route 192.168.20.0/24 192.168.50.2")
        s1.cmdCLI("exit")

        # add one more route on s2
        s2.cmdCLI("configure terminal")
        s2.cmdCLI("ip route 192.168.10.0/24 192.168.50.1")
        s2.cmdCLI("exit")

        time.sleep(2)

        # ping h1 to h2
        info("\n### added 1 more route between h1 and h2. ping should succeed")
        info('\n### Ping host1 from host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        # delete one route on s1. still ecmp
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("no ip route 192.168.20.0/24 192.168.30.2")
        s1.cmdCLI("exit")

        # delete one route on s2. still ecmp
        s2.cmdCLI("configure terminal")
        s2.cmdCLI("no ip route 192.168.10.0/24 192.168.30.1")
        s2.cmdCLI("exit")

        time.sleep(2)

        # ping h1 to h2
        info("\n### deleted 1 route between h1 and h2. ping should succeed")
        info('\n### Ping host1 from host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        # delete one more route on s1 to make it non-ecmp
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("no ip route 192.168.20.0/24 192.168.40.2")
        s1.cmdCLI("exit")

        # delete one more route on s2 to make it non-ecmp
        s2.cmdCLI("configure terminal")
        s2.cmdCLI("no ip route 192.168.10.0/24 192.168.40.1")
        s2.cmdCLI("exit")

        time.sleep(2)

        # ping h1 to h2
        info("\n### deleted 1 more route between h1 and h2. ping should succeed")
        info('\n### Ping host1 from host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Ping Failed!\n\n')

        # delete the final route on s1
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("no ip route 192.168.20.0/24 192.168.50.2")
        s1.cmdCLI("exit")

        # delete the final route on s2
        s2.cmdCLI("configure terminal")
        s2.cmdCLI("no ip route 192.168.10.0/24 192.168.50.1")
        s2.cmdCLI("exit")

        time.sleep(2)

        # ping h1 to h2
        info("\n### no route between h1 and h2. ping should fail")
        info('\n### Ping host1 from host2 ###\n')
        ret = h1.cmd("ping -c 1 192.168.20.1")
        status = parsePing(ret)
        # Return code means whether the test is successful
        if status:
            info('Ping Passed!\n\n')
        else:
            info('Success: Ping Failed!\n\n')

class Test_switchd_container_ecmp_static_route:

  def setup_class(cls):
    Test_switchd_container_ecmp_static_route.test = EcmpStaticRouteTest()

  def test_switchd_container_ecmp_static_route_config(self):
    self.test.config_check()

  def test_switchd_container_ecmp_static_route(self):
    self.test.test_ecmp_static_route()

  def teardown_class(cls):
    Test_switchd_container_ecmp_static_route.test.net.stop()

  def __del__(self):
    del self.test
