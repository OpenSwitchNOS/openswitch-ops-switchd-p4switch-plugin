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

import os
import time
from opsvsi.docker import *
from opsvsi.opsvsitest import *
import pdb

class CustomTopology( Topo ):

    def build(self, hsts=2, sws=1, **_opts):
        '''Function to build the custom topology of two hosts and two switches'''
        self.hsts = hsts
        self.sws = sws
        #Add list of hosts
        for h in irange( 1, hsts):
            host = self.addHost('h%s' % h, ip = '172.17.0.%d/24' % (10 + h))

        #Add list of switches
        for s in irange(1, sws):
            switch = self.addSwitch('s%s' % s)

        #Add links between nodes based on custom topology
        for i in irange(1, sws):
            hostname = "h%s" % i
            swname = "s%s" % i
            self.addLink(hostname, swname, port1 = 1, port2 = 1)
            hostname = "h%s" % (i + 2)
            self.addLink(hostname, swname, port1 = 1, port2 = 2)

        #Connect the switches
        self.addLink("s1", "s2", port1 = 3, port2 = 3)
        self.addLink("s1", "s2", port1 = 4, port2 = 4)
        self.addLink("s1", "s2", port1 = 5, port2 = 5)

class twoSwitchTest( OpsVsiTest ):

  # Topology
  # 4 hosts, 2 switches
  # 1, 3 hosts connected to s1
  # 2, 4 hosts connected to s2
  # s1 is connected s2
  def setupNet(self):
    self.net = Mininet(topo=CustomTopology(hsts=4, sws=2,
                                           hopts=self.getHostOpts(),
                                           sopts=self.getSwitchOpts()),
                                           switch=VsiOpenSwitch,
                                           host=Host,
                                           link=OpsVsiLink, controller=None,
                                           build=True)

  # show running config on the switches
  def show_running_config(self):
      info("\n###### Show Running Config #####\n")
      for switch in self.net.switches:
          if isinstance(switch, VsiOpenSwitch):
              info("\n###### Switch %s ######\n" % switch.name)
              runconf = switch.cmdCLI("show running-config")
              info(runconf + "\n")

  # vlan add method
  def vlan_add(self, vlan = 10):
      info("\n###### Configuring Vlan ######\n")
      for switch in self.net.switches:
          if isinstance(switch, VsiOpenSwitch):
              switch.cmdCLI("configure terminal")
              switch.cmdCLI("vlan %s" % vlan)
              switch.cmdCLI("no shutdown")
              switch.cmdCLI("end")

  # configure access or trunk interfaces
  def config_interface(self, sw, intf, mode, vlan, allowed_vlan="", state=""):
    info("\n###### Configuring Interfaces ######\n")
    switch = self.net.getNodeByName(sw)
    if isinstance(switch, VsiOpenSwitch):
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("interface %d" % intf)
        switch.cmdCLI("no routing")
        if mode == "access":
            switch.cmdCLI("vlan access %s" % vlan)
        elif mode == "trunk":
            if vlan:
                switch.cmdCLI("vlan trunk native %s" % vlan)
            if allowed_vlan:
              switch.cmdCLI("vlan trunk allowed %s" % allowed_vlan)
        if state:
            switch.cmdCLI(state)
        else:
            switch.cmdCLI("no shutdown")
        switch.cmdCLI("end")

  # unconfigure interfaces
  def unconfigure_interface(self, sw, intf, mode, vlan, allowed_vlan=""):
    info("\n##### Unconfigure Interface Config #####\n")
    #pdb.set_trace()
    switch = self.net.getNodeByName(sw)
    if isinstance(switch, VsiOpenSwitch):
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("interface %d" % intf)
        if mode == "access":
            switch.cmdCLI("no vlan access %s" % vlan)
        elif mode == "trunk":
            if vlan:
                switch.cmdCLI("no vlan trunk native %s" % vlan)
            if allowed_vlan:
              switch.cmdCLI("no vlan trunk allowed %s" % allowed_vlan)
        switch.cmdCLI("shutdown")
        switch.cmdCLI("end")

  # ping the hosts
  def mininet_ping_hosts(self):
    info("\n###### Ping Hosts #####\n")
    info("Sleep for 20 seconds for system to be up\n")
    time.sleep(20)
    hosts = self.net.hosts
    result = self.net.ping(hosts,30)
    info("### Result "+str(result))
    return int(result)

  # add link between switches
  def add_switch_link(self, sw1, sw2, port1, port2):
    self.net.addLink(sw1, sw2, port1 = port1, port2 = port2)

  # configure lag interface
  def config_lag_interface(self, sw, lag_intf, mode, vlan,\
                           mem_intf_list, allowed_vlan=""):
    info("\n####### Configuring Lag Interface #######\n")
    # pdb.set_trace()
    switch = self.net.getNodeByName(sw)
    if isinstance(switch, VsiOpenSwitch):
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("interface lag %d" % lag_intf)
        switch.cmdCLI("no routing")
        if mode == "access":
            switch.cmdCLI("vlan access %s" % vlan)
        elif mode == "trunk":
            if vlan:
                switch.cmdCLI("vlan trunk native %s" % vlan)
            if allowed_vlan:
                switch.cmdCLI("vlan trunk allowed %s" % allowed_vlan)
        switch.cmdCLI("no shutdown")
        switch.cmdCLI("exit")
        info("\n##### Configuring Lag Members ######\n")
        for intf in mem_intf_list:
            info("\n##### intf %s #####\n" % intf)
            switch.cmdCLI("interface %d" % intf)
            switch.cmdCLI("lag %d" % lag_intf)
            switch.cmdCLI("no shutdown")
            switch.cmdCLI("exit")
        switch.cmdCLI("end")

  def mininet_cli(self):
    CLI(self.net)

class Test_dual_switch_test:

  def setup_class(self):
    # Create the Mininet topology based on mininet.
    info("##### Create Topology #####\n")
    Test_dual_switch_test.test = twoSwitchTest()
    #pdb.set_trace()
    time.sleep(10)

  def test_vlan_add(self):
    info("##### Configure Vlan #####\n")
    self.test.vlan_add(vlan=500)

  def test_config_interface(self):
    info("##### Configure S1 Host Interfaces #####\n")
    self.test.config_interface(sw="s1",intf=1,mode="access",vlan=500)
    self.test.config_interface(sw="s1",intf=2,mode="trunk",vlan=500)
    info("##### Configure S1 Switch Interfaces - Trunk Mode #####\n")
    self.test.config_interface(sw="s1",intf=3,mode="trunk",vlan=500,
                               allowed_vlan=500)

    info("##### Configure S2 Host Interfaces #####\n")
    self.test.config_interface(sw="s2",intf=1,mode="access",vlan=500)
    self.test.config_interface(sw="s2",intf=2,mode="trunk",vlan=500,
                               allowed_vlan=500)
    info("##### Configure S2 Switch Interfaces - Trunk Mode #####\n")
    self.test.config_interface(sw="s2",intf=3,mode="trunk",vlan=500,
                               allowed_vlan=500)
    time.sleep(10)

  def test_show_run_1(self):
    self.test.show_running_config()

  '''
  def test_mininet_cli(self):
    self.test.mininet_cli()
  '''

  def test_mininet_ping_hosts_trunk(self):
    info("\n##### Ping Hosts, Switch Trunk #####\n")
    ret = self.test.mininet_ping_hosts()
    #print "Return = ", int(ret)
    assert(ret == 0)

  def test_unconfigure_interface(self):
    info("\n##### Unconfigure Switch Interfaces - Trunk Mode #####\n")
    self.test.unconfigure_interface(sw="s1",intf=3,mode="trunk",vlan=500,allowed_vlan=500)
    self.test.unconfigure_interface(sw="s2",intf=3,mode="trunk",vlan=500,
                                    allowed_vlan=500)

  def test_config_lag_interface(self):
    info("##### Configure Lag Interface - Trunk Mode #####\n")
    self.test.config_lag_interface(sw="s1", lag_intf=10,\
                                   mode="trunk", vlan="500",\
                                   mem_intf_list=[3, 4, 5],\
                                   allowed_vlan=500)
    self.test.config_lag_interface(sw="s2", lag_intf=10,\
                                   mode="trunk", vlan="500",\
                                   mem_intf_list=[3, 4, 5],\
                                   allowed_vlan=500)

  def test_show_run_2(self):
    time.sleep(10)
    self.test.show_running_config()

  def test_mininet_ping_hosts_lag(self):
    info("\n##### Ping Hosts, Switch Lag Group  #####\n")
    ret = self.test.mininet_ping_hosts()
    #print "\nReturn = ", int(ret)
    assert(ret == 0)
    #self.test.mininet_cli()


  def teardown_class(cls):
    # Stop the Docker containers, and
    # mininet topology
    Test_dual_switch_test.test.net.stop()

  def __del__(self):
    del self.test
