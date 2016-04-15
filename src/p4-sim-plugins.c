/*
 *  Copyright (C) 2016 Barefoot Networks Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain
 *  a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */

#include <unistd.h>
#include "openvswitch/vlog.h"
#include "netdev-provider.h"
#include "ofproto/ofproto-provider.h"
#include "netdev-p4-sim.h"
#include "ofproto-p4-sim-provider.h"
#include "p4-switch.h"

#define init libovs_p4_sim_plugin_LTX_init
#define run libovs_p4_sim_plugin_LTX_run
#define wait libovs_p4_sim_plugin_LTX_wait
#define destroy libovs_p4_sim_plugin_LTX_destroy
#define netdev_register libovs_p4_sim_plugin_LTX_netdev_register
#define ofproto_register libovs_p4_sim_plugin_LTX_ofproto_register

#define MAX_CMD_LEN             50

VLOG_DEFINE_THIS_MODULE(P4_sim_plugin);

extern void p4_ofproto_init(void);

void
init(void)
{
    p4_switch_init();
}

void
run(void)
{
}

void
wait(void)
{
}

void
destroy(void)
{
}

void
netdev_register(void)
{
    netdev_sim_register();
}

void
ofproto_register(void)
{
    ofproto_class_register(&ofproto_sim_provider_class);
    p4_ofproto_init();
}
