/*
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <openvswitch/vlog.h>
#include "ops-logical-switch.h"

VLOG_DEFINE_THIS_MODULE(ops_logical_switch);

/* Set logical switch */
int
ops_set_logical_switch(const struct ofproto *ofproto_,  void *aux,
                   enum logical_switch_action action,
                   struct logical_switch_node *log_switch)
{
    int hw_unit = 0;
    int rc = 0;
    VLOG_INFO(" [%s, %d] action:%d name:%s key:%d hw_unit:%d\n",
             __FUNCTION__, __LINE__,
             action, log_switch->name, log_switch->tunnel_key,
             hw_unit);

    switch (action) {
    case LSWITCH_ACTION_ADD:
        rc = ops_vport_lsw_create(0, log_switch->tunnel_key);
        VLOG_INFO("%s: Logical Network for HW Unit %d and VNI: 0x%x is %lx",
                        __func__, hw_unit, log_switch->tunnel_key, rc);
        break;
    case LSWITCH_ACTION_DEL:
		/* TO be added as a part of tunnel deletion code*/
        break;
    case LSWITCH_ACTION_MOD:
		/* TO be added as a part of tunnel modification code*/
    default:
        VLOG_ERR("Error [%s, %d] action:%d name:%s key:%d hw_unit:%d\n",
                 __FUNCTION__, __LINE__,
                 action, log_switch->name, log_switch->tunnel_key,
                 hw_unit);
        return 1;
    }

    return 0;
}
