/*
* (c) Copyright 2016 Hewlett Packard Enterprise  Development LP
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may
* not use this file except in compliance with the License. You may obtain
* a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
* License for the specific language governing permissions and limitations
* under the License.
*
* File: ops-logical-switch.h
*
* Purpose: This file provides public definitions for logical switch API.
*/

#ifndef __OPS_LOGICAL_SWITCH_H__
#define __OPS_LOGICAL_SWITCH_H__ 1

#include "log-switch-asic-provider.h"

extern int ops_set_logical_switch(const struct ofproto *ofproto, void *aux,
            enum logical_switch_action action,
            struct logical_switch_node *log_switch);

#endif /* __OPS_LOGICAL_SWITCH_H__ */
