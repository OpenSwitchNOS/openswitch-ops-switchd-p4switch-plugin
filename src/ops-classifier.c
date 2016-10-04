/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <util.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <openvswitch/vlog.h>
#include <ofproto/ofproto.h>
#include <ovs/list.h>

#include <ofproto/ofproto-provider.h>
#include <openvswitch/types.h>
#include <openvswitch/vlog.h>
#include <uuid.h>

#include "netdev-p4-sim.h"
/* P4 provider */
#include "ofproto-p4-sim-provider.h"
#include "ops-cls-asic-plugin.h"
#include "plugin-extensions.h"
#include "seq.h"
#include "ops-classifier.h"

/* Private header for ACL data structure */
#include "ops-classifier-private.h"

#define ACL_LOGGING_MIN_MS_BETWEEN_PKTS 1000 /**< ignore ACL logging packets
                                               received within this many ms of
                                               the previous packet */

/** Define a module for VLOG_ functionality */
VLOG_DEFINE_THIS_MODULE(ops_classifier);

/* hash map to store ACL */
struct hmap classifier_map;

/**
 * Function pointer to handle ACL logging packet data set functionality.
 * A callback is registered from PI at the init time to this function.
 * PD code needs to call this function when logging ACL packets.
 */
void (*acl_pd_log_pkt_data_set)(struct acl_log_info *);

/**************************************************************************//**
 * OPS_CLS plugin interface definition. This is the instance containing all
 * implementations of ops_cls plugin on this platform.
 *****************************************************************************/
static struct ops_cls_plugin_interface ops_cls_plugin = {
    ops_cls_p4_apply,
    ops_cls_p4_remove,
    NULL,  /* LAG:TBD */
    ops_cls_p4_replace,
    ops_cls_p4_list_update,
    ops_cls_p4_statistics_get,
    ops_cls_p4_statistics_clear,
    ops_cls_p4_statistics_clear_all,
    ops_cls_p4_acl_log_pkt_register_cb
};

/**************************************************************************//**
 * Ofproto plugin extension for OPS_CLS plugin. Holds the name, version and
 * plugin interface information.
 *****************************************************************************/
static struct plugin_extension_interface ops_cls_extension = {
    OPS_CLS_ASIC_PLUGIN_INTERFACE_NAME,
    OPS_CLS_ASIC_PLUGIN_INTERFACE_MAJOR,
    OPS_CLS_ASIC_PLUGIN_INTERFACE_MINOR,
    (void *)&ops_cls_plugin
};

/*
 * Init function (IFP initialization)
 */
int
ops_classifier_init()
{
    /* Initialize the classifier hash map */
    hmap_init(&classifier_map);

    return OPS_CLS_OK;
}

/*
 * Classifier lookup in hash table
 */
static struct ops_classifier*
ops_cls_lookup(const struct uuid *cls_id)
{
    struct ops_classifier *cls = NULL;

    uint32_t id = uuid_hash(cls_id);

    HMAP_FOR_EACH_WITH_HASH(cls, node, id, &classifier_map) {
        if (uuid_equals(&cls->id, cls_id)) {
            return cls;
        }
    }
    return NULL;
}

/*
 * Copy classifier rule entries and store in list
 */
static void
ops_cls_populate_entries(struct ops_classifier  *cls,
                         struct ovs_list        *list,
                         struct ops_cls_list    *clist)
{
    for (int i = 0; i < clist->num_entries; i++) {
        struct ops_cls_entry *entry =
            xzalloc(sizeof(struct ops_cls_entry));
        struct ops_cls_list_entry *cls_entry = &clist->entries[i];

        memcpy(&entry->entry_fields, &cls_entry->entry_fields,
               sizeof(struct ops_cls_list_entry_match_fields));
        memcpy(&entry->entry_actions, &cls_entry->entry_actions,
                sizeof(struct ops_cls_list_entry_actions));

        list_push_back(list, &entry->node);
    }
}

/*
 * Clean up classifier rule entries
 */
static void
ops_cls_cleanup_entries(struct ovs_list *list)
{
    struct ops_cls_entry *entry = NULL, *next_entry;

    LIST_FOR_EACH_SAFE (entry, next_entry,  node, list) {
        list_remove(&entry->node);
        free(entry);
    }
}

/*
 * Initialize orig list
 */
static void
ops_cls_init_orig_list(struct ops_cls_hw_info *hw_cls)
{
    list_init(&hw_cls->rule_index_list);
    list_init(&hw_cls->stats_index_list);
    list_init(&hw_cls->range_index_list);
}

/*
 * Initialize update list
 */
static void
ops_cls_init_update_list(struct ops_cls_hw_info *hw_cls)
{
    list_init(&hw_cls->rule_index_update_list);
    list_init(&hw_cls->stats_index_update_list);
    list_init(&hw_cls->range_index_update_list);
}

/*
 * Initialize list for port, routed,  clasiifier
 */
static void
ops_cls_init_hw_info(struct ops_cls_hw_info *hw_cls)
{
    hw_cls->in_asic = false;

    ops_cls_init_orig_list(hw_cls);
    ops_cls_init_update_list(hw_cls);
}

/*
 * Add classifier in hash (key uuid)
 */
static struct ops_classifier*
ops_cls_add(struct ops_cls_list  *clist)
{
    struct ops_classifier *cls;

    if (!clist) {
        return NULL;
    }

    cls = xzalloc(sizeof(struct ops_classifier));

    cls->id = clist->list_id;
    cls->name = xstrdup(clist->list_name);
    cls->type = clist->list_type;

    list_init(&cls->cls_entry_list);
    list_init(&cls->cls_entry_update_list);

    /* Init classifer hardware list entry list */
    ops_cls_init_hw_info(&cls->port_cls);
    ops_cls_init_hw_info(&cls->route_cls);

    if (clist->num_entries > 0) {
        VLOG_DBG("%s has %d rule entries", cls->name, clist->num_entries);
        ops_cls_populate_entries(cls, &cls->cls_entry_list, clist);
    }

    hmap_insert(&classifier_map, &cls->node, uuid_hash(&clist->list_id));

    VLOG_DBG("Added classifer %s in hashmap", cls->name);
    return cls;
}

/*
 * Delete classifier rule entries
 */
static void
ops_cls_delete_rule_entries(struct ovs_list *list)
{
    struct ops_cls_rule_entry *entry, *next_entry;

    LIST_FOR_EACH_SAFE (entry, next_entry,  node, list) {
        list_remove(&entry->node);
        free(entry);
    }
}

/*
 * Delete stats entries
 */
static void
ops_cls_delete_stats_entries(struct ovs_list *list)
{
    struct ops_cls_stats_entry *sentry = NULL, *next_sentry;

    LIST_FOR_EACH_SAFE (sentry, next_sentry,  node, list) {
        list_remove(&sentry->node);
        free(sentry);
    }
}

/*
 * Delete range entries
 */
static void
ops_cls_delete_range_entries(struct ovs_list *list)
{
    struct ops_cls_range_entry *rentry = NULL, *next_rentry;

    LIST_FOR_EACH_SAFE (rentry, next_rentry,  node, list) {
        list_remove(&rentry->node);
        free(rentry);
    }
}

/*
 * Delete original entires of classifier
 */
static void
ops_cls_delete_orig_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_rule_entries(&cls->port_cls.rule_index_list);
    ops_cls_delete_stats_entries(&cls->port_cls.stats_index_list);
    ops_cls_delete_range_entries(&cls->port_cls.range_index_list);

    ops_cls_delete_rule_entries(&cls->route_cls.rule_index_list);
    ops_cls_delete_stats_entries(&cls->route_cls.stats_index_list);
    ops_cls_delete_range_entries(&cls->route_cls.range_index_list);

    ops_cls_cleanup_entries(&cls->cls_entry_list);
}

/*
 * Delete updated entries of classifier
 */

static void
ops_cls_delete_updated_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_rule_entries(&cls->port_cls.rule_index_update_list);
    ops_cls_delete_stats_entries(&cls->port_cls.stats_index_update_list);
    ops_cls_delete_range_entries(&cls->port_cls.range_index_update_list);

    ops_cls_delete_rule_entries(&cls->route_cls.rule_index_update_list);
    ops_cls_delete_stats_entries(&cls->route_cls.stats_index_update_list);
    ops_cls_delete_range_entries(&cls->route_cls.range_index_update_list);

    ops_cls_cleanup_entries(&cls->cls_entry_update_list);
}


/*
 * Delete classifier from hash table
 */
static void
ops_cls_delete(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_orig_entries(cls);
    ops_cls_delete_updated_entries(cls);

    hmap_remove(&classifier_map, &cls->node);
    VLOG_DBG("Removed ACL %s in hashmap", cls->name);
    free(cls->name);
    free(cls);
}

/*
 * Update hardware info list
 */
static void
ops_cls_update_hw_info(struct ops_cls_hw_info *hw_info)
{
    list_move(&hw_info->rule_index_list, &hw_info->rule_index_update_list);
    list_move(&hw_info->stats_index_list, &hw_info->stats_index_update_list);
    list_move(&hw_info->range_index_list, &hw_info->range_index_update_list);
}

/*
 * Assign updated entries of classifer to original entires
 */

static void
ops_cls_update_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    /* move the installed update entries to original list */
    ops_cls_update_hw_info(&cls->port_cls);
    ops_cls_update_hw_info(&cls->route_cls);
    list_move(&cls->cls_entry_list, &cls->cls_entry_update_list);

    /* reinitialize update list for next update */
    ops_cls_init_update_list(&cls->port_cls);
    ops_cls_init_update_list(&cls->route_cls);
    list_init(&cls->cls_entry_update_list);
}

/*
 * Get ifhandle from bundle
 */
static int
ops_cls_get_ifhandle(struct ofproto *ofproto_,
                        void           *aux,
                        int            *device,
                        switch_handle_t *if_handle
                        )
{
    int unit = 0;
    int hw_port;
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);

    struct ofbundle *bundle = bundle_lookup(ofproto, aux);

    if (bundle == NULL) {
        VLOG_ERR("Failed to get port bundle");
        return OPS_CLS_FAIL;
    }

    struct sim_provider_ofport *port, *next_port;
    LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
        netdev_get_device_port_handle(port->up.netdev, device,
                                      &bundle->port_lag_handle);
    }

    *if_handle = bundle->if_handle;

    return OPS_CLS_OK;
}

/*
 * Set rule action
 */
static int
ops_cls_set_action(int                          unit,
                   struct ops_classifier       *cls,
                   struct ops_cls_entry        *cls_entry,
                   switch_acl_action_t         *action,
                   int                         *stat_index,
                   bool                        *isStatEnabled)
{
    int stat_id;

    VLOG_DBG("Classifier list entry action flag: 0x%x", cls_entry->act_flags);

    if ((cls_entry->act_flags & OPS_CLS_ACTION_LOG) &&
        (cls_entry->act_flags & OPS_CLS_ACTION_PERMIT)) {
        VLOG_ERR("Logging with permit action is unsupported");
        return OPS_CLS_HW_UNSUPPORTED_ERR;
    }

    if (cls_entry->act_flags & OPS_CLS_ACTION_DENY) {
        VLOG_DBG("setting action to DROP");
        *action = SWITCH_ACL_ACTION_DROP;
    } else if (cls_entry->act_flags & OPS_CLS_ACTION_PERMIT)  {
        VLOG_DBG("setting action to PERMIT");
        *action = SWITCH_ACL_ACTION_PERMIT;
    }


    if (cls_entry->act_flags & OPS_CLS_ACTION_COUNT) {
        //TODO: implement
        return OPS_CLS_HW_UNSUPPORTED_ERR;
    }

    if (cls_entry->act_flags & OPS_CLS_ACTION_LOG) {
        //TODO: implement
        return OPS_CLS_HW_UNSUPPORTED_ERR;
    }

    return OPS_CLS_OK;
}

/*
 * Set PI error code
 */
static void
ops_cls_set_pd_status(int                        rc,
                      int                        fail_index,
                      struct ops_cls_pd_status  *pd_status)
{

    VLOG_DBG("ops classifier error: %d ", rc);
    pd_status->entry_id = fail_index;

    switch (rc) {
    /* TBD: Add all P4 return code error code status */
    default:
        pd_status->status_code = OPS_CLS_STATUS_HW_UNKNOWN_ERR;
        VLOG_DBG("Unsupported (%d) error type", rc);
        break;
    }
}

/*
 * Set PI (list) error code
 */
static void
ops_cls_set_pd_list_status(int                             rc,
                           int                             fail_index,
                           struct ops_cls_pd_list_status  *status)
{

    VLOG_DBG("ops list error: %d ", rc);
    status->entry_id = fail_index;

    switch (rc) {
    /* TBD: Add all P4 return code error code status */
    default:
        status->status_code = OPS_CLS_STATUS_HW_UNKNOWN_ERR;
        VLOG_DBG("Unsupported (%d) error type", rc);
        break;
    }
}

/*
 * Get the source port range from classifier
 */
static void
ops_cls_get_src_port_range(struct ops_cls_list_entry_match_fields *field,
                           uint16_t                               *port_min,
                           uint16_t                               *port_max)
{
    if(field->L4_src_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = field->L4_src_port_min;
        *port_max = field->L4_src_port_max;
    } else if (field->L4_src_port_op == OPS_CLS_L4_PORT_OP_LT) {
        *port_min = 0;
        *port_max = field->L4_src_port_max;
    } else {
        *port_min = field->L4_src_port_min;
        *port_max = 65535;
    }
}

/*
 * Get the destination port range from classifier
 */
static void
ops_cls_get_dst_port_range(struct ops_cls_list_entry_match_fields *field,
                           uint16_t                               *port_min,
                           uint16_t                               *port_max)
{
    if(field->L4_dst_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = field->L4_dst_port_min;
        *port_max = field->L4_dst_port_max;
    } else if (field->L4_dst_port_op == OPS_CLS_L4_PORT_OP_LT) {
        *port_min = 0;
        *port_max = field->L4_dst_port_max;
    } else {
        *port_min = field->L4_dst_port_min;
        *port_max = 65535;
    }
}

static int
ops_cls_apply_acl_to_port(int        device,
        struct ops_classifier          *cls,
        switch_handle_t                 if_handle)
{
    switch_status_t rc;

    rc = switch_api_acl_reference(device, cls->acl, if_handle);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("Failed to apply ACL %s from interface", cls->name);
        return rc;
    }

    cls->port_ref_count ++;
    return rc;
}

static int
ops_cls_remove_acl_from_port(int                            device,
                             struct ops_classifier          *cls,
                             switch_handle_t                 if_handle)
{
    switch_status_t rc;

    rc = switch_api_acl_remove(device, cls->acl, if_handle);
    if (rc != SWITCH_STATUS_SUCCESS) {
        VLOG_ERR("Failed to remove ACL %s from interface", cls->name);
        return rc;
    }

    cls->port_ref_count --;
    /* If ACL is not applied by any ports delete ACL */
    if (0 == cls->port_ref_count) {
        rc = switch_api_acl_list_delete(device, cls->acl);
        if (rc != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("Failed to delete ACL %s", cls->name);
            return rc;
        }
        ops_cls_delete(cls);
    }

    return SWITCH_STATUS_SUCCESS;
}


/*
 * Add rule in FP
 */
static int
ops_cls_install_rule_in_asic(int                            unit,
                                struct ops_classifier         *cls,
                                struct ops_cls_entry          *cls_entry,
                                switch_handle_t                if_handle,
                                int                            index,
                                struct ops_cls_interface_info *intf_info,
                                bool                           isUpdate,
                                int                            ace_prio)
{
    switch_status_t rc = SWITCH_STATUS_SUCCESS;
    uint16_t port_mask = 0xFFFF;
    uint8_t protocol_mask = 0XFF;
    uint16_t min_port, max_port;
    int stat_index = 0;
    bool statEnabled = FALSE;
    bool src_rangeEnabled = FALSE;
    bool dst_rangeEnabled = FALSE;
    struct ops_cls_rule_entry *rulep;
    struct ops_cls_stats_entry *sentry;
    struct ops_cls_range_entry *rentry;
    struct ovs_list *listp;
    struct ops_cls_hw_info *hw_info;
    struct ops_cls_list_entry_match_fields *match = &cls_entry->entry_fields;
    switch_handle_t entry;

#define OPS_P4_MAX_KEY_VALUES 10 /* Update this incase we need
                                    to support more fields */

    union {
        switch_acl_ip_key_value_pair_t v4[OPS_P4_MAX_KEY_VALUES];
        switch_acl_ipv6_key_value_pair_t v6[OPS_P4_MAX_KEY_VALUES];
    } acl_key_value;

    int key_index = 0;
    switch_acl_action_params_t action_params;
    switch_acl_opt_action_params_t opt_action_params;
    switch_acl_action_t action;
    switch_handle_t ace_handle;

    memset(&acl_key_value, 0, sizeof(acl_key_value));
    action_params.redirect.handle = 0;

    /* According to vswitch.xml:
     * 'If no action is specified the ACE will not be programmed in hw.'
     */
    if (!cls_entry->act_flags) {
        return OPS_CLS_OK;
    }

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    if (cls_entry->match_flags & OPS_CLS_SRC_IPADDR_VALID) {
        if(cls->type == OPS_CLS_ACL_V4) {
            VLOG_DBG("Src ipv4 addr 0x%x and mask 0x%x", htonl(cls_entry->src_ip),
                     htonl(cls_entry->src_mask));
            acl_key_value.v4[key_index].field = SWITCH_ACL_IP_FIELD_IPV4_SRC;
            acl_key_value.v4[key_index].value.ipv4_source = htonl(cls_entry->src_ip);
            acl_key_value.v4[key_index].mask.u.mask = htonl(cls_entry->src_mask);
            key_index ++;
        } else if (cls->type == OPS_CLS_ACL_V6) {
            acl_key_value.v6[key_index].field = SWITCH_ACL_IPV6_FIELD_IPV6_SRC;
            memcpy(&acl_key_value.v6[key_index].value.ipv6_source , &cls_entry->src_ip6, sizeof(uint128_t));
            memcpy(&acl_key_value.v6[key_index].mask.u.mask, &cls_entry->src_mask6, sizeof(uint128_t));
            key_index ++;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_DEST_IPADDR_VALID) {
        if(cls->type == OPS_CLS_ACL_V4) {
            VLOG_DBG("Dst ipv4 addr 0x%x and mask 0x%x",
                     htonl(cls_entry->dst_ip), htonl(cls_entry->dst_mask));
            acl_key_value.v4[key_index].field = SWITCH_ACL_IP_FIELD_IPV4_DEST;
            acl_key_value.v4[key_index].value.ipv4_dest = htonl(cls_entry->dst_ip);
            acl_key_value.v4[key_index].mask.u.mask = htonl(cls_entry->dst_mask);
            key_index ++;
        } else if (cls->type == OPS_CLS_ACL_V6) {
            acl_key_value.v6[key_index].field = SWITCH_ACL_IPV6_FIELD_IPV6_DEST;
            memcpy(&acl_key_value.v6[key_index].value.ipv6_dest , &cls_entry->dst_ip6, sizeof(uint128_t));
            memcpy(&acl_key_value.v6[key_index].mask.u.mask, &cls_entry->dst_mask6, sizeof(uint128_t));
            key_index ++;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_PROTOCOL_VALID) {
        VLOG_DBG("IP protocol: 0x%x", match->protocol);
        if (cls->type == OPS_CLS_ACL_V4) {
            acl_key_value.v4[key_index].field = SWITCH_ACL_IP_FIELD_IP_PROTO;
            acl_key_value.v4[key_index].value.ip_proto = match->protocol;
            acl_key_value.v4[key_index].mask.u.mask = protocol_mask;
            key_index ++;
        } else if (cls->type == OPS_CLS_ACL_V6) {
            acl_key_value.v6[key_index].field = SWITCH_ACL_IPV6_FIELD_IP_PROTO;
            acl_key_value.v6[key_index].value.ip_proto = match->protocol;
            acl_key_value.v6[key_index].mask.u.mask.u.addr32[0] = protocol_mask;
            key_index ++;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_L4_SRC_PORT_VALID) {
        VLOG_DBG("L4 src port min: 0x%x max: 0x%x ops %d",
                 match->L4_src_port_min, match->L4_src_port_max,
                 match->L4_src_port_op);

        switch (match->L4_src_port_op) {
        case OPS_CLS_L4_PORT_OP_EQ:
            if (cls->type == OPS_CLS_ACL_V4) {
                acl_key_value.v4[key_index].field = SWITCH_ACL_IP_FIELD_L4_SOURCE_PORT;
                acl_key_value.v4[key_index].value.l4_source_port = match->protocol;
                acl_key_value.v4[key_index].mask.u.mask = protocol_mask;
                key_index ++;
            } else if (cls->type == OPS_CLS_ACL_V6) {
                acl_key_value.v6[key_index].field = SWITCH_ACL_IPV6_FIELD_L4_SOURCE_PORT;
                acl_key_value.v6[key_index].value.l4_source_port = match->protocol;
                acl_key_value.v6[key_index].mask.u.mask.u.addr32[0] = protocol_mask;
                key_index ++;
            }
            break;

        case OPS_CLS_L4_PORT_OP_RANGE:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        default:
            VLOG_INFO("L4 src port operation %d not supported",
                      match->L4_src_port_op);
            rc = OPS_CLS_HW_UNSUPPORTED_ERR;
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_L4_DEST_PORT_VALID) {
        VLOG_DBG("L4 dst port min: 0x%x max: 0x%x ops %d",
                 match->L4_dst_port_min, match->L4_dst_port_max,
                 match->L4_dst_port_op);

        switch (match->L4_dst_port_op) {
        case OPS_CLS_L4_PORT_OP_EQ:
            if (cls->type == OPS_CLS_ACL_V4) {
                acl_key_value.v4[key_index].field = SWITCH_ACL_IP_FIELD_L4_DEST_PORT;
                acl_key_value.v4[key_index].value.l4_dest_port = match->protocol;
                acl_key_value.v4[key_index].mask.u.mask = protocol_mask;
                key_index ++;
            } else if (cls->type == OPS_CLS_ACL_V6) {
                acl_key_value.v6[key_index].field = SWITCH_ACL_IPV6_FIELD_L4_DEST_PORT;
                acl_key_value.v6[key_index].value.l4_dest_port = match->protocol;
                acl_key_value.v6[key_index].mask.u.mask.u.addr32[0] = protocol_mask;
                key_index ++;
            }
            break;

        case OPS_CLS_L4_PORT_OP_RANGE:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        default:
            VLOG_INFO("L4 dst port operation %d not supported",
                      match->L4_dst_port_op);
            rc = OPS_CLS_HW_UNSUPPORTED_ERR;
            goto cleanup;
        }
    }

    /* Set the actions */
    rc = ops_cls_set_action(unit, cls, cls_entry, &action, &stat_index,
                            &statEnabled);

    if(ops_cls_error(rc)) {
        goto cleanup;
    }

    if (cls->type == OPS_CLS_ACL_V4) {
        rc = switch_api_acl_rule_create(unit, cls->acl, ace_prio, key_index, acl_key_value.v4, action,
                                    &action_params, &opt_action_params, &ace_handle);
    } else if (cls->type == OPS_CLS_ACL_V6) {
        rc = switch_api_acl_rule_create(unit, cls->acl, ace_prio, key_index, acl_key_value.v6, action,
                                    &action_params, &opt_action_params, &ace_handle);
    }

    if(rc != SWITCH_STATUS_SUCCESS) {
        VLOG_INFO("switch_api_acl_rule_create error %d", rc);
        goto cleanup;
    }

    VLOG_INFO("Classifier %s rule id %d action %d on if handle %d successfully installed",
              cls->name, ace_handle, action, if_handle);

    /* store stats entry */
    if (statEnabled) {
        /* add it in range list of acl entry */
        sentry = xzalloc(sizeof(struct ops_cls_stats_entry));
        sentry->index = stat_index;
        sentry->rule_index = index;
        listp = isUpdate ? &hw_info->stats_index_update_list
                            : &hw_info->stats_index_list;
        list_push_back(listp, &sentry->node);
    }

    /* store range entry */
    if (src_rangeEnabled) {
        rentry = xzalloc(sizeof(struct ops_cls_range_entry));
        //TODO: implement port range
        listp = isUpdate ? &hw_info->range_index_update_list
                            : &hw_info->range_index_list;
        list_push_back(listp, &rentry->node);
    }

    if (dst_rangeEnabled) {
        rentry = xzalloc(sizeof(struct ops_cls_range_entry));
        //TODO: implement port range
        listp = isUpdate ? &hw_info->range_index_update_list
                            : &hw_info->range_index_list;
        list_push_back(listp, &rentry->node);
    }

    /* Save the entry id in  field */
    rulep =  xzalloc(sizeof(struct ops_cls_rule_entry));
    rulep->index = ace_handle;
    listp = isUpdate ? &hw_info->rule_index_update_list
                        : &hw_info->rule_index_list;
    list_push_back(listp, &rulep->node);

    VLOG_DBG(" ---------------- ACE HANDLING COMPLETE ----------------");
    return OPS_CLS_OK;

cleanup:
    if (src_rangeEnabled) {
        //TODO: Destroy any range resource
    }

    if (dst_rangeEnabled) {
        //TODO: Destroy any range resource
    }

    if (statEnabled) {
        //TODO: Destroy any range resource
    }

    /* destroy entry and return rc */
    rc = switch_api_acl_rule_delete(unit, cls->acl, ace_handle);
    VLOG_DBG("---------------- ACE HANDLING (FAILED) ----------------");
    return rc;
}

/*
 * Add classifier rules in ASIC
 */
static int
ops_p4_cls_install_classifier_in_asic(int                             device,
                                      struct ops_classifier          *cls,
                                      struct ovs_list                *list,
                                      switch_handle_t                 if_handle,
                                      int                            *fail_index,
                                      bool                            isUpdate,
                                      struct ops_cls_interface_info  *intf_info)
{
    int rc;
    struct ops_cls_entry *cls_entry = NULL, *next_cls_entry;
    struct ops_cls_hw_info *hw_info;
    switch_acl_type_t type;
#define BASE_ACE_PRIO 1
    int ace_prio = BASE_ACE_PRIO;
    int acl_prio;

    if (cls->type == OPS_CLS_ACL_V4) {
        type = SWITCH_ACL_TYPE_IP;
        acl_prio = OPS_GROUP_PRI_IPv4;
    } else if (cls->type == OPS_CLS_ACL_V6) {
        type = SWITCH_ACL_TYPE_IPV6;
        acl_prio = OPS_GROUP_PRI_IPv6;
    } else {
        VLOG_ERR("Unsupported ACL type %d, ACL %s", cls-type, cls->name);
        return OPS_CLS_FAIL;
    }

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        /*
         * TODO: Nothing to do currently for Port based ACLs.
         * We will need to create RACLs for other interface types
         */
        VLOG_DBG("L3 Routable bit set");
    }

    /* Create acl list in hw */
    if(!cls->acl) {
        cls->acl = switch_api_acl_list_create(device, type);
        switch_api_acl_renumber(device, cls->acl, acl_prio);
        VLOG_DBG("switch_handle for ACL %d", cls->acl);
    }

    /* Install in ASIC */
    LIST_FOR_EACH_SAFE(cls_entry, next_cls_entry, node, list) {
        rc = ops_cls_install_rule_in_asic(device, cls, cls_entry, if_handle,
                                          *fail_index, intf_info, isUpdate, ace_prio);
        if (ops_cls_error(rc)) {
            VLOG_ERR("Failed to install classifier %s rule(s) ", cls->name);
            return rc;
        }
        ace_prio ++;
        (*fail_index)++;
    }

    /* If we have if_handle, lets apply it */
    if (if_handle) {
        rc = ops_cls_apply_acl_to_port(device, cls, if_handle);

        if(rc != SWITCH_STATUS_SUCCESS) {
            return rc;
        }
    }

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    hw_info->in_asic = true;

    VLOG_DBG("Classifier %s successfully installed in asic", cls->name);
    return rc;
}

/*
 * Delete rules in asic
 */
static int
ops_cls_delete_rules_in_asic(int                             device,
                             struct ops_classifier          *cls,
                             int                            *fail_index,
                             struct ops_cls_interface_info  *intf_info,
                             bool                            isUpdate)
{
    switch_status_t rc = SWITCH_STATUS_SUCCESS;
    struct ops_cls_rule_entry *rule_entry = NULL, *next_rule_entry;
    struct ops_cls_range_entry *rentry = NULL, *next_rentry;
    struct ops_cls_stats_entry *sentry = NULL, *next_sentry;
    struct ovs_list *rule_index_list, *range_index_list, *stats_index_list;
    struct ops_cls_hw_info *hw_info;
    int entry;
    int index = 0;

    if (!cls) {
        return OPS_CLS_FAIL;
    }

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    rule_index_list = isUpdate ? &hw_info->rule_index_update_list
                                  : &hw_info->rule_index_list;
    range_index_list = isUpdate ? &hw_info->range_index_update_list
                                   : &hw_info->range_index_list;
    stats_index_list = isUpdate ? &hw_info->stats_index_update_list
                                   : &hw_info->stats_index_list;

    LIST_FOR_EACH_SAFE(rule_entry, next_rule_entry, node, rule_index_list) {
        entry = rule_entry->index;

        rc = switch_api_acl_rule_delete(device, cls->acl, rule_entry->index);
        if(rc != SWITCH_STATUS_SUCCESS) {
            VLOG_ERR("Failed to destroy classifier %s entry 0x%x rc:%d",
                     cls->name, entry, rc);
            if (*fail_index == 0) {
                *fail_index = index;
            }
        }
        index++;
    }

    LIST_FOR_EACH_SAFE(rentry, next_rentry, node, range_index_list) {
        entry = rentry->index;
        /* TBD: Cleanup any resources used for port range */
    }

    LIST_FOR_EACH_SAFE(sentry, next_sentry, node, stats_index_list) {
        entry = sentry->index;
        /* TBD: Cleanup any resources used for stats */
    }

    return OPS_CLS_OK;
}

/*
 * Update port for classifier
 */
static int
ops_cls_update_classifier_in_asic(int                             device,
                                     struct ops_classifier          *cls,
                                     switch_handle_t                 if_handle,
                                     enum ops_update_port            action,
                                     int                            *fail_index,
                                     struct ops_cls_interface_info  *intf_info)
{
    switch_status_t rc = SWITCH_STATUS_SUCCESS;
    struct ops_cls_hw_info *hw_info;

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    switch (action) {
    case OPS_PORT_ADD:
        rc = ops_cls_apply_acl_to_port(device, cls, if_handle);
        break;

    case OPS_PORT_DEL:
        rc = ops_cls_remove_acl_from_port(device, cls, if_handle);
        break;

    default:
        break;

    }

    return rc;
}

/*
 * Apply classifier to a port
 */
int
ops_cls_p4_apply(struct ops_cls_list            *list,
                      struct ofproto                 *ofproto,
                      void                           *aux,
                      struct ops_cls_interface_info  *interface_info,
                      enum ops_cls_direction          direction,
                      struct ops_cls_pd_status       *pd_status)
{
    switch_status_t rc;
    int device;
    switch_handle_t if_handle;
    struct ops_classifier *cls = NULL;
    char pbmp_string[200];
    int fail_index = 0; /* rule index to PI on failure */
    bool in_asic;

    VLOG_INFO("Apply classifier "UUID_FMT" (%s)",
              UUID_ARGS(&list->list_id), list->list_name);

    if (direction != OPS_CLS_DIRECTION_IN) {
        VLOG_ERR("Failed to apply %s in the %s direction.",
                 list->list_name,
                 (direction == OPS_CLS_DIRECTION_OUT ? "egress" : "?"));
        rc = OPS_CLS_FAIL;
        goto apply_fail;
    }

    cls = ops_cls_lookup(&list->list_id);

    if (!cls) {
        cls = ops_cls_add(list);
        if (!cls) {
            VLOG_ERR ("Failed to add classifier "UUID_FMT" (%s) in hashmap",
                       UUID_ARGS(&list->list_id), list->list_name);
            rc = OPS_CLS_FAIL;
            goto apply_fail;
        }
    } else {
        VLOG_DBG("Classifier %s exist in hashmap", list->list_name);
    }

    /* get the ifhandle */
    if (ops_cls_get_ifhandle(ofproto, aux, &device, &if_handle)) {
        rc = OPS_CLS_FAIL;
        goto apply_fail;
    }

    VLOG_DBG("Apply classifier on if handle: %d", if_handle);

    if (interface_info && (interface_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        VLOG_DBG("Apply %s as routed classifier", cls->name);
        in_asic = cls->route_cls.in_asic;
    } else {
        VLOG_DBG("Apply %s as port classifier", cls->name);
        in_asic = cls->port_cls.in_asic;
    }

    if (!in_asic) {
        /* first binding of classifier*/
        rc = ops_p4_cls_install_classifier_in_asic(device, cls, &cls->cls_entry_list,
                                                   if_handle, &fail_index, FALSE,
                                                   interface_info);
        if (ops_cls_error(rc)) {
            int index = 0;
            ops_cls_delete_rules_in_asic(device, cls, &index,
                                         interface_info, FALSE);
            if (!cls->route_cls.in_asic && !cls->port_cls.in_asic) {
                ops_cls_delete(cls);
            }
            goto apply_fail;
        }
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(device, cls, if_handle,
                                                  OPS_PORT_ADD, &fail_index,
                                                  interface_info);
        if (ops_cls_error(rc)) {
            goto apply_fail;
        }
    }
    return OPS_CLS_OK;

apply_fail:
    ops_cls_set_pd_status(rc, fail_index, pd_status);
    return OPS_CLS_FAIL;
}

/*
 * Remove classifier from port
 */
int
ops_cls_p4_remove(const struct uuid                *list_id,
                       const char                       *list_name,
                       enum ops_cls_type                 list_type OVS_UNUSED,
                       struct ofproto                   *ofproto,
                       void                             *aux,
                       struct ops_cls_interface_info    *interface_info,
                       enum ops_cls_direction            direction,
                       struct ops_cls_pd_status         *pd_status)
{
    int rc;
    int device;
    switch_handle_t if_handle;
    int fail_index = 0; /* rule index to PI on failure */
    bool in_asic = false;
    struct ops_classifier *cls = NULL;

    cls = ops_cls_lookup(list_id);
    if (!cls) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_CLS_FAIL;
        goto remove_fail;
    }

    /* get the ifhandle */
    if (ops_cls_get_ifhandle(ofproto, aux, &device, &if_handle)) {
        rc = OPS_CLS_FAIL;
        goto remove_fail;
    }

    rc = ops_cls_remove_acl_from_port(device, cls, if_handle);
    return OPS_CLS_OK;

remove_fail:
    ops_cls_set_pd_status(rc, fail_index, pd_status);
    return OPS_CLS_FAIL;
}

/*
 * Attach port to different classifier
 */
int
ops_cls_p4_replace(const struct uuid               *list_id_orig,
                        const char                      *list_name_orig,
                        struct ops_cls_list             *list_new,
                        struct ofproto                  *ofproto,
                        void                            *aux,
                        struct ops_cls_interface_info   *interface_info,
                        enum ops_cls_direction           direction,
                        struct ops_cls_pd_status        *pd_status)
{
    int rc;
    int device;
    switch_handle_t if_handle;
    int hw_unit;
    struct ops_classifier *cls_orig = NULL, *cls_new = NULL;
    char pbmp_string[200];
    int fail_index = 0; /* rule index to PI on failure */
    bool *in_asic_orig = false;
    bool *in_asic_new = false;

    VLOG_DBG("Replace classifier "UUID_FMT" by "UUID_FMT"",
              UUID_ARGS(list_id_orig), UUID_ARGS(&list_new->list_id));

    if (direction != OPS_CLS_DIRECTION_IN) {
        VLOG_ERR("Failed to replace %s in the %s direction.",
                list_name_orig,
                (direction == OPS_CLS_DIRECTION_OUT ? "egress" : "?"));
        rc = OPS_CLS_FAIL;
        goto replace_fail;
    }

    cls_orig = ops_cls_lookup(list_id_orig);
    if (!cls_orig) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",
                 UUID_ARGS(list_id_orig));
        rc = OPS_CLS_FAIL;
        goto replace_fail;
    }

    cls_new = ops_cls_lookup(&list_new->list_id);
    if (!cls_new) {
        cls_new = ops_cls_add(list_new);
        if (!cls_new) {
            VLOG_ERR ("Failed to add classifier "UUID_FMT" (%s) in hashmap",
                       UUID_ARGS(&list_new->list_id), list_new->list_name);
            rc =  OPS_CLS_FAIL;
            goto replace_fail;
        }
    } else {
        VLOG_DBG("Replace classifier "UUID_FMT" (%s) exist in hashmap",
                  UUID_ARGS(&list_new->list_id), list_new->list_name);
    }

    /* get the ifhandle */
    if (ops_cls_get_ifhandle(ofproto, aux, &device, &if_handle)) {
        rc = OPS_CLS_FAIL;
        goto replace_fail;
    }

    if (interface_info && (interface_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        VLOG_DBG("Replace %s classifier and apply %s as routed classifier",
                  cls_orig->name, cls_new->name);
        in_asic_orig = &cls_orig->route_cls.in_asic;
        in_asic_new = &cls_new->route_cls.in_asic;
    } else {
        VLOG_DBG("Replace %s classifier and  apply %s as port classifier",
                  cls_orig->name, cls_new->name);
        in_asic_orig = &cls_orig->port_cls.in_asic;
        in_asic_new = &cls_new->port_cls.in_asic;
    }


    if (!(*in_asic_new)) {
        /* first binding of classifier*/
        rc = ops_p4_cls_install_classifier_in_asic(hw_unit, cls_new,
                                                   &cls_new->cls_entry_list,
                                                   if_handle, &fail_index,
                                                   FALSE, interface_info);
        if (ops_cls_error(rc)) {
            int index = 0;
            ops_cls_delete_rules_in_asic(hw_unit, cls_new, &index,
                                         interface_info, FALSE);
            goto replace_fail;
        }
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls_new, if_handle,
                                                  OPS_PORT_ADD, &fail_index,
                                                  interface_info);
        if (ops_cls_error(rc)) {
            goto replace_fail;
        }
    }

    if (in_asic_orig) {
        /* already in asic update port bitmap */
        fail_index = 0;
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls_orig, if_handle,
                                               OPS_PORT_DEL, &fail_index,
                                               interface_info);
        if(rc != SWITCH_STATUS_SUCCESS) {
            goto replace_fail;
        }
    }

    return OPS_CLS_OK;

replace_fail:
    ops_cls_set_pd_status(rc, fail_index, pd_status);
    return OPS_CLS_FAIL;
}

/*
 * Create a new ACL.
 */
int
ops_cls_p4_list_update(struct ops_cls_list                 *list,
                            struct ops_cls_pd_list_status       *status)
{
    int rc, rc_fail;
    struct ops_classifier *cls = NULL;
    int hw_unit =  0;
    int fail_index = 0; /* rule index to PI on failure */
    struct ops_cls_interface_info intf_info;

    VLOG_DBG("Update classifier "UUID_FMT" (%s)", UUID_ARGS(&list->list_id),
            list->list_name);

    cls = ops_cls_lookup(&list->list_id);
    if (!cls) {
        VLOG_ERR ("Failed to find classifier %s in hashmap", list->list_name);
        rc = OPS_CLS_FAIL;
        goto update_fail;
    } else {
        VLOG_DBG("Classifier %s exist in hashmap", list->list_name);
    }

    if (cls->route_cls.in_asic) {
        intf_info.flags = OPS_CLS_INTERFACE_L3ONLY;
    }

    VLOG_DBG("Total rules %d in classifier update", list->num_entries);


    /*
     * Delete list of ACEs and install new list.
     * Incase of any failure reinstall original
     * list of ACEs
     * TODO: Currently this design might leak a
     * few packets during list update. This
     * is a limitation in p4 software model
     * where we cannot add duplicate ACE entry
     * with same priority. The other option is to
     * manage priorities of individual ACEs in PD
     * but this is not currently in the scope.
     */

    if (cls->port_cls.in_asic) {
        ops_cls_delete_rules_in_asic(hw_unit, cls, &fail_index,
                NULL, FALSE);
    }

    if (cls->route_cls.in_asic) {
        ops_cls_delete_rules_in_asic(hw_unit, cls, &fail_index,
                &intf_info, FALSE);
    }

    if (list->num_entries > 0) {
        ops_cls_populate_entries(cls, &cls->cls_entry_update_list, list);

        if (cls->port_cls.in_asic) {
            rc = ops_p4_cls_install_classifier_in_asic(hw_unit, cls,
                    &cls->cls_entry_update_list,
                    0, &fail_index,
                    TRUE, NULL);
        }

        if (!ops_cls_error(rc) && cls->route_cls.in_asic) {
            rc = ops_p4_cls_install_classifier_in_asic(hw_unit, cls,
                    &cls->cls_entry_update_list,
                    0, &fail_index,
                    TRUE, &intf_info);
        }

        int index = 0;
        if(ops_cls_error(rc)) {
            if (cls->port_cls.in_asic) {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index,
                        NULL, TRUE);
            }

            if (cls->route_cls.in_asic) {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index,
                        &intf_info, TRUE);
            }

            ops_cls_delete_updated_entries(cls);
            goto update_fail;
        } else {
            ops_cls_delete_orig_entries(cls);
            ops_cls_update_entries(cls);
        }
    }
    return OPS_CLS_OK;
update_fail:
    ops_cls_set_pd_list_status(rc, fail_index, status);

    /* Reinstall original list of entries */
    if (cls->port_cls.in_asic) {
        rc_fail = ops_p4_cls_install_classifier_in_asic(hw_unit, cls,
                &cls->cls_entry_list,
                0, &fail_index,
                FALSE, NULL);
    }

    if (!ops_cls_error(rc_fail) && cls->route_cls.in_asic) {
        rc_fail = ops_p4_cls_install_classifier_in_asic(hw_unit, cls,
                &cls->cls_entry_list,
                0, &fail_index,
                FALSE, &intf_info);
    }

    if(ops_cls_error(rc_fail)) {
        VLOG_ERR("Unable to restore ACL entries %s. ASIC is out of sync.");
    }

    return OPS_CLS_FAIL;
}

/*
 * Get statistics of FP entries
 */
int
ops_cls_p4_statistics_get(const struct uuid              *list_id,
                               const char                     *list_name,
                               enum ops_cls_type              list_type,
                               struct ofproto                 *ofproto,
                               void                           *aux,
                               struct ops_cls_interface_info  *interface_info,
                               enum ops_cls_direction         direction,
                               struct ops_cls_statistics      *statistics,
                               int                            num_entries,
                               struct ops_cls_pd_list_status  *status)
{
    VLOG_ERR("%s unimplemented", __func__);
    return OPS_CLS_FAIL;
}


/*
 * Clear statistics of FP entries
 */
int
ops_cls_p4_statistics_clear(const struct uuid               *list_id,
                                 const char                      *list_name,
                                 enum ops_cls_type               list_type,
                                 struct ofproto                  *ofproto,
                                 void                            *aux,
                                 struct ops_cls_interface_info   *interface_info,
                                 enum ops_cls_direction          direction,
                                 struct ops_cls_pd_list_status   *status)
{
    VLOG_ERR("%s unimplemented", __func__);
    return OPS_CLS_FAIL;
}


int
ops_cls_p4_statistics_clear_all(struct ops_cls_pd_list_status *status)
{
    VLOG_ERR("%s unimplemented", __func__);
    return OPS_CLS_FAIL;
}

int
ops_cls_p4_acl_log_pkt_register_cb(void (*callback_handler)(struct acl_log_info *))
{
    if (!callback_handler) {
        VLOG_ERR("No ACL logging callback provided");
        return OPS_CLS_FAIL;
    }
    acl_pd_log_pkt_data_set = callback_handler;
    return OPS_CLS_OK;
}

int
register_ops_cls_plugin()
{
    /* Initialize cls plugin */
    ops_classifier_init();
    return (register_plugin_extension(&ops_cls_extension));
}
