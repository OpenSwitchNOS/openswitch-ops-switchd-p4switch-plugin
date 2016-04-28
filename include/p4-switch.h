/*
 * Copyright (C) 2016 Barefoot Networks Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _P4_SWITCH_H_
#define _P4_SWITCH_H_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_hostif.h"
#include "switchapi/switch_interface.h"
#include "switchapi/switch_vlan.h"
#include "switchapi/switch_l3.h"
#include "switchapi/switch_hostif.h"
#include "switchapi/switch_vrf.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_acl.h"
#include "switchapi/switch_nhop.h"
#include "switchapi/switch_rmac.h"
#include "switchapi/switch_neighbor.h"
#include "switchapi/switch_lag.h"
#include "switchapi/switch_log.h"

#define MAX_P4_SWITCH_PORTS 64

// These are netdev stats... there are problems including netdev.h and netlink.h
// ovs/netlink.h(included via netdev.h) and linux/netlink.h have duplicate definitions
struct p4_port_stats {
    uint64_t rx_packets;        /* Total packets received. */
    uint64_t tx_packets;        /* Total packets transmitted. */
    uint64_t rx_bytes;          /* Total bytes received. */
    uint64_t tx_bytes;          /* Total bytes transmitted. */
    uint64_t rx_errors;         /* Bad packets received. */
    uint64_t tx_errors;         /* Packet transmit problems. */
    uint64_t rx_dropped;        /* No buffer space. */
    uint64_t tx_dropped;        /* No buffer space. */
    uint64_t multicast;         /* Multicast packets received. */
    uint64_t collisions;

    /* Detailed receive errors. */
    uint64_t rx_length_errors;
    uint64_t rx_over_errors;    /* Receiver ring buff overflow. */
    uint64_t rx_crc_errors;     /* Recved pkt with crc error. */
    uint64_t rx_frame_errors;   /* Recv'd frame alignment error. */
    uint64_t rx_fifo_errors;    /* Recv'r fifo overrun . */
    uint64_t rx_missed_errors;  /* Receiver missed packet. */

    /* Detailed transmit errors. */
    uint64_t tx_aborted_errors;
    uint64_t tx_carrier_errors;
    uint64_t tx_fifo_errors;
    uint64_t tx_heartbeat_errors;
    uint64_t tx_window_errors;
};

void p4_switch_init(void);
int p4_port_stats_get (const char *if_name, struct p4_port_stats *stats);

#endif /* _P4_SWITCH_H_ */
