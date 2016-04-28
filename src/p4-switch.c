/*
 *  Copyright (C) 2016 Barefoot Networks Inc.
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include "openvswitch/vlog.h"
#include "p4-switch.h"

VLOG_DEFINE_THIS_MODULE(P4_switch_api);

/* netlink socket to emulns namespace - to get interface stats */
static int emulns_nl_sockfd;
static int emulns_fd;
static int swns_fd;

static void
emulns_nl_sock_init()
{
    /* Open a socket in emulation (setns done by caller) namespace
     * to get interface stats when requested by upper layers
     */
    int sock = -1;
    struct sockaddr_nl s_addr;

    emulns_nl_sockfd = -1;
    sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock < 0) {
        VLOG_ERR("Netlink socket creation failed (%s)", strerror(errno));
        return;
    }

    memset((void *) &s_addr, 0, sizeof(s_addr));
    s_addr.nl_family = AF_NETLINK;
    s_addr.nl_pid = 0;
    s_addr.nl_groups = 0;

    if (connect(sock, (struct sockaddr *) &s_addr, sizeof(s_addr)) < 0) {
        VLOG_ERR("Socket connect failed");
        close(sock);
        return;
    }
    emulns_nl_sockfd = sock;
}

int
p4_to_ops_log_level(switch_api_log_level_t level)
{
    switch (level)
    {
        case SWITCH_API_LOG_ERROR:
            return VLL_ERR;
        case SWITCH_API_LOG_WARN:
            return VLL_WARN;
        case SWITCH_API_LOG_INFO:
            return VLL_INFO;
        case SWITCH_API_LOG_VERBOSE:
        case SWITCH_API_LOG_TRACE:
        default:
            return VLL_DBG;
    }
    return VLL_OFF;
}

bool
p4_switch_api_log_level_check(switch_api_log_level_t level)
{
    return vlog_is_enabled(&VLM_P4_switch_api, p4_to_ops_log_level(level));
}

int
p4_switch_api_logger(switch_api_log_level_t level, char *fmt, ...)
{
    va_list args;
    char buf[512];
    
    if (!p4_switch_api_log_level_check(level)) {
        return 0;
    }
    va_start(args, fmt);
    vsnprintf(buf, 512, fmt, args);

    switch (level)
    {
        case SWITCH_API_LOG_ERROR:
            VLOG_ERR(buf); break;
        case SWITCH_API_LOG_WARN:
            VLOG_WARN(buf); break;
        case SWITCH_API_LOG_INFO:
            VLOG_INFO(buf); break;
        case SWITCH_API_LOG_VERBOSE:
        case SWITCH_API_LOG_TRACE:
        default:
            VLOG_DBG(buf); break;
    }
    va_end(args);
    return 1;
}

void
p4_switch_init ()
{
    /* P4 simulator supports only a single device with N ports,
     * always pass device=0 to all apis
     */
    emulns_fd = -1;
    swns_fd = -1;
    /* model runs in emulns while plugin runs in swns.
     * attach to emulns while initializing interface and communication with the model
     */
    if ((emulns_fd = open("/var/run/netns/emulns", O_RDONLY)) < 0) {
        VLOG_ERR("Cannot find emulns name space for the model - %s", strerror(errno));
    } else {
        if (setns(emulns_fd, 0) < 0) {
            VLOG_ERR("Failed to connect to netns for the model");
        } else {
            VLOG_INFO("Using emulns for the model");
        }
    }
    if ((swns_fd = open("/var/run/netns/swns", O_RDONLY)) < 0) {
        VLOG_ERR("Could not find swns - %s", strerror(errno));
    }
    emulns_nl_sock_init();
    p4_pd_init();
    p4_pd_dc_init();
    p4_pd_dc_assign_device(0, "ipc:///tmp/bmv2-0-notifications.ipc", 10001);
    /* Initialize cpu interface between model and the plugin - this is done internally by api_init */
    switch_api_init(0, MAX_P4_SWITCH_PORTS+1);  /* add 1 port cpu port */
    /* register logger function to send switchapi logs to vlog infra */
    switch_api_log_function_set(p4_switch_api_logger);
    start_switch_api_packet_driver();
    /* attach to swns for the rest of the processing */
    if (swns_fd >= 0) {
        if (setns(swns_fd, 0) < 0) {
            VLOG_ERR("Could not switch back to swns");
            return;
        }
        VLOG_INFO("Switched back to swns");
    }
}

static void
netdev_parse_netlink_msg(struct nlmsghdr *h, struct p4_port_stats *stats)
{
    struct ifinfomsg *iface;
    struct rtattr *attribute;
    struct rtnl_link_stats *s;
    int len;

    iface = (struct ifinfomsg *)NLMSG_DATA(h);
    len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
    for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len);
         attribute = RTA_NEXT(attribute, len)) {
        switch(attribute->rta_type) {
        case IFLA_STATS:
            //VLOG_DBG("Recieved stats from netlink..");
            s = (struct rtnl_link_stats *) RTA_DATA(attribute);
            stats->rx_packets = s->rx_packets;
            stats->tx_packets = s->tx_packets;
            stats->rx_bytes = s->rx_bytes;
            stats->tx_bytes = s->tx_bytes;
            stats->rx_errors = s->rx_errors;
            stats->tx_errors = s->tx_errors;
            stats->rx_dropped = s->rx_dropped;
            stats->tx_dropped = s->tx_dropped;
            stats->multicast = s->multicast;
            stats->collisions = s->collisions;
            stats->rx_crc_errors = s->rx_crc_errors;
            break;
        default:
            break;
        }
    }
}

/* API to get port stats */
int
p4_port_stats_get (const char *if_name, struct p4_port_stats *stats)
{
    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg iface;
    } req;
    struct sockaddr_nl kernel;
    struct msghdr rtnl_msg;
    struct iovec io;
    int ret = 0;

    if (emulns_nl_sockfd < 0) {
        return -1;
    }

    if (emulns_fd > 0) {
        if (setns(emulns_fd, 0) < 0) {
            VLOG_ERR("Failed to connect to emulns for the model");
            return 0;
        }
    }

    memset (&req, 0, sizeof(req));
    memset (&kernel, 0, sizeof(kernel));
    memset (&rtnl_msg, 0, sizeof(rtnl_msg));

    kernel.nl_family = AF_NETLINK;
    kernel.nl_pid = 0;
    kernel.nl_groups = 0;

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST;
    req.hdr.nlmsg_type = RTM_GETLINK;

    req.iface.ifi_family = AF_UNSPEC;
    req.iface.ifi_type = IFLA_UNSPEC;
    req.iface.ifi_flags = 0;
    req.iface.ifi_change = 0xffffffff;
    req.iface.ifi_index = if_nametoindex(if_name);

    if (req.iface.ifi_index == 0) {
        ret = -1;
        goto stats_done;
    }
    io.iov_base = &req;
    io.iov_len = req.hdr.nlmsg_len;

    rtnl_msg.msg_name = &kernel;
    rtnl_msg.msg_namelen = sizeof(kernel);
    rtnl_msg.msg_iov = &io;
    rtnl_msg.msg_iovlen = 1;

    //VLOG_DBG("Requesting stats for %s index %d", if_name, req.iface.ifi_index);
    sendmsg(emulns_nl_sockfd, (struct msghdr *) &rtnl_msg, 0);

    /* Prepare for reply from the kernel */
    bool multipart_msg_end = false;

    while (!multipart_msg_end) {
        struct sockaddr_nl nladdr;
        struct msghdr msg;
        struct iovec iov;
        struct nlmsghdr *nlh;
        char buffer[4096];

        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;
        iov.iov_base = (void *)buffer;
        iov.iov_len = sizeof(buffer);
        msg.msg_name = (void *)&(nladdr);
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ret = recvmsg(emulns_nl_sockfd, &msg, 0);

        if (ret < 0) {
            VLOG_ERR("Reply error during netlink \
                     request for statistics\n");
            goto stats_done;
        }

        nlh = (struct nlmsghdr*) buffer;

        for (nlh = (struct nlmsghdr *) buffer;
             NLMSG_OK(nlh, ret);
             nlh = NLMSG_NEXT(nlh, ret)) {
            switch(nlh->nlmsg_type) {
                case RTM_NEWLINK:
                    netdev_parse_netlink_msg(nlh, stats);
                    break;

                case NLMSG_DONE:
                    multipart_msg_end = true;
                    break;

                default:
                    break;
            }

            if (!(nlh->nlmsg_flags & NLM_F_MULTI)) {
                multipart_msg_end = true;
            }
        }
    }
stats_done:
    if (swns_fd >= 0) {
        if (setns(swns_fd, 0) < 0) {
            VLOG_ERR("Could not switch back to swns");
        }
    }
    return ret;
}
