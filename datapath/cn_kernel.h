/*
* Copyright (c) 2016-17, Internet for Things Research Lab,
* Swinburne University of Technology. All rights reserved.
*
* Author: Dzuy Pham (dhpham@swin.edu.au), Jason But (jbut@swin.edu.au)
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*
* The views and conclusions contained in the software and documentation are
* those of the authors and should not be interpreted as representing official
* policies, either expressed or implied, of the FreeBSD Project.
*/

#ifdef K_ENABLE_CN_STATS
#ifndef CN_KERNEL_H
#define CN_KERNEL_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/mutex.h>
#include <net/genetlink.h>
#include <linux/skbuff.h>
 
#ifndef NLCOMMON_H
#define NLCOMMON_H

/* Generic Netlink (genl) definitions to be able to send data between kernel
 * and user-space */
#define STAT_TABLE_FAMILY_NAME "STAT_TABLE"
#define STAT_TABLE_GROUP "STAT_TABLE"
#define STAT_TABLE_VERSION 1

/* Number of incoming packets to parse data from before transmitting to 
 * user-space */
#ifndef K_MAX_PKT_CNT
#define K_MAX_PKT_CNT 100
#endif

/* Statistics Struct to store packet data in kernel memory */
struct nl_per_ip {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
};

struct cn_per_flow_stats {
    struct nl_per_ip ipv4;
    __be32 pkt_cnt;
    __be16 *pkt_size;
};

struct per_stats_table {
    struct cn_per_flow_stats *stats;
    struct per_stats_table *next;
};

/* Netlink Protocol Headers */
struct k_per_flow_stats {
    struct nl_per_ip ipv4;
    __be32 pkt_cnt;
    __be16 pkt_list[K_MAX_PKT_CNT];
};

struct attr_stat_table {
    struct k_per_flow_stats *stats;
    double size;
};

enum {
    STAT_TABLE_UNSPEC,
    FLOW_STATS,
    __STAT_TABLE_ATTR_MAX
};
#define STAT_TABLE_ATTR_MAX (__STAT_TABLE_ATTR_MAX - 1)

enum cn_stats_handles {
    STAT_TABLE_CMD_DUMP,
    STAT_TABLE_CMD_DISABLE,
    STAT_TABLE_CMD_ENABLE,
};
#endif

static DEFINE_MUTEX(cn_mutex);
extern struct per_stats_table *stats_table;
extern int cn_k_stats_enabled;
extern struct genl_family stats_table_gnl_family;

int per_flow_stats_update(struct sw_flow_key *key, int length);
int stats_table_search(struct sw_flow_key *key, int length);
void stats_table_initialise(struct sw_flow_key *key, int length);
void cn_get_stats(struct cn_per_flow_stats *per_stats, struct sw_flow_key *key);
void stats_table_new_flow(struct sw_flow_key *key, int length) ;
int stats_table_clear_all(void);
int stats_update_packet_size(struct cn_per_flow_stats *stats, __be16 packet_size);
void free_stats_table(void);
unsigned int packet_length(const struct sk_buff *skb);
int stats_table_cmd_dump(struct sk_buff *skb_2, struct genl_info *info_2);
int stats_table_cmd_enable(struct sk_buff *skb, struct genl_info *info);
int stats_table_cmd_disable(struct sk_buff *skb_2, struct genl_info *info_2);

#endif /* CN_KERNEL_H */
#endif /* K_ENABLE_CN_STATS */
