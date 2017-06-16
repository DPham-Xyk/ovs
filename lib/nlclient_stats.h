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

#include <config.h>
#include <openflow/openflow.h> 
#include <openflow/nicira-ext.h>

#ifndef NICIRA_CUST
#define NICIRA_CUST

/* Nicira Extension defined messages in order to transmit user-space statistics
 * to connected controllers */
struct netlink_stats_request {
    ovs_be16 flag;
    uint8_t pad[2];           /* Align to 4 byte. */
};
OFP_ASSERT(sizeof(struct netlink_stats_request) == 4);

struct netlink_stats_enable {
    ovs_be16 flag;
    uint8_t pad[2];           /* Align to 4 byte. */
};
OFP_ASSERT(sizeof(struct netlink_stats_enable) == 4);

struct netlink_stats_disable {
    ovs_be16 flag;     
    uint8_t pad[2];           /* Align to 4 byte. */
};
OFP_ASSERT(sizeof(struct netlink_stats_disable) == 4);

struct ofp_exp_enable_req {
    struct ofp_header header;
    ovs_be32 vendor;
    ovs_be32 subtype;
    struct netlink_stats_disable data;
};
OFP_ASSERT(sizeof(struct ofp_exp_enable_req) == 20);

struct netlink_stats_ipv4_reply {
    ovs_be32 src_ip;
    ovs_be32 dst_ip;
    ovs_be16 src_port;
    ovs_be16 dst_port;
    uint8_t proto;
    uint8_t pad[3];
};

struct netlink_stats_reply {
    struct netlink_stats_ipv4_reply ipv4;   /* 16 */
    ovs_be32 pkt_count;                     /* 4 */
    ovs_be16 pkt_size_max;                  /* 2 */
    ovs_be16 pkt_size[5000];                /* 10000 */
    uint8_t pad[2];                         /* 2 */
};
OFP_ASSERT(sizeof(struct netlink_stats_reply) == 10024);

/* Nicira Vendor Message OVS 2.5.0 */

struct cn_ofp11_stats_msg {
    struct ofp_header header;
    ovs_be16 type;              /* One of the OFPST_* constants. */
    ovs_be16 flags;             /* OFPSF_REQ_* flags (none yet defined). */
    uint8_t pad[4];
    /* Followed by the body of the request. */
};

/* Vendor extension stats message. */
struct x_25_vendor_stats_msg {
    struct cn_ofp11_stats_msg osm; /* Type OFPST_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
};
//OFP_ASSERT(sizeof(struct x_25_vendor_stats_msg) == 20);

struct x_25_nicira11_stats_msg {
    struct x_25_vendor_stats_msg vsm; /* Vendor NX_VENDOR_ID. */
    ovs_be32 subtype;            /* Vendor-specific subtype. */
};
//OFP_ASSERT(sizeof(struct x_25_nicira11_stats_msg) == 24);

/* Nicira Vendor Message OVS 2.6.0+ */
/* Vendor extension stats message. */
struct x_26_vendor_stats_msg {
    struct cn_ofp11_stats_msg osm; /* Type OFPST_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
    ovs_be32 subtype;           /* Vendor-specific subtype. */
};
//OFP_ASSERT(sizeof(struct ofp11_vendor_stats_msg) == 24);

#endif /* NICIRA_CUST */

#ifdef ENABLE_CN_STATS
#ifndef NLCLIENT_H
#define NLCLIENT_H

#include <time.h>
#include <sys/queue.h>
#include <syslog.h>
#include <linux/types.h>

#define CN_STATS_DEBUG_MSG 0
#define CN_STATS_INFO_MSG 0
#define CN_STATS_ERROR_MSG 0
#define K_DUMP_INTERVAL 10
#define C_DUMP_INTERVAL 10

/* For use in the User-space */
/* Max size of packet_size array in user-space to send to controller */
#define C_MAX_PKT_CNT 5000 
#define LOG_ENABLE 0
#define LOG_LOCATION "/home/ryu/nlclient.log"

/* Size of hash table */
#ifndef HASH_STATS_LEN
#define HASH_STATS_LEN 7919
#endif

/* Logging commands */
#define NL_SYS_DEBUG(s, ...) \
    do {if (CN_STATS_DEBUG_MSG == 1)\
            syslog(LOG_DEBUG, s, ##__VA_ARGS__); \
    } while(0)

#define NL_SYS_INFO(s, ...) \
    do {if (CN_STATS_INFO_MSG == 1)\
            syslog(LOG_INFO, s, ##__VA_ARGS__); \
    } while(0)

#define NL_SYS_ERR(s, ...) \
    do {if (CN_STATS_ERROR_MSG == 1) \
            syslog(LOG_ERR, s, ##__VA_ARGS__); \
    } while(0)

/* User-space hash table */
struct cn_stats_htable {
    struct cn_flow_stats *stats_link;
    struct cn_stats_htable *prev;
    struct cn_stats_htable *next;
};

struct stats_queue {
    struct cn_stats_htable **old_htable_stats;
    SIMPLEQ_ENTRY(stats_queue) next;
};

#ifndef NLCOMMON_H
#define NLCOMMON_H

/* Generic Netlink (genl) definitions to be able to send data between kernel
 * and user-space */
#define STAT_TABLE_FAMILY_NAME "STAT_TABLE"
#define STAT_TABLE_GROUP "STAT_TABLE"
#define STAT_TABLE_VERSION 1

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

struct cn_flow_stats {
    struct nl_per_ip ipv4;
    __be32 pkt_cnt;
    __be16 *pkt_size;
};

struct per_stats_table {
    struct cn_flow_stats *stats;
    struct per_stats_table *next;
};

/* Netlink Protocol Headers */
struct k_flow_stats {
    struct nl_per_ip ipv4;
    __be32 pkt_cnt;
    __be16 pkt_list[K_MAX_PKT_CNT];
};

struct attr_stat_table {
    struct k_flow_stats *stats;
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
#endif /* NLCOMMON_H */

struct nl_sock;
struct nl_msg;
struct ovs_list;
int cn_k_ready;
int cn_initialised;

/* Classifier Node Main Function */
void cn_user_stats_init(void);
int cn_c_queue_init(void);
struct cn_stats_htable **cn_stats_htable_init(void);
struct cn_stats_htable **cn_stats_htable_reinit(struct cn_stats_htable **stats_hash_table_old);
struct cn_stats_htable *cn_stats_htable_search(struct cn_stats_htable **stats_hash_table, struct k_flow_stats *flow_stats);
struct cn_stats_htable *cn_stats_htable_free_node(struct cn_stats_htable *stats_hash_table, struct cn_flow_stats *flow_stats);
void cn_stats_htable_init_dump(struct cn_stats_htable **hash_table);
void cn_copy_tuple(struct k_flow_stats *k_stats, struct cn_flow_stats *cn_new_flow, 
                   __be16 *packet_list_new);
int cn_stats_htable_update(struct cn_stats_htable **stats_hash_table, struct k_flow_stats *flow_stats);
int cn_stats_htable_insert(struct cn_stats_htable **stats_hash_table, struct k_flow_stats *flow_stats);
int cn_stats_htable_delete_all(struct cn_stats_htable **stats_hash_table);
int cn_flow_stats_compare(struct cn_flow_stats *flow_stats1, struct k_flow_stats *flow_stats2);
int cn_get_hash_key(struct k_flow_stats *flow_stats);
void cb_print_flow(struct cn_flow_stats *flow_stats);
int cn_k_timer_init(void);
int cn_c_timer_init(void);
void *cn_c_timer(void *args);
void *cn_k_timer(void *args);
void cn_timer_user_dump_req(void);
void cn_reset_timer(timer_t timer_id, int interval);
void cn_stats_uninit(struct nl_sock *sk);
void cn_stats_htable_delete_global(void);

/* CN Kernel Functions */
void *cn_k_nl_sock_init(void *args);
void *cn_k_nl_sock_recv(void *args);
void cn_k_nl_dump_request(void);
void cn_k_nl_disable_request(void);
void cn_k_nl_enable_request(void);
int cn_k_nl_stats_handler(struct nl_msg *msg, void *args);

/* CN Controller Functions */
void cn_c_reply_append(struct ovs_list *replies, struct cn_flow_stats *cur_stats);
void cn_c_encode_stats(struct netlink_stats_reply *reply, struct cn_flow_stats *stats);
SIMPLEQ_HEAD(StatsHead, stats_queue) cn_stats_queue_head;
#endif /* NLCLIENT_H */
#endif /* ENABLE_CN_STATS */
