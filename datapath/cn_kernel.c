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
#include <config.h>
#include "datapath.h"
#include "cn_kernel.h"
#include <linux/kernel.h>
#include <linux/openvswitch.h>
#include <linux/genetlink.h>
#include <linux/spinlock.h>

int incoming_packet_count;
int cn_k_stats_enabled;
static DEFINE_SPINLOCK(dump_lock);

#ifdef CNSG_DEBUG
int k_pkt_cnt;
#endif

struct per_stats_table *stats_table;

struct genl_multicast_group stats_table_multicast_group = {
        .name = STAT_TABLE_GROUP,
};

static const struct nla_policy stats_table_gnl_policy[STAT_TABLE_ATTR_MAX + 1] = {
        [FLOW_STATS] = {.type = NLA_NESTED},
};

/*
 * Classifier Node Statistics enable commands
 * - STAT_TABLE_CMD_DUMP
 *   Sends Classifier Node statistics to all connected controllers
 * - STAT_TABLE_CMD_DISABLE
 *   Disables the statistics gathering modules in the kernel and user-space
 * - STAT_TABLE_CMD_ENABLE
 *   Enables the statistics gathering modules in the kernel and user-space
 */
static struct genl_ops stats_table_gnl_ops_echo[] = {
        {.cmd = STAT_TABLE_CMD_DUMP,
         .flags = 0,
         .policy = stats_table_gnl_policy,
         .doit = stats_table_cmd_dump,
        },
        {.cmd = STAT_TABLE_CMD_DISABLE,
         .flags = 0,
         .policy = stats_table_gnl_policy,
         .doit = stats_table_cmd_disable,
        },
        {.cmd = STAT_TABLE_CMD_ENABLE,
         .flags = 0,
         .policy = stats_table_gnl_policy,
         .doit = stats_table_cmd_enable,
        },
};

/* Generic Netlink family group settings */
struct genl_family stats_table_gnl_family = {
        .id = GENL_ID_GENERATE,
        .hdrsize =  0,
        .name = STAT_TABLE_FAMILY_NAME,
        .version = STAT_TABLE_VERSION,
        .maxattr = STAT_TABLE_ATTR_MAX,
        .ops = stats_table_gnl_ops_echo,
        .n_ops = ARRAY_SIZE(stats_table_gnl_ops_echo),
        .mcgrps = &stats_table_multicast_group,
        .n_mcgrps = 1,
};

/* Update and add 5-tuple statistics to the Kernel Statistics Table for each
 * incoming packet */
int per_flow_stats_update(struct sw_flow_key *key, int length)
{
        if(stats_table != NULL) {
            /* Check if any subsequent packets contain an entry in the
             * statistics table. Updates the packet size and packet
             * count if there is a match */
            int found = stats_table_search(key, length);
            if (found == 0) {
                    return 0;
            } else {
                    /* Create a new entry in the statistics table */
                    stats_table_new_flow(key, length);
                    return 0;
            }
        } else {
                /* Initialise the kernel statistics for the first packet */
                stats_table_initialise(key, length);
        }
        return 0;
}

/*
 * - Linear search through Statistics Table for match
 * - Updates the packet count for the corresponding 5-tuple
 * - Initiates the userspace dumping process when packet count >= PACKET_SIZE_LEN
 */
int stats_table_search(struct sw_flow_key *key, int length)
{
        struct per_stats_table *tmp_head;
        struct sk_buff *skb_2 = {0};
        struct genl_info *info = {0};

        if (stats_table->stats == NULL)
            return -1;

        tmp_head = stats_table;

        /* Loop through statistics table and check for 5-tuple match */
        while (stats_table != NULL) {
                if (key->ipv4.addr.src == stats_table->stats->ipv4.src_ip
                    && key->ipv4.addr.dst == stats_table->stats->ipv4.dst_ip
                    && ntohs(key->tp.src) == stats_table->stats->ipv4.src_port
                    && ntohs(key->tp.dst) == stats_table->stats->ipv4.dst_port
                    && key->ip.proto == stats_table->stats->ipv4.proto) {

                        stats_table->stats->pkt_cnt++;
                        incoming_packet_count++;
                        stats_update_packet_size(stats_table->stats, length);

                        /* Send statistics table to user-space when full */
                        if (stats_table->stats->pkt_cnt >= K_MAX_PKT_CNT
                            || incoming_packet_count >= K_MAX_PKT_CNT) {
                                stats_table = tmp_head;
                                stats_table_cmd_dump(skb_2, info);
                                return 0;
                        } else {
                                stats_table = tmp_head;
                                return 0;
                        }
                } else {
                        /* Keep looping through statistics table linked list
                         * until it is empty */
                        if (stats_table->next != NULL) {
                                stats_table = stats_table->next;
                        } else {
                                /* No Match */
                                stats_table = tmp_head;
                                return -1;
                        }
                }
        }
        stats_table = tmp_head;
        return 0;
}

/* Initialises first node in linked list and copies the 5-tuple from key */
void stats_table_initialise(struct sw_flow_key *key, int length)
{
        struct cn_per_flow_stats *new_stats;

        /* Allocate initial memory */
        stats_table = kmalloc(sizeof(*stats_table), GFP_ATOMIC);
        if (stats_table == NULL)
                return;
        new_stats = kzalloc(sizeof(*new_stats), GFP_ATOMIC);
        if (new_stats == NULL) {
                kfree(stats_table);
                return;
        }
        /* Add 5-tuple information, packet count and packet sizes */
        new_stats->pkt_cnt = 1;
        stats_update_packet_size(new_stats, length);
        cn_get_stats(new_stats, key);

        /* Link new entry to Statistics Table */
        stats_table->stats = new_stats;
        stats_table->next = NULL;
}

/* Copies the ovs parsed 5-tuple information into our own format */
void cn_get_stats(struct cn_per_flow_stats *per_stats, struct sw_flow_key *key)
{
        per_stats->ipv4.src_ip = key->ipv4.addr.src;
        per_stats->ipv4.dst_ip = key->ipv4.addr.dst;
        per_stats->ipv4.src_port = ntohs(key->tp.src);
        per_stats->ipv4.dst_port = ntohs(key->tp.dst);
        per_stats->ipv4.proto = key->ip.proto;
}

/* Initialises the new statistic flow entries at the head of the linked list */
void stats_table_new_flow(struct sw_flow_key *key, int length)
{
        struct cn_per_flow_stats *new_stats;
        struct per_stats_table *new_stats_table;

        /* Allocate initial memory */
        new_stats_table = kmalloc(sizeof(*new_stats_table), GFP_ATOMIC);
        if (new_stats_table == NULL)
                return;
        new_stats = kzalloc(sizeof(*new_stats), GFP_ATOMIC);
        if (new_stats == NULL) {
                kfree(new_stats_table);
                return;
        }

        /* Add 5-tuple information, packet count and packet sizes */
        new_stats->pkt_cnt = 1;
        stats_update_packet_size(new_stats, length);
        cn_get_stats(new_stats, key);	/* Copy 5-tuple */

        /* Link new statistics flow to linked list */
        new_stats_table->stats = new_stats;
        if (stats_table !=  NULL)
                new_stats_table->next = stats_table;

        stats_table = new_stats_table;
}

/* Deletes all entries in the statistics table */
int stats_table_clear_all(void)
{
        struct per_stats_table *temp;

        if (stats_table == NULL)
                return -1;

        /* Go through linked list and free everything until final table */
        while (stats_table->next != NULL) {
                temp = stats_table->next;
                if (stats_table != NULL){
                        if (stats_table->stats != NULL) {
                                if (stats_table->stats->pkt_size != NULL)
                                        kfree(stats_table->stats->pkt_size);
                        kfree(stats_table->stats);
                        }
                }
                kfree(stats_table);
                stats_table = temp;
        }

        /* Free the final entry in the statistics table if it exists */
        if (stats_table->stats != NULL) {
                if (stats_table->stats->pkt_size != NULL)
                        kfree(stats_table->stats->pkt_size);
                kfree(stats_table->stats);
        }

        if (stats_table != NULL)
                kfree(stats_table);
        stats_table = NULL;
        return 0;
}

/* Allocates packet-size array for new flows or updates the statistics table */
int stats_update_packet_size(struct cn_per_flow_stats *stats,
                             int length)
{
        int index;

        if (stats->pkt_cnt > K_MAX_PKT_CNT)
                return -1;

        /* Allocate memory for new packet size array */
        if (stats->pkt_size == NULL)
                stats->pkt_size = kzalloc(sizeof(__be16)* K_MAX_PKT_CNT, GFP_ATOMIC);

        /* Assign packet size to array */
        stats->pkt_size[stats->pkt_cnt - 1] = length;
        return 0;
}

/* Gets the length of the packet minus the ethernet frame */
unsigned int packet_length(const struct sk_buff *skb)
{
        unsigned int length = skb->len - ETH_HLEN;

        if (skb->protocol == htons(ETH_P_8021Q))
                length -= VLAN_HLEN;

        return length;
}

/* Frees the last entry in the statistics table */
void free_stats_table(void)
{
        if (stats_table != NULL) {
                if (stats_table->stats != NULL) {
                        if (stats_table->stats->pkt_size != NULL)
                                kfree(stats_table->stats->pkt_size);
                        kfree(stats_table->stats);
                }
                kfree(stats_table);
        }
}

/* Kernel Dumper/Handler for STATS_TABLE_DUMP requests */
int stats_table_cmd_dump(struct sk_buff *skb_2, struct genl_info *info_2)
{
        struct k_per_flow_stats nl_stats;
        struct per_stats_table *temp;
        struct sk_buff *skb;
        void *msg_head;
        int rc = 0;
        int i;

        spin_lock(&dump_lock);
        incoming_packet_count = 0; /* Reset packet count */
        temp = stats_table;

        do {
                if (stats_table == NULL ) {
                        spin_unlock(&dump_lock);
                        return 0;
                }

                if (stats_table->stats == NULL) {
                        spin_unlock(&dump_lock);
                        return 0;
                }

                /* Allocate memory for new Generic Netlink Message*/
                skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);

                if (!skb) {
                        rc = -ENOMEM;
                        pr_info("Ran out of memory for skb");
                        spin_unlock(&dump_lock);
                        return rc;
                }

                /* Copy flow statistics into netlink compatible format */
                nl_stats.ipv4 = stats_table->stats->ipv4;
                nl_stats.pkt_cnt = stats_table->stats->pkt_cnt;
                for (i = 0; i <= 100; i++) {
                                nl_stats.pkt_list[i] = stats_table->stats->pkt_size[i];
                }

                /* Attach genl header */
                msg_head = genlmsg_put(skb, 0, 0, &stats_table_gnl_family, 0,
                                       STAT_TABLE_CMD_DUMP);

                if (!msg_head) {
                        rc = -ENOMEM;
                        goto error;
                }

                /* Put statistics into the genl message */
                rc = nla_put(skb, FLOW_STATS, sizeof(struct k_per_flow_stats),
                             &nl_stats);
                if (rc < 0) {
                        pr_info("Not enough space in skb");
                        rc = -ENOMEM;
                        goto error;
                }

                genlmsg_end(skb, msg_head);

                /* Multicast netlink message to userspace */
                genlmsg_multicast_allns(&stats_table_gnl_family,
                                        skb,
                                        0,
                                        GROUP_ID(&stats_table_multicast_group),
                                        GFP_ATOMIC);

                /* Clean up current statistics flow entry and grab the next one */
                if (stats_table->next != NULL) {
                        temp = stats_table->next;
                        free_stats_table();
                        stats_table = temp;
                        rc = 0;
                        temp = NULL;
                } else {
                        free_stats_table();
                        stats_table = NULL;
                        spin_unlock(&dump_lock);
                        return rc;
                }

        } while(stats_table);
        goto end;

error:
        pr_info("An error occured while dumping\n");
        kfree_skb(skb);
        spin_unlock(&dump_lock);
        return rc;
end:
        spin_unlock(&dump_lock);
        stats_table = temp;
        return rc;
}

/* Enables capturing statistics of incoming packets and sends current
 * statistics table to userspace */
int stats_table_cmd_enable(struct sk_buff *skb, struct genl_info *info)
{
        if (cn_k_stats_enabled == 1)
                pr_info("Kernel Stats Already Enabled\n");
        else {
                cn_k_stats_enabled = 1;
                pr_info("Kernel Stats Gathering Enabled\n");
        }
        return 0;
}

/* Disables capturing statistics of incoming packets and sends current
 * statistics table to userspace */
int stats_table_cmd_disable(struct sk_buff *skb_2, struct genl_info *info_2)
{
        int rc = 0;
        int err;

        if (cn_k_stats_enabled == 0) {
                pr_info("Kernel Stats Already Disabled\n");
                return 0;
        }
        else {
				cn_k_stats_enabled = 0;
				pr_info("Kernel Stats Gathering Disabled\n");
        }

        rcu_read_lock();
        /* Send currently captured statistics to userspace */
        err = stats_table_cmd_dump(skb_2, info_2);
        rcu_read_unlock();
        return err;
}
#endif /* K_ENABLE_CN_STATS */
