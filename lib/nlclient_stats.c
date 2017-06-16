/* ~~Notes~~
 * Simple MC Example - https://stackoverflow.com/questions/26265453/netlink-multicast-kernel-group
 * nl_socket_modify_cb - https://www.infradead.org/~tgr/libnl/doc/api/group__socket.html#gaeee66d6edef118209c7e7f1e3d393448
 * genl example - https://wiki.linuxfoundation.org/networking/generic_netlink_howto
 */
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
#ifdef ENABLE_CN_STATS
#include <ovs-thread.h>
#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/kernel.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <poll-loop.h>
#include <sys/queue.h>
#include "nlclient_stats.h"

static struct nla_policy stats_table_gnl_policy[STAT_TABLE_ATTR_MAX + 1] = {
    [FLOW_STATS] = {.type = NLA_NESTED},
};

int family_id;
int group_id;
int cn_k_ready;
int cn_initialised;
timer_t t_kernel;
timer_t t_controller;
pthread_t nlclient_rid;
pthread_t nlclient_sid;
pthread_t nlclient_ctimer;
pthread_t nlclient_ktimer;
pthread_t nlclient_cli_id;
pthread_mutex_t lock_clock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_stats_table = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_old_stats_table = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_clock = PTHREAD_COND_INITIALIZER;
struct cn_stats_htable **g_hash_table;
struct nl_sock *sk;

/* CN User-space statistics gathering initialiser */
void
cn_user_stats_init(void)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    int error = 0;

    cn_k_ready = 0;

    SIMPLEQ_INIT(&cn_stats_queue_head);

    /* Initiate Statistics Hash Table */
    pthread_mutex_lock(&lock_stats_table);
    g_hash_table = cn_stats_htable_init();
    pthread_mutex_unlock(&lock_stats_table);

    /* Create persisting socket */
    error |= pthread_create(&(nlclient_sid), NULL, &cn_k_nl_sock_init, NULL);
    if (error != 0)
        NL_SYS_ERR("Error: NL Statistics Socket could not be started\n");
    else
        NL_SYS_INFO("Initialising NL Statistics Socket thread\n");
    pthread_join(nlclient_sid, NULL);

    /* Kernel receiver thread
     * Receiver thread should always be on, to receive messages from the kernel
     * module if necessary */
    error |= pthread_create(&(nlclient_rid), NULL, &cn_k_nl_sock_recv, NULL);
    if (error != 0)
        NL_SYS_ERR("Error: NL Statistics Receiver could not be started\n");
    else
        NL_SYS_INFO("Initialising NL Statistics Receiver thread\n");
    
    cn_initialised = 1;
}

/* Initialise Kernel Statistics Timer to collect statistics from kernel if 
 * user-space has not received statistics in a while */
int 
cn_k_timer_init(void)
{
    int error;
    /* Periodic kernel dump request thread */
    error = pthread_create(&(nlclient_ktimer), NULL, &cn_k_timer, NULL);
    if (error != 0) {
        NL_SYS_ERR("Error: Kernel Timer could not be started\n");
    } else {
        NL_SYS_INFO("Initialising Kernel Timer thread\n");
        pthread_join(nlclient_ktimer, NULL);
    }
    return error;
}

/* Initialises the Controller Statistics Timer to attempt to send statistics to
 * connected controller */ 
int
cn_c_timer_init(void)
{
    int error;

    /* Timer Thread */
    error = pthread_create(&(nlclient_ctimer), NULL, &cn_c_timer, NULL);
    if (error) {
        NL_SYS_ERR("Error: Controller Timer could not be started\n");
    } else {
        NL_SYS_INFO("Initialising Controller Timer thread\n");
    }

    return error;
}

/* Socket using the netlink protocol which listens for STAT_TABLE Multicast 
 * packets from the kernel
 * https://stackoverflow.com/questions/26265453/netlink-multicast-kernel-group
 * https://people.redhat.com/nhorman/papers/netlink.pdf
 */
void
*cn_k_nl_sock_init(void *args)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    int err;
    (void) args;
    /* Create Socket */
    sk = nl_socket_alloc();
    nl_socket_disable_seq_check(sk);  /* Disable sequence number check */
    nl_socket_disable_auto_ack(sk);   /* Disable ACK check */
    nl_socket_set_nonblocking(sk);    /* Enable Non-Blocking Socket */
    nl_socket_set_buffer_size(sk, 65536, 65536); /* Set Socket buffer size */
    genl_connect(sk);                 /* Connect to socket */

    family_id = genl_ctrl_resolve(sk, STAT_TABLE_FAMILY_NAME);
    group_id = genl_ctrl_resolve_grp(sk, STAT_TABLE_FAMILY_NAME, STAT_TABLE_GROUP);

    if (group_id < 0)
        NL_SYS_ERR("Could not resolve group\n");

    /* Subscribe to STAT_TABLE_GROUP */
    err = nl_socket_add_memberships(sk, group_id, 0);
    if (err)
        NL_SYS_ERR("Could not add group membership: %d\n", err);
    else
        NL_SYS_INFO("Socket creation successful\n");

    pthread_exit(NULL);

    return 0;
}

/* Receives and handles Netlink statistics messages from the kernel and parses
 * the data */
void
*cn_k_nl_sock_recv(void *args)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    int err = 0;
    (void) args;
    /* Set reply function for valid messages */
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
                        cn_k_nl_stats_handler, NULL);

    /* Listen for NL messages*/
    for (;;) {
        if (cn_initialised == 1) {
            NL_SYS_DEBUG("Waiting for NL Kernel Message\n");
            err = nl_recvmsgs_default(sk);
            if (err == 0) {
                /* Reset Timers if a kernel statistics message is received */
                if (t_kernel)
                    cn_reset_timer(t_kernel, K_DUMP_INTERVAL);
                NL_SYS_DEBUG("NL Kernel Message successfully parsed\n");
            }
        } else {
            pthread_exit(NULL);
            return 0;
        }
    }
    return 0;
}

/* Adds the 5-tuple information to the reply message bound for the controller */
void
cn_c_reply_append(struct ovs_list *replies, struct cn_flow_stats *cur_stats)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct netlink_stats_reply *reply = ofpmp_append(replies, sizeof (*reply));

    cn_c_encode_stats(reply, cur_stats);
}

/* Encode the statistics in network order */
void
cn_c_encode_stats(struct netlink_stats_reply *reply,
                     struct cn_flow_stats *stats)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    int i;

    reply->ipv4.src_ip = htonl(stats->ipv4.src_ip);
    reply->ipv4.dst_ip = htonl(stats->ipv4.dst_ip);
    reply->ipv4.src_port = htons(stats->ipv4.src_port);
    reply->ipv4.dst_port = htons(stats->ipv4.dst_port);
    reply->ipv4.proto = stats->ipv4.proto;
    reply->pkt_count = ntohl(stats->pkt_cnt);
    reply->pkt_size_max = htons(C_MAX_PKT_CNT);

    for(i = 0; i < C_MAX_PKT_CNT; i++) {
        reply->pkt_size[i] = htons(stats->pkt_size[i]);
    }
}

/* Kernel NL Message Handler */
int
cn_k_nl_stats_handler(struct nl_msg *msg, void * arg)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    
    (void) arg;
    struct nlmsghdr * hdr = nlmsg_hdr(msg);
    struct genlmsghdr * gnlh = nlmsg_data(hdr);
    struct nlattr * attrs[STAT_TABLE_ATTR_MAX + 1];
    int valid = genlmsg_validate(hdr, 0, STAT_TABLE_ATTR_MAX, stats_table_gnl_policy);

    NL_SYS_DEBUG("Valid Message Received %d %s\n", valid, valid ? "ERROR" : "OK");

    if (hdr->nlmsg_type == 2) {
        NL_SYS_ERR("Error Message Received %i\n", hdr->nlmsg_type);
        return -1;
    }

    if (gnlh->cmd != STAT_TABLE_CMD_DUMP) {
        NL_SYS_ERR("Message received is not STAT_TABLE_CMD_DUMP; ignoring. %i\n", gnlh->cmd);
        return -2;
    }

    if (genlmsg_parse(hdr, 0, attrs, STAT_TABLE_ATTR_MAX, stats_table_gnl_policy) < 0)
        NL_SYS_ERR("genlmsg parse error\n");
    else {
        /* Parse and add flow stats to hash table */
        int remaining = genlmsg_attrlen(gnlh, 0);
        struct nlattr *attr = genlmsg_attrdata(gnlh, 0);
        while (nla_ok(attr, remaining)) {
            NL_SYS_DEBUG("remaining %d\n", remaining);
            NL_SYS_DEBUG("attr @ %p\n", attr);

            struct k_flow_stats *k_stats = (struct k_flow_stats *) nla_data(attr);
            if (k_stats != NULL)
                cn_stats_htable_update(g_hash_table, k_stats);
            /* Get next set of flow statistics */
            attr = nla_next(attr, &remaining);
        }
    }
    return NL_STOP;
}

/* Request statistics from kernel using Netlink protocol */
void
cn_k_nl_dump_request(void)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct nl_msg *msg;

    /* Check for socket */
    if (sk == NULL) {
        NL_SYS_ERR("Socket Doesn't Exist\n");
        return;
    }
    /* Allocate memory for request */
    msg = nlmsg_alloc();

    /* Request Message for STAT_TABLE_CMD_DUMP */
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
                0,                   /* hdrlen */
                0,                   /* flags */
                STAT_TABLE_CMD_DUMP, /* numeric command identifier */
                STAT_TABLE_VERSION); /* interface version */

    /* Send request to the kernel */
    nl_send_auto(sk, msg);

    /* Re-obtain memory from message */
    nlmsg_free(msg);
    NL_SYS_INFO("Requesting Stats from Kernel\n");
}

/* Send Disable Statistics request to the kernel module */
void
cn_k_nl_disable_request(void)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct nl_msg *msg;

    /* Check for socket */
    if (sk == NULL) {
        NL_SYS_ERR("Socket Doesn't Exist\n");
        return;
    }

    /* Allocate memory for request */
    msg = nlmsg_alloc();

    /* Request Message for DUMP */
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
                0,                      /* hdrlen */
                0,                      /* flags */
                STAT_TABLE_CMD_DISABLE, /* numeric command identifier */
                STAT_TABLE_VERSION);    /* interface version */
    
    /* Send disable message to the kernel */
    nl_send_auto(sk, msg);

    /* Re-obtain memory from message */
    nlmsg_free(msg);
    NL_SYS_INFO("Requesting to Disable Packet Capture in kernel\n");
}

/* Send Enable Statistics Request to the kernel module */
void
cn_k_nl_enable_request(void)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct nl_msg *msg;

    /* Check for socket */
    if (sk == NULL) {
        NL_SYS_ERR("Socket Doesn't Exist\n");
        return;
    }

    /* Allocate memory for request */
    msg = nlmsg_alloc();

    /* Request Message for DUMP */
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
                0,                      /* hdrlen */
                0,                      /* flags */
                STAT_TABLE_CMD_ENABLE,  /* numeric command identifier */
                STAT_TABLE_VERSION);    /* interface version */

    /* Send enable message to the kernel */
    nl_send_auto(sk, msg);

    /* Free sent message */
    nlmsg_free(msg);
    NL_SYS_INFO("Requesting to Disable Packet Capture in kernel\n");
}

/* Starts the statistics hash table dumping thread */
void 
cn_stats_htable_init_dump(struct cn_stats_htable **stats_hash_table) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct stats_queue *new_table;
    
    new_table = malloc(sizeof(*new_table));
    if (new_table == NULL)
        return;
    new_table->old_htable_stats = stats_hash_table;
    cn_stats_htable_reinit(stats_hash_table);

    SIMPLEQ_INSERT_TAIL(&cn_stats_queue_head, new_table, next);

    poll_immediate_wake();

}

/* Create a statistics hash table */
struct 
cn_stats_htable **cn_stats_htable_init(void) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct cn_stats_htable **new_hash_table;

    new_hash_table = malloc(HASH_STATS_LEN * sizeof (struct cn_stats_htable));
    if (new_hash_table == NULL)
        return NULL;
    memset(new_hash_table, 0, HASH_STATS_LEN * sizeof (struct cn_stats_htable));

    return new_hash_table;
}

/* Reinitialise a new statistics hash table, enabling the old one to be acted upon */
struct 
cn_stats_htable **cn_stats_htable_reinit(struct cn_stats_htable **old_hash_table) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);

    /* Replace global table with new one */
    pthread_mutex_lock(&lock_stats_table);
    g_hash_table = cn_stats_htable_init();
    pthread_mutex_unlock(&lock_stats_table);

    return old_hash_table;
}

/* Searches through hash_stats_table to find if 5-tuple exists
 * If there is a match return the hash node containing those statistics
 * else return a NULL
 */
struct 
cn_stats_htable *cn_stats_htable_search(struct cn_stats_htable **stats_hash_table, 
                                        struct k_flow_stats *flow_stats) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct cn_stats_htable *cn_cur;
    int key;

    key = cn_get_hash_key(flow_stats);

    /* Checks if stats in first node */
    if (stats_hash_table[key] == NULL) {
        NL_SYS_DEBUG("Not in hash table\n");
        return NULL;
    }

    cn_cur = stats_hash_table[key];

    /* Search through linked list for 5-tuple match */
    while (cn_cur != NULL) {
        /* First node check */
        if (cn_cur->stats_link == NULL) {
            NL_SYS_DEBUG("First node stats link is NULL\n");
            return NULL;
        }

        int match = cn_flow_stats_compare(cn_cur->stats_link, flow_stats);

        if (match == 0) {
            NL_SYS_DEBUG("Found match\n");
            goto out;
        }
        else {
            /* Check if in end of linked list */
            if (cn_cur->next == NULL) {
                NL_SYS_DEBUG("No more tables to loop through\n");
                return NULL;
            }
            /* Go to next table otherwise */
            cn_cur = cn_cur->next;
        }
    }

out:
    return cn_cur;
}

/* Timer for flow statistics requests to kernel */
void
*cn_k_timer(void *args)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct itimerspec its;
    struct sigevent sev;
    (void) args;
    
    memset(&its, 0, sizeof (struct itimerspec));
    memset(&sev, 0, sizeof (struct sigevent));

    its.it_value.tv_sec = K_DUMP_INTERVAL;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = (void *) cn_k_nl_dump_request;

    timer_create(CLOCK_MONOTONIC, &sev, &t_kernel);
    timer_settime(t_kernel, 0, &its, NULL);
    pthread_exit(NULL);
}

/* Timer for hash table sending to user-space */
void
*cn_c_timer(void *args)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct itimerspec its;
    struct sigevent sev;
    (void) args;
    
    memset(&its, 0, sizeof (struct itimerspec));
    memset(&sev, 0, sizeof (struct sigevent));

    its.it_value.tv_sec = C_DUMP_INTERVAL;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = (void *) cn_timer_user_dump_req;

    timer_create(CLOCK_MONOTONIC, &sev, &t_controller);
    timer_settime(t_controller, 0, &its, NULL);
    pthread_exit(NULL);
}

void
cn_timer_user_dump_req(void)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    cn_stats_htable_init_dump(g_hash_table);
    return;
}

/* Resets the timer */
void
cn_reset_timer(timer_t r_timer_id, int interval)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct itimerspec its;
    memset(&its, 0, sizeof (struct itimerspec));

    its.it_value.tv_sec = interval;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;

    if (cn_k_ready == 1) {
        if (r_timer_id != NULL) {
            timer_settime(r_timer_id, 0, &its, NULL);
        }
    }
    return;
}

/* Updates/Inserts statistics into the hash table */
int 
cn_stats_htable_update(struct cn_stats_htable **stats_hash_table, 
                       struct k_flow_stats *flow_stats) 
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct cn_stats_htable *cn_cur;
    int size = 0;

    /* Search for existing stats */
    if (stats_hash_table == NULL)
        return -1;

    if (flow_stats == NULL)
        return -1;

    cn_cur = cn_stats_htable_search(stats_hash_table, flow_stats);

    /* Checks if adding the statistics will exceed the table limit */
    if (cn_cur != NULL) {
        /* Check if flow stats is in hash table */
        /* If match */
        size = cn_cur->stats_link->pkt_cnt;

        if ((size + flow_stats->pkt_cnt) > C_MAX_PKT_CNT) {
            /* Create new hash table, dump and delete old if packet count exceeds TBL_SIZE_LEN */
            cn_stats_htable_init_dump(stats_hash_table);
            cn_cur = cn_stats_htable_search(g_hash_table, flow_stats);
        }
    }

    /* Updates statistics if match */
    if (cn_cur != NULL) {
        /* Update the array */
        for (int i = 0; i < flow_stats->pkt_cnt; i++) {
            NL_SYS_DEBUG("Size: %i\n", size);
            cn_cur->stats_link->pkt_size[size + i] = flow_stats->pkt_list[i];
        }

        /* Update packet_count */
        cn_cur->stats_link->pkt_cnt += flow_stats->pkt_cnt;
        return 0;
    } else {
        /* Insert statistics into hash table for no match */
        NL_SYS_DEBUG("Inserting stats into table\n");
        int err = cn_stats_htable_insert(g_hash_table, flow_stats);
        return err;
    }
}

/* Copy Kernel 5-tuple data and packet sizes to user-space flow */
void 
cn_copy_tuple(struct k_flow_stats* k_stats, struct cn_flow_stats* cn_new_flow, 
              __be16* packet_list_new)
{
    cn_new_flow->pkt_cnt = k_stats->pkt_cnt;
    memcpy(packet_list_new, k_stats->pkt_list, sizeof (__be16) * K_MAX_PKT_CNT);
    cn_new_flow->ipv4.src_ip = k_stats->ipv4.src_ip;
    cn_new_flow->ipv4.dst_ip = k_stats->ipv4.dst_ip;
    cn_new_flow->ipv4.src_port = k_stats->ipv4.src_port;
    cn_new_flow->ipv4.dst_port = k_stats->ipv4.dst_port;
    cn_new_flow->ipv4.proto = k_stats->ipv4.proto;
}

/* Adds the 5-tuple statistics to the hash table using the hashing function, if
 * a statistics already exists, add linked the statistics by linked list for 
 * the new flow rules */
int 
cn_stats_htable_insert(struct cn_stats_htable **stats_hash_table, 
                       struct k_flow_stats *k_stats) 
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    int key;
    struct cn_flow_stats *cn_new_flow;
    struct cn_stats_htable *cn_new;
    struct cn_stats_htable *cn_head;
    __be16 *packet_list_new;

    key = cn_get_hash_key(k_stats);

    if (stats_hash_table[key] == NULL) {
        /* Create First Node */
        NL_SYS_DEBUG("Key not found in table\n");

        /* Allocate */
        cn_new = malloc(sizeof (*cn_new));
        if (cn_new == NULL)
            return -1;

        cn_new_flow = malloc(sizeof (*cn_new_flow));
        if (cn_new_flow == NULL) {
            free(cn_new);
            return -1;
        }

        packet_list_new = (__be16 *) calloc(C_MAX_PKT_CNT, sizeof (__be16));
        if (packet_list_new == NULL) {
            free(cn_new);
            free(cn_new_flow);
            return -1;
        }

        /* Copy stats */
        cn_copy_tuple(k_stats, cn_new_flow, packet_list_new);

        /* Link nodes */
        cn_new_flow->pkt_size = packet_list_new;
        cn_new->stats_link = cn_new_flow;
        cn_new->next = NULL;
        cn_new->prev = NULL;
        stats_hash_table[key] = cn_new;

        /* Debug */
        NL_SYS_DEBUG("Node created\n");
    } else {
        NL_SYS_DEBUG("First Node Exists\n");
        /* First node exists creating new node */
        cn_head = stats_hash_table[key];

        /* Loop to end of linked list */
        for (;;) {
            /* Check if next node exists */
            if (stats_hash_table[key]->next != NULL) {
                stats_hash_table[key] = stats_hash_table[key]->next;
                NL_SYS_DEBUG("Going to next table\n");
            } else {
                NL_SYS_DEBUG("In last table\n");

                cn_new = malloc(sizeof (*cn_new));
                if (cn_new == NULL)
                    return -1;
                
                cn_new_flow = malloc(sizeof (*cn_new_flow));
                if (cn_new_flow == NULL) {
                    free(cn_new);
                    return -1;
                }
                
                packet_list_new = (__be16 *) calloc(C_MAX_PKT_CNT, sizeof (__be16));
                if (packet_list_new == NULL) {
                    free(cn_new);
                    free(cn_new_flow);
                    return -1;
                }

                /* Copy stats */
                cn_copy_tuple(k_stats, cn_new_flow, packet_list_new);

                /* Link the data */
                cn_new_flow->pkt_size = packet_list_new;
                cn_new->prev = stats_hash_table[key];
                cn_new->next = NULL;
                cn_new->stats_link = cn_new_flow;

                /* Link statistics to hash table */
                stats_hash_table[key]->next = cn_new;

                /* Return header */
                stats_hash_table[key] = cn_head;
            }
        }
    }
    return 0;
}

/* Delete the current statistics hash_table in use */
void 
cn_stats_htable_delete_global(void) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    
    if (g_hash_table != NULL) {
        pthread_mutex_lock(&lock_stats_table);
        cn_stats_htable_delete_all(g_hash_table);
        pthread_mutex_unlock(&lock_stats_table);
    }
}

/* Deletes all the statistics and nodes in the hash table */
int 
cn_stats_htable_delete_all(struct cn_stats_htable **stats_hash_table) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct cn_stats_htable *cn_cur;
    struct cn_stats_htable *cn_temp;

    if (stats_hash_table == NULL) {
        NL_SYS_ERR("Error: Cannot find table, table not deleted\n");
        return -1;
    }

    for (int i = 0; i < HASH_STATS_LEN - 1; i++) {
        cn_temp = stats_hash_table[i];
        if (cn_temp != NULL) {
            if (cn_temp->next != NULL) {
                while (cn_temp->next != NULL) {
                    cn_cur = cn_temp;
                    if (cn_temp->stats_link != NULL) {
                        free(cn_temp->stats_link->pkt_size);
                        free(cn_temp->stats_link);
                    }
                    cn_temp = cn_cur->next;
                }
            } else {
                if (cn_temp->next == NULL) {
                    if (cn_temp->stats_link != NULL) {
                        free(cn_temp->stats_link->pkt_size);
                        free(cn_temp->stats_link);
                    }
                    if (cn_temp != NULL) {
                        free(cn_temp);
                    }
                }
            }
            stats_hash_table[i] = NULL;
        }
    }
    free(stats_hash_table);
    stats_hash_table = NULL;
    return 0;
}

/* Checks if two 5-tuple flows are the same */
int cn_flow_stats_compare(struct cn_flow_stats *user_stats, 
                          struct k_flow_stats *kernel_stats) 
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);

    if (user_stats->ipv4.src_ip == kernel_stats->ipv4.src_ip
        && user_stats->ipv4.dst_ip == kernel_stats->ipv4.dst_ip
        && user_stats->ipv4.src_port == kernel_stats->ipv4.src_port
        && user_stats->ipv4.dst_port == kernel_stats->ipv4.dst_port
        && user_stats->ipv4.proto == kernel_stats->ipv4.proto) {
        NL_SYS_DEBUG("Match\n");
        return 0;
    } else {
        NL_SYS_DEBUG("No Match\n");
        return -1;
    }
}

/* Hash function from 5-tuple */
/* TODO: Get better hash function */
/* Current: http://stackoverflow.com/questions/3215232/hash-function-for-src-dest-ip-port */
int
cn_get_hash_key(struct k_flow_stats *flow_stats)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    int key = 0;

    if (flow_stats != NULL) {
        key = ((size_t) (flow_stats->ipv4.src_ip) * 59)
               ^ ((size_t) (flow_stats->ipv4.dst_ip))
               ^ ((size_t) (flow_stats->ipv4.src_port) << 16)
               ^ ((size_t) (flow_stats->ipv4.dst_port))
               ^ ((size_t) (flow_stats->ipv4.proto));

        key %= 7919;
    }
    return abs(key);
}

/* Prints and logs the 5-tuple flow stats */
void 
cb_print_flow(struct cn_flow_stats *flow_stats) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    char s_srcip[INET_ADDRSTRLEN];
    char s_dstip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(flow_stats->ipv4.src_ip), s_srcip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(flow_stats->ipv4.dst_ip), s_dstip, INET_ADDRSTRLEN);

    if (flow_stats != NULL) {
        if (LOG_ENABLE == 1) {
            FILE *fp = fopen(LOG_LOCATION, "a+");
            fprintf(fp, "PC:%-5u |PS:%-8p |SIP:%-8s |DIP:%-8s |SP:%-6u |DP:%-6u |P:%-i \n",
                    flow_stats->pkt_cnt,
                    flow_stats->pkt_size,
                    s_srcip,
                    s_dstip,
                    flow_stats->ipv4.src_port,
                    flow_stats->ipv4.dst_port,
                    flow_stats->ipv4.proto);
            fclose(fp);
        }

        NL_SYS_DEBUG("PC:%-5u |PS:%-8p |SIP:%-i |DIP:%-i |SP:%-6u |DP:%-6u |P:%-i \n",
                     flow_stats->pkt_cnt,
                     flow_stats->pkt_size,
                     flow_stats->ipv4.src_ip,
                     flow_stats->ipv4.dst_ip,
                     flow_stats->ipv4.src_port,
                     flow_stats->ipv4.dst_port,
                     flow_stats->ipv4.proto);
    } else {
        NL_SYS_ERR("Bad flow stats Input\n");
    }
}

/* Un-initialise user-space functions */
void
cn_stats_uninit(struct nl_sock * sk)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);

    cn_k_ready = 0;

    pthread_join(nlclient_rid, NULL);
    pthread_join(nlclient_ctimer, NULL);
    pthread_join(nlclient_ktimer, NULL);
    pthread_join(nlclient_sid, NULL);

    /* Clean Timers */
    if (t_kernel)
        timer_delete(t_kernel);
    if (t_controller)
        timer_delete(t_controller);

    /* Clean Threads */
    pthread_cancel(nlclient_sid);

    /* Clean Socket */
    nl_close(sk);
    nl_socket_free(sk);

    /* Clean hash table */
    pthread_mutex_lock(&lock_stats_table);
    cn_stats_htable_delete_all(g_hash_table);
    pthread_mutex_unlock(&lock_stats_table);

    NL_SYS_INFO("EXITED!\n");
}
#endif
