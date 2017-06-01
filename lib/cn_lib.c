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
/* ~~Notes~~
 * Simple MC Example - https://stackoverflow.com/questions/26265453/netlink-multicast-kernel-group
 * nl_socket_modify_cb - https://www.infradead.org/~tgr/libnl/doc/api/group__socket.html#gaeee66d6edef118209c7e7f1e3d393448
 * genl example - https://wiki.linuxfoundation.org/networking/generic_netlink_howto
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
#include "ofp-msgs.h"
#include "cn_lib.h"
#include "openvswitch/vlog.h"
#include "byte-order.h"

VLOG_DEFINE_THIS_MODULE(cnsg);

static struct nla_policy stats_table_gnl_policy[STAT_TABLE_ATTR_MAX + 1] = {
    [FLOW_STATS] = {.type = NLA_NESTED},
};

int family_id;
int group_id;
int cn_k_ready;
int cn_initialised;

timer_t t_kernel;
timer_t t_controller;

pthread_t cn_lib_rid;
pthread_t cn_lib_sid;
pthread_t cn_lib_ctimer;
pthread_t cn_lib_ktimer;
pthread_t cn_lib_cli_id;

pthread_mutex_t lock_cn_k = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_cn_init = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_cn_queue = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_stats_table = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_o_table = PTHREAD_MUTEX_INITIALIZER;

struct cn_stats_htable **g_hash_table;
struct nl_sock *sk;

/* Statistics gathering program initialiser */
void
cn_user_stats_init(void)
{
    int error = 0;

    /* Kernel module is disabled on startup */
    pthread_mutex_lock(&lock_cn_k);
    cn_k_ready = 0;
    pthread_mutex_unlock(&lock_cn_k);

    /* Initialise statistics queue */
    pthread_mutex_lock(&lock_cn_queue);
    SIMPLEQ_INIT(&cn_stats_queue_head);
    pthread_mutex_unlock(&lock_cn_queue);

    /* Initalise statistics hash table */
    pthread_mutex_lock(&lock_stats_table);
    g_hash_table = cn_stats_htable_init();
    pthread_mutex_unlock(&lock_stats_table);

    /* Create persisting socket */
    error |= pthread_create(&(cn_lib_sid), NULL, &cn_k_nl_sock_init, NULL);
    if (error != 0)
        VLOG_ERR("Error: NL Statistics Socket could not be started\n");
    pthread_join(cn_lib_sid, NULL);

    /* Kernel receiver thread
     * Receiver thread should always be on, to receive messages from the kernel
     * module if necessary */
    error = pthread_create(&(cn_lib_rid), NULL, &cn_k_nl_sock_recv, NULL);
    if (error)
        VLOG_ERR("Error: NL Statistics Receiver could not be started\n");

    pthread_mutex_lock(&lock_cn_init);
    cn_initialised = 1;
    pthread_mutex_unlock(&lock_cn_init);
}

/* Initialise Kernel Statistics Timer to collect statistics from kernel if
 * user-space has not received statistics in a while */
int
cn_k_timer_init(void)
{
    int error;
    /* Periodic kernel dump request thread */
    error = pthread_create(&(cn_lib_ktimer), NULL, &cn_k_timer, NULL);
    if (error != 0) {
        VLOG_ERR("Error: Kernel Timer could not be started\n");
    } else {
        pthread_join(cn_lib_ktimer, NULL);
    }
    return error;
}

/* Initialises the Controller Statistics Timer to send statistics to
 * connected controller */
int
cn_c_timer_init(void)
{
    int error;

    /* Timer Thread */
    error = pthread_create(&(cn_lib_ctimer), NULL, &cn_c_timer, NULL);
    if (error)
        VLOG_ERR("Error: Controller Timer could not be started\n");

    return error;
}

/* Socket using the netlink protocol which listens for STAT_TABLE Multicast
 * packets from the kernel
 * https://stackoverflow.com/questions/26265453/netlink-multicast-kernel-group
 * https://people.redhat.com/nhorman/papers/netlink.pdf
 */
#define NL_SOCKET_BUFFER_SIZE   (1024 * 1024)
#define NL_MSG_BUFFER_SIZE   65536
void
*cn_k_nl_sock_init(void *args)
{
	int err;
    (void) args;

    sk = nl_socket_alloc();			  /* Create Socket */
    genl_connect(sk);                 /* Connect to socket */
    nl_socket_disable_seq_check(sk);  /* Disable sequence number check */
    nl_socket_disable_auto_ack(sk);   /* Disable ACK check */

    err = nl_socket_set_buffer_size(sk, NL_SOCKET_BUFFER_SIZE, NL_SOCKET_BUFFER_SIZE);
    if (err)
        VLOG_ERR("Could not set buffer size\n");
    err = nl_socket_set_msg_buf_size(sk, NL_MSG_BUFFER_SIZE*4); /* Set Socket buffer size */
    if (err)
        VLOG_ERR("Could not set msg buffer size\n");
    nl_socket_enable_msg_peek(sk);


    family_id = genl_ctrl_resolve(sk, STAT_TABLE_FAMILY_NAME);
    group_id = genl_ctrl_resolve_grp(sk, STAT_TABLE_FAMILY_NAME, STAT_TABLE_GROUP);

    if (group_id < 0)
        VLOG_ERR("Could not resolve group\n");

    /* Subscribe to STAT_TABLE_GROUP */
    err = nl_socket_add_memberships(sk, group_id, 0);
    if (err)
        VLOG_ERR("Could not add group membership: %d\n", err);

    pthread_exit(NULL);

    return 0;
}

/* Receives and handles Netlink statistics messages from the kernel and parses
 * the data */
void
*cn_k_nl_sock_recv(void *args)
{
    int err = 0;
    (void) args;
    /* Set reply function for valid messages */
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
                        cn_k_nl_stats_handler, NULL);

    /* Listen for NL messages*/
    for (;;) {
        pthread_mutex_lock(&lock_cn_init);
        if (cn_initialised == 1) {
            pthread_mutex_unlock(&lock_cn_init);

            err = nl_recvmsgs_default(sk);
            if (err == 0) {
                /* Reset Timers if a kernel statistics message is received */
                if (t_kernel)
                    cn_reset_timer(t_kernel, K_DUMP_INTERVAL);
            }
        } else {
            pthread_mutex_unlock(&lock_cn_init);
            pthread_exit(NULL);
            return 0;
        }
    }
    return 0;
}

/* Adds 5-tuple information to the reply message that is bound
 * for the controller */
void
cn_c_reply_append(struct ovs_list *replies, struct cn_flow_stats *cur_stats)
{
    struct netlink_stats_reply *reply;
    reply = (struct netlink_stats_reply *) ofpmp_append(replies, sizeof (*reply));

    cn_c_encode_stats(reply, cur_stats);
}

/* Encode the statistics in network order */
void
cn_c_encode_stats(struct netlink_stats_reply *reply,
                  struct cn_flow_stats *stats)
{
    int i;

#ifdef WORDS_BIGENDIAN
    reply->ipv4.src_ip = htonl(stats->ipv4.src_ip);
    reply->ipv4.dst_ip = htonl(stats->ipv4.dst_ip);
#else
    reply->ipv4.src_ip = htonl(uint32_byteswap(stats->ipv4.src_ip));
    reply->ipv4.dst_ip = htonl(uint32_byteswap(stats->ipv4.dst_ip));
#endif
    reply->ipv4.src_port = htons(stats->ipv4.src_port);
    reply->ipv4.dst_port = htons(stats->ipv4.dst_port);
    reply->ipv4.proto = stats->ipv4.proto;
    reply->pkt_count = ntohl(stats->pkt_cnt);
    reply->pkt_size_max = htons(C_MAX_PKT_CNT);

    for(i = 0; i < C_MAX_PKT_CNT; i++) {
        reply->pkt_size[i] = htons(stats->pkt_size[i]);
    }
}

/* Kernel Netlink message handler */
int
cn_k_nl_stats_handler(struct nl_msg *msg, void * arg)
{
    (void) arg;
    struct nlmsghdr * hdr = nlmsg_hdr(msg);
    struct genlmsghdr * gnlh = nlmsg_data(hdr);
    struct nlattr * attrs[STAT_TABLE_ATTR_MAX + 1];

    if (hdr->nlmsg_type == NLMSG_ERROR) {
        VLOG_ERR("NLMSG_ERROR Received %i\n", hdr->nlmsg_type);
        return NL_SKIP;
    }
    else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
        VLOG_ERR("NLMSG_OVERRUN Occurred %i\n", hdr->nlmsg_type);
        return 0;
    }

    if (hdr->nlmsg_flags == NLM_F_MULTI) {
    	VLOG_ERR("NLM_F_MULTI Received %i\n", hdr->nlmsg_type);
		return 0;
    }
    if (gnlh->cmd != STAT_TABLE_CMD_DUMP) {
        return NL_OK;
    }

    if (genlmsg_parse(hdr, 0, attrs, STAT_TABLE_ATTR_MAX, stats_table_gnl_policy) < 0)
        VLOG_ERR("genlmsg parse error\n");
    else {
        /* Parse and add flow stats to hash table */
        int remaining = genlmsg_attrlen(gnlh, 0);
        struct nlattr *attr = genlmsg_attrdata(gnlh, 0);
        while (nla_ok(attr, remaining)) {
            struct k_flow_stats *k_stats = (struct k_flow_stats *) nla_data(attr);
            if (k_stats != NULL)
                cn_stats_htable_update(g_hash_table, k_stats);
            /* Get next set of flow statistics */
            attr = nla_next(attr, &remaining);
        }
        return NL_OK;
    }
    return NL_SKIP;
}

/* Request statistics from kernel using Netlink protocol */
void
cn_k_nl_dump_request(void)
{

    struct nl_msg *msg;

    /* Check for socket */
    if (sk == NULL) {
        VLOG_ERR("Socket Doesn't Exist\n");
        return;
    }
    /* Allocate memory for request */
    msg = nlmsg_alloc_size(NL_MSG_BUFFER_SIZE);

    /* Request Message for STAT_TABLE_CMD_DUMP */
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
                0,                   /* Hdrlen */
                0,                   /* Flags */
                STAT_TABLE_CMD_DUMP, /* Command */
                STAT_TABLE_VERSION); /* Version */

    /* Send request to the kernel */
    nl_send_auto(sk, msg);

    /* Re-obtain memory from message */
    nlmsg_free(msg);
}

/* Send Disable Statistics request to the kernel module */
void
cn_k_nl_disable_request(void)
{
    struct nl_msg *msg;

    /* Check for socket */
    if (sk == NULL) {
        VLOG_ERR("Socket Doesn't Exist\n");
        return;
    }

    /* Allocate memory for request */
    msg = nlmsg_alloc();

    /* Request Message for DUMP */
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
                0,                      /* Hdrlen */
                0,                      /* Flags */
                STAT_TABLE_CMD_DISABLE, /* Command */
                STAT_TABLE_VERSION);    /* Version */

    /* Send disable message to the kernel */
    nl_send_auto(sk, msg);

    /* Re-obtain memory from message */
    nlmsg_free(msg);
}

/* Send Enable Statistics Request to the kernel module */
void
cn_k_nl_enable_request(void)
{
    struct nl_msg *msg;

    /* Check for socket */
    if (sk == NULL) {
        VLOG_ERR("Socket Doesn't Exist\n");
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
}

/* Starts the statistics hash table dumping thread */
void
cn_stats_htable_init_dump(struct cn_stats_htable **stats_hash_table)
{
    struct stats_queue *new_table;

    new_table = malloc(sizeof(*new_table));
    if (new_table == NULL)
        return;
    new_table->old_htable_stats = stats_hash_table;
    cn_stats_htable_reinit(stats_hash_table);

    pthread_mutex_lock(&lock_cn_queue);
    SIMPLEQ_INSERT_TAIL(&cn_stats_queue_head, new_table, next);
    pthread_mutex_unlock(&lock_cn_queue);

    poll_immediate_wake();

}

/* Create a statistics hash table */
struct
cn_stats_htable **cn_stats_htable_init(void)
{
    struct cn_stats_htable **new_hash_table;

    new_hash_table = malloc(HASH_STATS_LEN * sizeof (struct cn_stats_htable));
    if (new_hash_table == NULL)
        return NULL;
    memset(new_hash_table, 0, HASH_STATS_LEN * sizeof (struct cn_stats_htable));

    return new_hash_table;
}

/* Reinitialise a new statistics hash table, enable old one to be acted upon */
struct
cn_stats_htable **cn_stats_htable_reinit(struct cn_stats_htable **old_hash_table)
{
    /* Replace global table with new one */
    pthread_mutex_lock(&lock_stats_table);
    g_hash_table = cn_stats_htable_init();
    pthread_mutex_unlock(&lock_stats_table);

    return old_hash_table;
}

/* Searches through hash_stats_table to find if 5-tuple exists
 * If there is a match return the hash node containing those statistics
 * else return a NULL */
struct
cn_stats_htable *cn_stats_htable_search(struct cn_stats_htable **stats_hash_table,
                                        struct k_flow_stats *flow_stats)
{
    struct cn_stats_htable *cn_cur;
    int key;

    key = cn_get_hash_key(flow_stats);

    /* Checks if stats in first node */
    if (stats_hash_table[key] == NULL) {
        return NULL;
    }

    cn_cur = stats_hash_table[key];

    /* Search through linked list for 5-tuple match */
    while (cn_cur != NULL) {
        /* First node check */
        if (cn_cur->stats_link == NULL) {
            return NULL;
        }

        int match = cn_flow_stats_compare(cn_cur->stats_link, flow_stats);

        if (match == 0) {
            goto out;
        }
        else {
            /* Check if in end of linked list */
            if (cn_cur->next == NULL) {
                return NULL;
            }
            /* Go to next table otherwise */
            cn_cur = cn_cur->next;
        }
    }

out:
    return cn_cur;
}

/* Kernel timer to request kernelspace statistics */
void
*cn_k_timer(void *args)
{
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

/* Controller timer to enqueue userspace statistics */
void
*cn_c_timer(void *args)
{
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
    cn_stats_htable_init_dump(g_hash_table);
    return;
}

/* Resets the timer */
void
cn_reset_timer(timer_t r_timer_id, int interval)
{
    struct itimerspec its;
    memset(&its, 0, sizeof (struct itimerspec));

    its.it_value.tv_sec = interval;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;

    pthread_mutex_lock(&lock_cn_k);
    if (cn_k_ready == 1) {
        pthread_mutex_unlock(&lock_cn_k);
        if (r_timer_id != NULL) {
            timer_settime(r_timer_id, 0, &its, NULL);
        }
    } else {
        pthread_mutex_unlock(&lock_cn_k);
    }
    return;
}

/* Updates/Inserts statistics into the hash table */
int
cn_stats_htable_update(struct cn_stats_htable **stats_hash_table,
                       struct k_flow_stats *flow_stats)
{
    struct cn_stats_htable *cn_cur;
    int size = 0;

    if (stats_hash_table == NULL)
        return -1;

    if (flow_stats == NULL)
        return -1;

    /* Search for existing stats */
    cn_cur = cn_stats_htable_search(stats_hash_table, flow_stats);

    /* Checks if adding the statistics will exceed the table limit */
    if (cn_cur != NULL) {
        /* Check if flow stats is in hash table */
        /* If match */
        size = cn_cur->stats_link->pkt_cnt;

        if ((size + flow_stats->pkt_cnt) > C_MAX_PKT_CNT) {
            /* Create new hash table, dump and delete old if packet count exceeds C_MAX_PKT_CNT */
            cn_stats_htable_init_dump(stats_hash_table);
            cn_cur = cn_stats_htable_search(g_hash_table, flow_stats);
        }
    }

    /* Updates statistics if match */
    if (cn_cur != NULL) {
        /* Update the array */
        for (int i = 0; i < flow_stats->pkt_cnt; i++) {
            cn_cur->stats_link->pkt_size[size + i] = flow_stats->pkt_list[i];
        }

        /* Update packet_count */
        cn_cur->stats_link->pkt_cnt += flow_stats->pkt_cnt;
        return 0;
    } else {
        /* Insert statistics into hash table for no match */
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
    int key;
    struct cn_flow_stats *cn_new_flow;
    struct cn_stats_htable *cn_new;
    struct cn_stats_htable *cn_head;
    __be16 *packet_list_new;

    key = cn_get_hash_key(k_stats);

    if (stats_hash_table[key] == NULL) {
        /* Create First Node */

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

    } else {
        /* First node exists creating new node */
        cn_head = stats_hash_table[key];

        /* Loop to end of linked list */
        for (;;) {
            /* Check if next node exists */
            if (stats_hash_table[key]->next != NULL) {
                stats_hash_table[key] = stats_hash_table[key]->next;
            } else {

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
cn_stats_htable_delete_global(void)
{
    if (g_hash_table != NULL) {
        pthread_mutex_lock(&lock_stats_table);
        cn_stats_htable_delete_all(g_hash_table);
        pthread_mutex_unlock(&lock_stats_table);
    }
}

/* Deletes all the statistics and nodes in the hash table */
int
cn_stats_htable_delete_all(struct cn_stats_htable **stats_hash_table)
{
    struct cn_stats_htable *cn_cur;
    struct cn_stats_htable *cn_temp;

    if (stats_hash_table == NULL) {
        VLOG_ERR("Error: Cannot find table, table not deleted\n");
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
    if (user_stats->ipv4.src_ip == kernel_stats->ipv4.src_ip
        && user_stats->ipv4.dst_ip == kernel_stats->ipv4.dst_ip
        && user_stats->ipv4.src_port == kernel_stats->ipv4.src_port
        && user_stats->ipv4.dst_port == kernel_stats->ipv4.dst_port
        && user_stats->ipv4.proto == kernel_stats->ipv4.proto) {
        return 0;
    } else {
        return -1;
    }
}

/* Hash function from 5-tuple */
/* TODO: Get better hash function */
/* Current: http://stackoverflow.com/questions/3215232/hash-function-for-src-dest-ip-port */
int
cn_get_hash_key(struct k_flow_stats *flow_stats)
{
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
cb_print_flow(struct cn_flow_stats *flow_stats)
{
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
    } else {
        VLOG_ERR("Bad flow stats Input\n");
    }
}

/* Un-initialise userspace functions */
void
cn_stats_uninit(struct nl_sock * sk)
{
    pthread_mutex_lock(&lock_cn_k);
    cn_k_ready = 0;
    pthread_mutex_unlock(&lock_cn_k);
    pthread_join(cn_lib_rid, NULL);
    pthread_join(cn_lib_ctimer, NULL);
    pthread_join(cn_lib_ktimer, NULL);
    pthread_join(cn_lib_sid, NULL);

    /* Clean Timers */
    if (t_kernel)
        timer_delete(t_kernel);
    if (t_controller)
        timer_delete(t_controller);

    /* Clean Threads */
    pthread_cancel(cn_lib_sid);

    /* Clean Socket */
    nl_close(sk);
    nl_socket_free(sk);

    /* Clean hash table */
    pthread_mutex_lock(&lock_stats_table);
    cn_stats_htable_delete_all(g_hash_table);
    pthread_mutex_unlock(&lock_stats_table);
}
#endif
