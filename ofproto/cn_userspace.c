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

#include "ofproto/ofproto.h"
#include "ofproto/connmgr.h"
#include "ofproto/cn_userspace.h"
#include "ofp-msgs.h"
#include "nlclient_stats.h"

/* If a Statistics Disable message is received from controller, dump current
 * table to the controller, disable user-space statistics gathering 
 * functionality, and send a kernel statistics disable message */
enum ofperr
handle_nxt_netlink_disable(void) 
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    NL_SYS_INFO("Got disable message");
    
    /* Check if cn stats is already disabled */
    if (cn_k_ready == 0 || nl_c_enable == 0)
        return 0;
    
    cn_k_ready = 0;
    nl_c_enable = 0;
    
    cn_stats_htable_init_dump(g_hash_table);
    
    NL_SYS_INFO("Turning off timers and reinit table");
    /* Clean Timers */
    timer_delete(t_kernel);
    timer_delete(t_controller);

    cn_k_nl_disable_request();

    return 0;
}

/* If a Statistics Enable message is received from the controller, enable 
 * user-space statistics gathering functionality and send a kernel statistics
 * capture message to the kernel */
enum ofperr
handle_nxt_netlink_enable(void) 
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);    
    NL_SYS_INFO("Got enable message");

    /* Check if cn stats is already disabled */
    if (cn_k_ready == 1 && nl_c_enable == 1)
        return 0;
    
    cn_k_nl_enable_request();
    
    /* Initiate Stats Hash Table */
    if (g_hash_table)
        cn_stats_htable_init_dump(g_hash_table);
    else
        g_hash_table = cn_stats_htable_init();
    
    /* Clean Timers */
    cn_k_timer_init();
    cn_c_timer_init();
    
    cn_k_ready = 1;
    nl_c_enable = 1;
    return 0;
}

/* If a Statistics Request message is received from the controller, send 
 * current statistics to the controller */
enum ofperr
handle_nxst_netlink_request(struct ofconn *ofconn,
                            const struct ofp_header *request)
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct ovs_list replies;
    enum ofperr error;
    struct cn_stats_htable **old_hash_table;
    NL_SYS_DEBUG("Version: %i Type: %i Length: %d xid:%u",
                                            request->version,
                                            request->type,
                                            ntohs(request->length),
                                            request->xid);
    
    /* Reply to the Stats request message from the controller */
    ofpmp_init(&replies, request);
    old_hash_table = cn_stats_htable_reinit(g_hash_table);

    nxst_stats_hdr->xid = 0; // Future messages don't require a transaction ID
    error = send_cn_stats(ofconn, &replies, old_hash_table);
    
    if (old_hash_table != NULL) {
        cn_stats_htable_delete_all(old_hash_table);
        free(old_hash_table);
        old_hash_table = NULL;    
    }
    return error;
}

//#define OVS_VER_BRANCH(code1, code2)
//if (strcmp(VERSION, <2.5)) {print error} else if strcmp(VERSION=2.5) {code1} else {code2}
/* Initialise the header for the openflow experimenter message for OVS 2.5.0 */
void 
nxst_stats_msg_init(void) 
{
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    /* Hold an example exp vendor stats message for future push to controller messages */
    if (!nxst_stats_hdr) {
        if (!strcmp(VERSION,"2.6.0")) { 
            struct x_26_vendor_stats_msg *nxst_stats_msg;
            nxst_stats_hdr = (struct ofp_header *) malloc(sizeof(struct x_26_vendor_stats_msg));
            nxst_stats_msg = (struct x_26_vendor_stats_msg *) nxst_stats_hdr;

            nxst_stats_msg->osm.header.version = 4;
            nxst_stats_msg->osm.header.type = 18;
            nxst_stats_msg->osm.header.length = htons(28);
            nxst_stats_msg->osm.header.xid = 0;
            nxst_stats_msg->osm.type = htons(0xFFFF);
            nxst_stats_msg->osm.flags = 0;
            nxst_stats_msg->vendor = htonl(NX_VENDOR_ID);
            nxst_stats_msg->subtype = htonl(50);
        }
        else if (!strcmp(VERSION,"2.5.0")) {
            struct x_25_nicira11_stats_msg *nxst_stats_msg;
            nxst_stats_hdr = (struct ofp_header *) malloc(sizeof(struct x_25_nicira11_stats_msg));
            nxst_stats_msg = (struct x_25_nicira11_stats_msg *) nxst_stats_hdr;

            nxst_stats_msg->vsm.osm.header.version = 4;
            nxst_stats_msg->vsm.osm.header.type = 18;
            nxst_stats_msg->vsm.osm.header.length = htons(28);
            nxst_stats_msg->vsm.osm.header.xid = 0;
            nxst_stats_msg->vsm.osm.type = htons(0xFFFF);
            nxst_stats_msg->vsm.osm.flags = 0;
            nxst_stats_msg->vsm.vendor = htonl(NX_VENDOR_ID);
            nxst_stats_msg->subtype = htonl(50);
        }
        else {
            NL_SYS_ERR("CN Statistics Gatherer - Unsupported Version %s", VERSION);
            return;
        }
        nl_c_enable = 1;
    }
}

/* Searches through old hash table for netlink stats, adds them to the reply and 
 * sends the final message to the controller */
int send_cn_stats(struct ofconn *ofconn, struct ovs_list *replies, 
                        struct cn_stats_htable **old_hash_table) {
    NL_SYS_DEBUG("Entering: %s\n", __func__);
    struct cn_stats_htable *stats_hash_table_cur = {0};
    struct cn_stats_htable *stats_hash_table_temp = {0};
    enum ofperr error = 0;
    
    if (old_hash_table == NULL)
        goto done;

    pthread_mutex_lock(&lock_old_stats_table);

    for (int i = 0; i < HASH_STATS_LEN-1; i++) {
        stats_hash_table_temp = old_hash_table[i];
        if (stats_hash_table_temp != NULL) {
            /* If node is not the head */
            if (stats_hash_table_temp->next != NULL) {
                /* Loop through linked list and dump everything */
                while(stats_hash_table_temp->next != NULL) {
                    stats_hash_table_cur = stats_hash_table_temp;
                    if (stats_hash_table_temp->stats_link != NULL) {
                            cn_c_reply_append(replies, stats_hash_table_temp->stats_link);
                            error = 0;
                    }
                    stats_hash_table_temp = stats_hash_table_cur->next;
                }
            }

            /* If node is final */
            if (stats_hash_table_temp->next == NULL) {
                if (stats_hash_table_temp->stats_link != NULL) {
                    cn_c_reply_append(replies, stats_hash_table_temp->stats_link);
                    error = 0;
                }
            }
        }
    }
    pthread_mutex_unlock(&lock_old_stats_table);

    if (!error) {
        cn_reset_timer(t_controller, C_DUMP_INTERVAL);
        /* Send reply to controller */
        ofconn_send_replies(ofconn, replies);
        NL_SYS_INFO("Sent Stats Msg to controller\n");
    }
    else {
        /* Delete reply buffer */
        ofpbuf_list_delete(replies);
    }
    return error;
done:
    NL_SYS_ERR("ERROR: No old hash table\n");
    return error;
}

/* Initialises statistics hash table queue on startup */
void 
cn_init_queue(struct ovs_list* replies)
{
    if (nl_c_enable == 1 && cn_initialised == 1) {
        if(!SIMPLEQ_EMPTY(&cn_stats_queue_head))
            memset(&(*replies), 0, sizeof((*replies)));
    }
}

/* Send each hash table in the queue to connected controllers */
void 
cn_send_to_controller(struct ofconn* ofconn, struct stats_queue** queue_old, 
                      struct ovs_list* replies)
{
    if (nl_c_enable == 1 && cn_initialised == 1) {
        if(!SIMPLEQ_EMPTY(&cn_stats_queue_head)){
            (*queue_old) = SIMPLEQ_FIRST(&cn_stats_queue_head);
            SIMPLEQ_FOREACH((*queue_old), &cn_stats_queue_head, next) {
                ofpmp_init(&(*replies), nxst_stats_hdr);
                send_cn_stats(ofconn, &(*replies), (*queue_old)->old_htable_stats);
            }
        }
    }
}

/* Obtain memory from queues */
void 
cn_free_queue(struct stats_queue** queue_old)
{
    if (nl_c_enable == 1 && cn_initialised == 1) {
        while(!SIMPLEQ_EMPTY(&cn_stats_queue_head)) {
            (*queue_old) = SIMPLEQ_FIRST(&cn_stats_queue_head); 
            /* Delete old statistics hash table */
            SIMPLEQ_REMOVE(&cn_stats_queue_head, (*queue_old), stats_queue, next);
            cn_stats_htable_delete_all((*queue_old)->old_htable_stats);
            free((*queue_old)->old_htable_stats);
            free((*queue_old));
        }
    }
}
#endif /* ENABLE_CN_STATS */
