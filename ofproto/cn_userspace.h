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
#ifndef CN_USERSPACE_H
#define CN_USERSPACE_H
#include "nlclient_stats.h"

extern timer_t t_controller;
extern timer_t t_kernel;
extern timer_t t_controller;
extern pthread_mutex_t lock_o_table;
extern pthread_mutex_t lock_cn_queue;
extern pthread_mutex_t lock_cn_k;
extern pthread_mutex_t lock_cn_init;
extern int cn_k_ready;
int nl_c_enable;

extern struct cn_stats_htable **g_hash_table;

struct ofp_header *nxst_stats_hdr;

enum ofperr handle_nxt_netlink_disable(void);
enum ofperr handle_nxst_netlink_request(struct ofconn *ofconn,
                                const struct ofp_header *request);
enum ofperr handle_nxt_netlink_enable(void);
void nxst_stats_msg_init(void);
int old_htable_check(void);
int send_cn_stats(struct ofconn *ofconn, struct ovs_list *replies,
                    struct cn_stats_htable **old_hash_table);
void cn_init_queue(struct ovs_list* replies);
void cn_send_to_controller(struct ofconn* ofconn, struct stats_queue** queue_old,
                        struct ovs_list* replies);
void cn_free_queue(struct stats_queue** queue_old);

#endif /* CN_USERSPACE_H */
#endif /* ENABLE_CN_STATS */
